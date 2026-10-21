"""
coverage_tracker.py - Coverage.py integration and staleness heuristics.

Two complementary staleness detectors are provided:

* CoverageTracker  - cumulative line/branch coverage across fuzz iterations.
                     If N consecutive iterations add no new line or arc the
                     campaign is flagged stale.
* ProgressWatchdog - guards a *single* procedure run.  Every simulated API call
                     is a checkpoint; if N consecutive checkpoints revisit known
                     (line, previous line) transitions, or T seconds pass without
                     a new transition, the run is interrupted with
                     StaleExecutionError (a BaseException, so `except Exception`
                     blocks inside procedures cannot swallow it).

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import ctypes
import json
import os
import sys
import tempfile
import threading
import time
from typing import Any, Dict, Optional, Set, Tuple

import coverage

STALE_EXECUTION_TIMEOUT = "STALE_EXECUTION_TIMEOUT"
PROCEDURE_TIMEOUT = "PROCEDURE_TIMEOUT"


def norm_path(path: str) -> str:
    return os.path.normcase(os.path.abspath(path))


class StaleExecutionError(BaseException):
    """Raised inside a procedure when no new execution progress is observed."""
    event = STALE_EXECUTION_TIMEOUT


class StaleTimeoutInterrupt(StaleExecutionError):
    """Asynchronously injected when the time-based staleness threshold expires."""

    def __init__(self, *args: Any) -> None:
        super().__init__(*(args or ("No new execution path discovered within the staleness time limit",)))


class ProcedureTimeoutInterrupt(BaseException):
    """Asynchronously injected when the hard per-iteration timeout expires."""
    event = PROCEDURE_TIMEOUT

    def __init__(self, *args: Any) -> None:
        super().__init__(*(args or ("Procedure exceeded the hard iteration timeout",)))


def _async_raise(thread_id: int, exc_type: Optional[type]) -> bool:
    """Inject (or clear, when exc_type is None) an exception in another thread."""
    obj = ctypes.py_object(exc_type) if exc_type is not None else ctypes.c_void_p(0)
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), obj)
    if res > 1:  # should never happen; undo
        ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(thread_id), ctypes.c_void_p(0))
        return False
    return res == 1


# --------------------------------------------------------------------------- #
class CoverageTracker:
    """Accumulates branch coverage over many runs of one procedure file."""

    def __init__(self, script_path: str, staleness_threshold: int = 10) -> None:
        if staleness_threshold < 1:
            raise ValueError("staleness_threshold must be >= 1")
        self.script_path = norm_path(script_path)
        self.staleness_threshold = staleness_threshold
        self._cov = coverage.Coverage(branch=True, data_file=None, config_file=False,
                                      include=[os.path.abspath(script_path)])
        self._seen_lines: Set[int] = set()
        self._seen_arcs: Set[Tuple[int, int]] = set()
        self._running = False
        self.stale_count = 0
        self.history: list = []

    # ------------------------------------------------------------ control
    def start(self) -> None:
        if not self._running:
            self._cov.start()
            self._running = True

    def stop(self) -> None:
        if self._running:
            self._cov.stop()
            self._running = False

    # ------------------------------------------------------------ queries
    def _executed(self) -> Tuple[Set[int], Set[Tuple[int, int]]]:
        data = self._cov.get_data()
        for f in data.measured_files():
            if norm_path(f) == self.script_path:
                return set(data.lines(f) or ()), set(data.arcs(f) or ())
        return set(), set()

    def register_iteration(self, label: str = "") -> Dict[str, Any]:
        """Fold the latest run into the cumulative set and update staleness."""
        lines, arcs = self._executed()
        new_lines, new_arcs = lines - self._seen_lines, arcs - self._seen_arcs
        self._seen_lines |= new_lines
        self._seen_arcs |= new_arcs
        self.stale_count = 0 if (new_lines or new_arcs) else self.stale_count + 1
        entry = {"label": label, "new_lines": len(new_lines), "new_arcs": len(new_arcs),
                 "total_lines": len(self._seen_lines), "total_arcs": len(self._seen_arcs),
                 "stale_count": self.stale_count, "is_stale": self.is_stale}
        entry.update({k: v for k, v in self.totals().items() if k in ("line_pct", "branch_pct")})
        self.history.append(entry)
        return entry

    @property
    def is_stale(self) -> bool:
        return self.stale_count >= self.staleness_threshold

    def reset_staleness(self) -> None:
        self.stale_count = 0

    def totals(self) -> Dict[str, Any]:
        """Line / branch statistics via Coverage.py's public JSON reporter."""
        empty = {"line_pct": 0.0, "branch_pct": 0.0, "statements": 0, "covered_lines": 0,
                 "branches": 0, "covered_branches": 0, "executed_lines": [],
                 "missing_lines": [], "missing_branches": [], "excluded_lines": []}
        was_running = self._running
        self.stop()
        fd, tmp = tempfile.mkstemp(suffix=".json", prefix="fuzzcov_")
        os.close(fd)
        try:
            try:
                self._cov.json_report(outfile=tmp, include=[os.path.abspath(self.script_path)])
            except coverage.exceptions.NoDataError:
                return empty
            with open(tmp, "r", encoding="utf-8") as fh:
                report = json.load(fh)
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
            if was_running:
                self.start()
        files = report.get("files") or {}
        if not files:
            return empty
        entry = next(iter(files.values()))
        s = entry.get("summary", {})
        stm, cl = s.get("num_statements", 0), s.get("covered_lines", 0)
        br, cb = s.get("num_branches", 0), s.get("covered_branches", 0)
        return {
            "line_pct": round(100.0 * cl / stm, 2) if stm else 100.0,
            "branch_pct": round(100.0 * cb / br, 2) if br else 100.0,
            "statements": stm, "covered_lines": cl, "branches": br, "covered_branches": cb,
            "executed_lines": entry.get("executed_lines", []),
            "missing_lines": entry.get("missing_lines", []),
            "missing_branches": entry.get("missing_branches", []),
            "excluded_lines": entry.get("excluded_lines", []),
        }


# --------------------------------------------------------------------------- #
class ProgressWatchdog:
    """Detects stalled loops inside a single procedure execution."""

    def __init__(self, script_path: str, loop_threshold: int = 25,
                 stale_seconds: float = 30.0, hard_timeout: float = 60.0) -> None:
        self.script_path = norm_path(script_path)
        self.loop_threshold = max(1, int(loop_threshold))
        self.stale_seconds = float(stale_seconds)
        self.hard_timeout = float(hard_timeout)
        self._lock = threading.Lock()
        self._armed = False
        self._thread_id: Optional[int] = None
        self._monitor: Optional[threading.Thread] = None
        self.reset()

    def reset(self) -> None:
        self.seen: Set[Tuple[int, int]] = set()
        self.repeats = 0
        self._last_line = 0
        self.started = time.monotonic()
        self.last_new = self.started
        self.fired: Optional[str] = None
        self.reason: Optional[str] = None

    @property
    def distinct_sites(self) -> int:
        return len(self.seen)

    # ---------------------------------------------------------- lifecycle
    def arm(self) -> None:
        self.reset()
        self._thread_id = threading.get_ident()
        with self._lock:
            self._armed = True
        self._monitor = threading.Thread(target=self._watch, name="fuzzer-watchdog", daemon=True)
        self._monitor.start()

    def disarm(self) -> None:
        with self._lock:
            self._armed = False
            if self.fired and self._thread_id is not None:
                _async_raise(self._thread_id, None)  # clear anything still pending
        if self._monitor is not None:
            self._monitor.join(timeout=1.0)
            self._monitor = None

    def _watch(self) -> None:
        while True:
            time.sleep(0.05)
            with self._lock:
                if not self._armed:
                    return
                now = time.monotonic()
                exc: Optional[type] = None
                if now - self.started > self.hard_timeout:
                    self.fired, exc = PROCEDURE_TIMEOUT, ProcedureTimeoutInterrupt
                    self.reason = f"Hard timeout of {self.hard_timeout:.1f}s exceeded"
                elif now - self.last_new > self.stale_seconds:
                    self.fired, exc = STALE_EXECUTION_TIMEOUT, StaleTimeoutInterrupt
                    self.reason = (f"No new execution transition for {self.stale_seconds:.1f}s "
                                   f"(last progress at line {self._last_line})")
                if exc is not None:
                    self._armed = False
                    _async_raise(self._thread_id, exc)
                    return

    # --------------------------------------------------------- checkpoint
    def checkpoint(self) -> Tuple[int, bool]:
        """Called from every simulated API call. Returns (line, is_new_transition)."""
        frame = sys._getframe(1)
        line = 0
        while frame is not None:
            if norm_path(frame.f_code.co_filename) == self.script_path:
                line = frame.f_lineno
                break
            frame = frame.f_back
        key = (line, self._last_line)
        self._last_line = line
        if key not in self.seen:
            self.seen.add(key)
            self.repeats = 0
            self.last_new = time.monotonic()
            return line, True
        self.repeats += 1
        if self.repeats >= self.loop_threshold:
            self.fired = STALE_EXECUTION_TIMEOUT
            self.reason = (f"{self.repeats} consecutive API calls without a new execution "
                           f"transition (stalled near line {line})")
            raise StaleExecutionError(self.reason)
        return line, False
