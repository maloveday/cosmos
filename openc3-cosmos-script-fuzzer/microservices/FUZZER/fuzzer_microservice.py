"""
fuzzer_microservice.py - Fuzzing engine, simulated openc3.script API and the
OpenC3 COSMOS microservice entry point.

The engine executes a Script Runner procedure repeatedly in headless mode.
`from openc3.script import *` inside the procedure resolves to a simulated
module whose tlm/cmd/check/ask/... functions are backed by RedisTelemetryDB.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import ast
import builtins
import contextlib
import json
import os
import random
import re
import sys
import tempfile
import time
import traceback
import types
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from coverage_tracker import (PROCEDURE_TIMEOUT, STALE_EXECUTION_TIMEOUT,  # noqa: E402
                              CoverageTracker, ProcedureTimeoutInterrupt,
                              ProgressWatchdog, StaleExecutionError, norm_path)
from redis_db import STRATEGIES, RedisTelemetryDB, TelemetryDBError  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
@dataclass
class Step:
    timestamp: str
    keyword: str
    args: str
    result: str
    status: str            # PASS | WARN | FAIL
    line: int = 0
    new_path: bool = False
    sites: int = 0
    detail: str = ""


@dataclass
class TestCase:
    name: str
    iteration: int
    strategy: str
    start: str
    end: str = ""
    elapsed: float = 0.0
    status: str = "PASS"   # PASS | FAIL
    message: str = ""
    traceback: str = ""
    event: str = ""        # STALE_EXECUTION_TIMEOUT | PROCEDURE_TIMEOUT | ""
    steps: List[Step] = field(default_factory=list)
    coverage: Dict[str, Any] = field(default_factory=dict)


class CheckError(AssertionError):
    """Raised by check()/wait_check() when a telemetry condition is not met."""


class StopScript(Exception):
    """Mirrors openc3.script StopScript."""


class SkipScript(Exception):
    """Mirrors openc3.script SkipScript."""


# --------------------------------------------------------------------------- #
# Simulated openc3.script API
# --------------------------------------------------------------------------- #
_CMP_SAFE = {"__builtins__": {}}
_COMMA_SPLIT = re.compile(r""",(?=(?:[^"']*["'][^"']*["'])*[^"']*$)""")


def _coerce(text: str) -> Any:
    text = text.strip()
    try:
        return ast.literal_eval(text)
    except (ValueError, SyntaxError):
        return text


def _short(value: Any, limit: int = 300) -> str:
    s = repr(value)
    return s if len(s) <= limit else s[: limit - 3] + "..."


class SimulatedScriptAPI:
    """Implements the Script Runner API surface against the simulation model."""

    EXPORTS = ("tlm", "tlm_raw", "tlm_formatted", "tlm_with_units", "check", "check_tolerance",
               "wait", "wait_check", "wait_check_tolerance", "cmd", "cmd_no_range_check",
               "cmd_no_hazardous_check", "cmd_no_checks", "ask", "ask_string", "message_box",
               "vertical_message_box", "combo_box", "prompt", "CheckError", "StopScript",
               "SkipScript", "disconnect_script", "step_mode", "run_mode")

    def __init__(self, db: RedisTelemetryDB, rng: random.Random, strategy: str,
                 test: TestCase, watchdog: ProgressWatchdog) -> None:
        self.db, self.rng, self.strategy, self.test, self.watchdog = db, rng, strategy, test, watchdog
        self.sim_time = 0.0

    # ------------------------------------------------------------ helpers
    def _step(self, keyword: str, args: str, result: Any, status: str = "PASS",
              detail: str = "", checkpoint: bool = True) -> None:
        line, new = self.watchdog.checkpoint() if checkpoint else (0, False)
        self.test.steps.append(Step(_now(), keyword, args, result if isinstance(result, str) else _short(result),
                                    status, line, new, self.watchdog.distinct_sites, detail))

    def _fail_step(self, keyword: str, args: str, exc: BaseException) -> None:
        self.test.steps.append(Step(_now(), keyword, args, f"{type(exc).__name__}: {exc}", "FAIL",
                                    self.watchdog._last_line, False, self.watchdog.distinct_sites))

    @staticmethod
    def _split_tlm(args: Sequence[Any]):
        if len(args) == 1 and isinstance(args[0], str):
            parts = args[0].split(None, 3)
            if len(parts) < 3:
                raise ValueError(f"Telemetry reference must be 'TARGET PACKET ITEM': {args[0]!r}")
            return parts[0].upper(), parts[1].upper(), parts[2].upper(), (parts[3] if len(parts) > 3 else "")
        if len(args) >= 3:
            return str(args[0]).upper(), str(args[1]).upper(), str(args[2]).upper(), ""
        raise ValueError(f"Invalid telemetry arguments: {args!r}")

    def _sample(self, t: str, p: str, i: str) -> Any:
        return self.db.get_tm_value(t, p, i, strategy=self.strategy, rng=self.rng)

    @staticmethod
    def _compare(value: Any, comparison: str) -> bool:
        if not comparison.strip():
            return True
        try:
            return bool(eval(f"__v {comparison}", _CMP_SAFE, {"__v": value}))  # noqa: S307
        except Exception as exc:
            raise ValueError(f"Invalid comparison '{comparison}': {exc}") from None

    # --------------------------------------------------------- telemetry
    def tlm(self, *args: Any, **kwargs: Any) -> Any:
        ref = " ".join(map(str, args))
        try:
            t, p, i, _ = self._split_tlm(args)
            value = self._sample(t, p, i)
        except (TelemetryDBError, ValueError) as exc:
            self._fail_step("tlm", ref, exc)
            raise
        self._step("tlm", ref, value, detail=f"strategy={self.strategy}")
        return value

    tlm_raw = tlm

    def tlm_formatted(self, *args: Any, **kwargs: Any) -> str:
        return str(self.tlm(*args, **kwargs))

    tlm_with_units = tlm_formatted

    def check(self, *args: Any, **kwargs: Any) -> None:
        ref = " ".join(map(str, args))
        try:
            t, p, i, comparison = self._split_tlm(args if len(args) == 1 else args[:3])
            if len(args) >= 4:
                comparison = str(args[3])
            value = self._sample(t, p, i)
            ok = self._compare(value, comparison)
        except (TelemetryDBError, ValueError) as exc:
            self._fail_step("check", ref, exc)
            raise
        if not ok:
            self._step("check", ref, f"{t} {p} {i} = {value!r}", "FAIL")
            raise CheckError(f"CHECK: {t} {p} {i} {comparison} failed with value == {value!r}")
        self._step("check", ref, f"{t} {p} {i} = {value!r}")

    def check_tolerance(self, ref: str, expected: float, tolerance: float, **kwargs: Any) -> None:
        t, p, i, _ = self._split_tlm([ref])
        value = self._sample(t, p, i)
        ok = abs(float(value) - float(expected)) <= abs(float(tolerance))
        self._step("check_tolerance", f"{ref} {expected}±{tolerance}", value, "PASS" if ok else "FAIL")
        if not ok:
            raise CheckError(f"CHECK: {ref} expected {expected}±{tolerance}, got {value!r}")

    def wait(self, *args: Any, **kwargs: Any) -> float:
        if args and isinstance(args[0], (int, float)):
            secs = float(args[0])
            self.sim_time += secs
            self._step("wait", f"{secs}s (simulated)", f"sim_time={self.sim_time:.2f}s")
            return secs
        if args and isinstance(args[0], str) and len(args[0].split()) > 3:
            return self.wait_check(*args, raise_on_fail=False, **kwargs)
        self._step("wait", " ".join(map(str, args)) or "(indefinite)", "skipped in simulation")
        return 0.0

    def wait_check(self, expr: str, timeout: float = 1.0, polling_rate: float = 0.25,
                   raise_on_fail: bool = True, **kwargs: Any) -> float:
        try:
            t, p, i, comparison = self._split_tlm([expr])
        except ValueError as exc:
            self._fail_step("wait_check", expr, exc)
            raise
        samples = max(1, min(20, int(float(timeout) / max(float(polling_rate), 1e-3))))
        values = []
        try:
            for n in range(samples):
                v = self._sample(t, p, i)
                values.append(v)
                if self._compare(v, comparison):
                    elapsed = n * float(polling_rate)
                    self.sim_time += elapsed
                    self._step("wait_check", f"{expr} (timeout {timeout}s)",
                               f"met after {n + 1} sample(s) = {v!r}", detail=f"samples={_short(values)}")
                    return elapsed
        except (TelemetryDBError, ValueError) as exc:
            self._fail_step("wait_check", expr, exc)
            raise
        self.sim_time += float(timeout)
        self._step("wait_check", f"{expr} (timeout {timeout}s)", f"timeout; last = {values[-1]!r}",
                   "FAIL" if raise_on_fail else "WARN", detail=f"samples={_short(values)}")
        if raise_on_fail:
            raise CheckError(f"CHECK: {expr} failed to be met within {timeout}s; last value {values[-1]!r}")
        return float(timeout)

    def wait_check_tolerance(self, ref: str, expected: float, tolerance: float,
                             timeout: float = 1.0, polling_rate: float = 0.25, **kwargs: Any) -> float:
        lo, hi = float(expected) - abs(float(tolerance)), float(expected) + abs(float(tolerance))
        return self.wait_check(f"{ref} >= {lo} and __v <= {hi}", timeout, polling_rate)

    # ----------------------------------------------------------- commands
    def _parse_cmd(self, args: Sequence[Any], kwargs: Dict[str, Any]):
        if len(args) == 1 and isinstance(args[0], str):
            m = re.match(r"^\s*(\S+)\s+(\S+)(?:\s+with\s+(.*))?\s*$", args[0], re.IGNORECASE | re.DOTALL)
            if not m:
                raise ValueError(f"Invalid command string: {args[0]!r}")
            params: Dict[str, Any] = {}
            if m.group(3):
                for chunk in _COMMA_SPLIT.split(m.group(3)):
                    if not chunk.strip():
                        continue
                    parts = chunk.strip().split(None, 1)
                    params[parts[0].upper()] = _coerce(parts[1]) if len(parts) > 1 else None
            return m.group(1).upper(), m.group(2).upper(), params
        if len(args) >= 2:
            params = args[2] if len(args) > 2 else kwargs.get("params", {})
            return str(args[0]).upper(), str(args[1]).upper(), dict(params or {})
        raise ValueError(f"Invalid command arguments: {args!r}")

    def cmd(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        ref = " ".join(map(str, args))
        try:
            target, name, params = self._parse_cmd(args, kwargs)
        except ValueError as exc:
            self._fail_step("cmd", ref, exc)
            raise
        result = self.db.send_command(target, name, params, rng=self.rng)
        self._step("cmd", f"{target} {name} {json.dumps(params, default=str)}", result["status"],
                   "PASS" if result["status"] == "SUCCESS" else "WARN", detail="stochastic 75/25")
        return result

    cmd_no_range_check = cmd_no_hazardous_check = cmd_no_checks = cmd

    # ------------------------------------------------------------ prompts
    def _prompt(self, kind: str, message: str, valid: Optional[Sequence[Any]]) -> Any:
        answer = self.db.handle_user_prompt(kind, message, valid, rng=self.rng)
        self._step(kind, message, answer, detail=f"valid={_short(list(valid or []))}")
        return answer

    def ask_string(self, question: str, blank_or_default: Any = False, password: bool = False) -> str:
        if blank_or_default not in (False, True, None) and self.rng.random() < 0.25:
            return self._prompt("ask_string", question, [str(blank_or_default)])
        return str(self._prompt("ask_string", question, None))

    def ask(self, question: str, blank_or_default: Any = False, password: bool = False) -> Any:
        value = self._prompt("ask", question, None)
        try:  # Script Runner's ask() converts numeric answers
            return ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return value

    def message_box(self, message: str, *buttons: Any, **kwargs: Any) -> Any:
        return self._prompt("message_box", message, list(buttons) or ["Ok"])

    vertical_message_box = message_box

    def combo_box(self, message: str, *items: Any, **kwargs: Any) -> Any:
        return self._prompt("combo_box", message, list(items) or None)

    def prompt(self, message: str, **kwargs: Any) -> str:
        return self._prompt("prompt", message, ["Ok"])

    # ------------------------------------------------------------- no-ops
    def disconnect_script(self) -> None: ...
    def step_mode(self) -> None: ...
    def run_mode(self) -> None: ...

    def namespace(self) -> Dict[str, Any]:
        ns: Dict[str, Any] = {}
        for name in self.EXPORTS:
            attr = getattr(self, name, None)
            ns[name] = attr if attr is not None else globals()[name]
        return ns


@contextlib.contextmanager
def patched_openc3_script(api_ns: Dict[str, Any]):
    """Temporarily make `import openc3.script` resolve to the simulated API."""
    saved = {k: sys.modules.get(k) for k in ("openc3", "openc3.script")}
    module = types.ModuleType("openc3.script")
    module.__dict__.update(api_ns)
    module.__all__ = list(api_ns)
    if "openc3" not in sys.modules:
        pkg = types.ModuleType("openc3")
        pkg.__path__ = []  # mark as package
        sys.modules["openc3"] = pkg
    parent = sys.modules["openc3"]
    old_attr = getattr(parent, "script", None)
    sys.modules["openc3.script"] = module
    setattr(parent, "script", module)
    try:
        yield module
    finally:
        if old_attr is not None:
            setattr(parent, "script", old_attr)
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# --------------------------------------------------------------------------- #
# Fuzzing engine
# --------------------------------------------------------------------------- #
@dataclass
class FuzzConfig:
    script_path: str
    staleness_threshold: int = 10       # N iterations without new coverage
    loop_staleness: int = 25            # N repeated API transitions inside one run
    stale_seconds: float = 30.0         # T seconds without new transition inside one run
    iteration_timeout: float = 60.0     # hard per-iteration limit
    max_iterations: int = 100
    seed: Optional[int] = None
    strategies: Sequence[str] = STRATEGIES


class ScriptFuzzer:
    def __init__(self, db: RedisTelemetryDB, config: FuzzConfig) -> None:
        if not os.path.isfile(config.script_path):
            raise FileNotFoundError(f"Procedure not found: {config.script_path}")
        unknown = [s for s in config.strategies if s not in STRATEGIES]
        if unknown:
            raise ValueError(f"Unknown mutation strategies: {unknown}")
        self.db, self.config = db, config
        self.script_path = os.path.abspath(config.script_path)
        with open(self.script_path, "r", encoding="utf-8") as fh:
            self.source = fh.read()
        self.code = compile(self.source, self.script_path, "exec")  # SyntaxError surfaces early
        self.tracker = CoverageTracker(self.script_path, config.staleness_threshold)
        self.watchdog = ProgressWatchdog(self.script_path, config.loop_staleness,
                                         config.stale_seconds, config.iteration_timeout)
        self.events: List[Dict[str, Any]] = []
        self.log = lambda msg: print(msg, file=sys.stderr)

    def _event(self, kind: str, iteration: int, strategy: str, detail: str, action: str) -> None:
        self.events.append({"timestamp": _now(), "event": kind, "iteration": iteration,
                            "strategy": strategy, "detail": detail, "action": action})

    def _run_iteration(self, index: int, strategy: str) -> TestCase:
        seed = None if self.config.seed is None else self.config.seed + index
        rng = random.Random(seed)
        test = TestCase(name=f"Fuzz Iteration {index + 1:03d}", iteration=index + 1,
                        strategy=strategy, start=_now())
        api = SimulatedScriptAPI(self.db, rng, strategy, test, self.watchdog)
        ns = {"__name__": "__main__", "__file__": self.script_path, "__builtins__": builtins}
        ns.update(api.namespace())
        t0 = time.perf_counter()
        script_dir = os.path.dirname(self.script_path)
        sys.path.insert(0, script_dir)
        try:
            with patched_openc3_script(api.namespace()):
                try:
                    self.watchdog.arm()
                    self.tracker.start()
                    try:
                        exec(self.code, ns)  # noqa: S102
                    finally:
                        self.watchdog.disarm()
                        self.tracker.stop()
                except StaleExecutionError as exc:
                    test.status, test.event = "FAIL", STALE_EXECUTION_TIMEOUT
                    test.message = f"{STALE_EXECUTION_TIMEOUT}: {self.watchdog.reason or exc}"
                except ProcedureTimeoutInterrupt as exc:
                    test.status, test.event = "FAIL", PROCEDURE_TIMEOUT
                    test.message = f"{PROCEDURE_TIMEOUT}: {self.watchdog.reason or exc}"
                except SystemExit as exc:
                    if exc.code not in (0, None):
                        test.status, test.message = "FAIL", f"SystemExit({exc.code})"
                except KeyboardInterrupt:
                    raise
                except BaseException as exc:  # unhandled procedure exception
                    test.status = "FAIL"
                    test.message = f"{type(exc).__name__}: {exc}"
                    test.traceback = self._procedure_traceback()
        except (StaleExecutionError, ProcedureTimeoutInterrupt) as exc:  # late async delivery
            if test.status == "PASS":
                test.status, test.event, test.message = "FAIL", getattr(exc, "event", ""), str(exc)
        finally:
            self.tracker.stop()
            with contextlib.suppress(ValueError):
                sys.path.remove(script_dir)
        test.elapsed = time.perf_counter() - t0
        test.end = _now()
        return test

    def _procedure_traceback(self) -> str:
        etype, value, tb = sys.exc_info()
        frames = [f for f in traceback.extract_tb(tb)
                  if norm_path(f.filename) == norm_path(self.script_path)
                  or os.path.dirname(norm_path(f.filename)) != norm_path(os.path.dirname(__file__))]
        out = ["Traceback (most recent call last):\n"] + traceback.format_list(frames)
        out += traceback.format_exception_only(etype, value)
        return "".join(out)

    def run(self) -> Dict[str, Any]:
        cfg = self.config
        started, t0 = _now(), time.perf_counter()
        tests: List[TestCase] = []
        strategy_idx, conclusion = 0, f"Reached iteration limit ({cfg.max_iterations})"
        concluded_early = False
        for index in range(cfg.max_iterations):
            strategy = cfg.strategies[strategy_idx]
            test = self._run_iteration(index, strategy)
            cov = self.tracker.register_iteration(test.name)
            test.coverage = cov
            tests.append(test)
            self.log(f"[{test.status}] {test.name} strategy={strategy} new_lines={cov['new_lines']} "
                     f"new_arcs={cov['new_arcs']} line={cov['line_pct']}% branch={cov['branch_pct']}%"
                     + (f" {test.message}" if test.status == "FAIL" else ""))

            stale_reason = None
            if test.event == STALE_EXECUTION_TIMEOUT:
                stale_reason = f"In-run staleness: {test.message}"
            elif self.tracker.is_stale:
                stale_reason = (f"No new line/branch coverage for {self.tracker.stale_count} "
                                f"consecutive iterations")
            if stale_reason:
                if strategy_idx + 1 < len(cfg.strategies):
                    strategy_idx += 1
                    action = f"Mutation strategy shifted: {strategy} -> {cfg.strategies[strategy_idx]}"
                    self._event(STALE_EXECUTION_TIMEOUT, index + 1, strategy, stale_reason, action)
                    self.tracker.reset_staleness()
                elif self.tracker.is_stale:
                    concluded_early = True
                    conclusion = "All mutation strategies exhausted without new coverage; cycle concluded early"
                    self._event(STALE_EXECUTION_TIMEOUT, index + 1, strategy, stale_reason, "Fuzzing cycle concluded")
                    break
                else:
                    self._event(STALE_EXECUTION_TIMEOUT, index + 1, strategy, stale_reason,
                                "Procedure interrupted; continuing with final strategy")
            if test.event == PROCEDURE_TIMEOUT:
                self._event(PROCEDURE_TIMEOUT, index + 1, strategy, test.message, "Procedure interrupted")

        totals = self.tracker.totals()
        elapsed = time.perf_counter() - t0
        passed = sum(t.status == "PASS" for t in tests)
        return {
            "script": self.script_path, "source": self.source, "backend": self.db.description,
            "started": started, "finished": _now(), "elapsed": elapsed,
            "summary": {"total": len(tests), "passed": passed, "failed": len(tests) - passed,
                        "pass_pct": round(100.0 * passed / len(tests), 1) if tests else 0.0},
            "coverage": totals, "progression": self.tracker.history, "events": self.events,
            "stale_interruptions": sum(e["event"] == STALE_EXECUTION_TIMEOUT for e in self.events),
            "concluded_early": concluded_early, "conclusion": conclusion,
            "config": {k: (list(v) if isinstance(v, tuple) else v) for k, v in asdict(cfg).items()},
            "tests": [asdict(t) for t in tests],
        }


# --------------------------------------------------------------------------- #
# OpenC3 COSMOS microservice wrapper
# --------------------------------------------------------------------------- #
JOB_QUEUE = os.environ.get("FUZZER_JOB_QUEUE", "openc3-script-fuzzer:jobs")
REPORT_PREFIX = "openc3-script-fuzzer:report:"


def run_job(db: RedisTelemetryDB, job: Dict[str, Any]) -> Dict[str, Any]:
    """Execute one fuzz job. job = {script_path | script_text, ...FuzzConfig fields}."""
    from report_generator import render_report
    job_id = job.get("id") or uuid.uuid4().hex[:12]
    tmp_path = None
    try:
        script_path = job.get("script_path")
        if not script_path:
            fd, tmp_path = tempfile.mkstemp(suffix=".py", prefix=f"fuzz_{job_id}_")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(job["script_text"])
            script_path = tmp_path
        cfg = FuzzConfig(script_path=script_path, **{k: v for k, v in job.items()
                                                     if k in FuzzConfig.__dataclass_fields__ and k != "script_path"})
        result = ScriptFuzzer(db, cfg).run()
        html = render_report(result)
        db.client.set(REPORT_PREFIX + job_id, html, ex=7 * 24 * 3600)
        db.client.set(REPORT_PREFIX + job_id + ":summary",
                      json.dumps({"summary": result["summary"], "coverage": {
                          k: result["coverage"][k] for k in ("line_pct", "branch_pct")},
                          "stale_interruptions": result["stale_interruptions"]}), ex=7 * 24 * 3600)
        return {"id": job_id, "status": "COMPLETE", "summary": result["summary"]}
    finally:
        if tmp_path:
            with contextlib.suppress(OSError):
                os.remove(tmp_path)


def _db_from_env() -> RedisTelemetryDB:
    return RedisTelemetryDB(host=os.environ.get("OPENC3_REDIS_HOSTNAME", "localhost"),
                            port=int(os.environ.get("OPENC3_REDIS_PORT", "6379")),
                            username=os.environ.get("OPENC3_REDIS_USERNAME") or None,
                            password=os.environ.get("OPENC3_REDIS_PASSWORD") or None)


def _job_loop(db: RedisTelemetryDB, should_stop=lambda: False, logger=print) -> None:
    while not should_stop():
        try:
            popped = db.client.blpop([JOB_QUEUE], timeout=5)
            if not popped:
                continue
            job = json.loads(popped[1])
            logger(f"Fuzzer job received: {job.get('id', '?')}")
            logger(json.dumps(run_job(db, job)))
        except Exception as exc:  # keep the microservice alive
            logger(f"Fuzzer job error: {type(exc).__name__}: {exc}")
            time.sleep(1)


try:
    from openc3.microservices.microservice import Microservice  # type: ignore

    class FuzzerMicroservice(Microservice):  # pragma: no cover - requires COSMOS runtime
        def run(self):
            db = _db_from_env()
            self.state = "RUNNING"
            _job_loop(db, lambda: getattr(self, "cancel_thread", False),
                      getattr(getattr(self, "logger", None), "info", print))
except Exception:  # openc3 package not available outside the COSMOS runtime
    FuzzerMicroservice = None  # type: ignore


if __name__ == "__main__":
    if FuzzerMicroservice is not None and hasattr(FuzzerMicroservice, "class_run"):
        FuzzerMicroservice.class_run()
    else:
        _job_loop(_db_from_env())
