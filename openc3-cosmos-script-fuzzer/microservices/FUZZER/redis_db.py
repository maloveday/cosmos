"""
redis_db.py - Redis-backed telemetry metadata store and simulation primitives.

Key schema:  tm:<TARGET>:<PACKET>:<ITEM>   (Redis HASH)

    name              Telemetry mnemonic
    description       Free-text description
    type              INT | UINT | FLOAT | STRING
    subtype           NUMERIC | CALIBRATION
    min_value         numeric lower bound   (NUMERIC only)
    max_value         numeric upper bound   (NUMERIC only)
    calibration_list  JSON array of states  (CALIBRATION only)

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import fnmatch
import json
import math
import random
import string
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

try:  # redis is optional when running with the in-memory backend
    import redis  # type: ignore
except ImportError:  # pragma: no cover
    redis = None  # type: ignore

VALID_TYPES = {"INT", "UINT", "FLOAT", "STRING"}
VALID_SUBTYPES = {"NUMERIC", "CALIBRATION"}
STRATEGIES = ("uniform", "boundary", "edge_heavy")
KEY_PREFIX = "tm"


class TelemetryDBError(Exception):
    """Base class for telemetry database errors."""


class TelemetryNotFoundError(TelemetryDBError, KeyError):
    """Raised when a tm:<TARGET>:<PACKET>:<ITEM> key does not exist."""


class TelemetryDefinitionError(TelemetryDBError, ValueError):
    """Raised when a stored telemetry definition is malformed."""


class RedisUnavailableError(TelemetryDBError, ConnectionError):
    """Raised when the Redis server cannot be reached."""


# --------------------------------------------------------------------------- #
# Minimal in-memory Redis stand-in (for offline demos and unit tests)
# --------------------------------------------------------------------------- #
class InMemoryRedis:
    """Implements the tiny subset of the redis-py API used by this plugin."""

    def __init__(self) -> None:
        self._hashes: Dict[str, Dict[str, str]] = {}
        self._lists: Dict[str, List[str]] = {}
        self._strings: Dict[str, str] = {}

    def ping(self) -> bool:
        return True

    def hset(self, key: str, field: Optional[str] = None, value: Any = None,
             mapping: Optional[Dict[str, Any]] = None) -> int:
        h = self._hashes.setdefault(key, {})
        items = dict(mapping or {})
        if field is not None:
            items[field] = value
        h.update({k: str(v) for k, v in items.items()})
        return len(items)

    def hgetall(self, key: str) -> Dict[str, str]:
        return dict(self._hashes.get(key, {}))

    def exists(self, *keys: str) -> int:
        return sum(1 for k in keys if k in self._hashes or k in self._strings)

    def delete(self, *keys: str) -> int:
        n = 0
        for k in keys:
            n += int(self._hashes.pop(k, None) is not None)
            n += int(self._strings.pop(k, None) is not None)
        return n

    def scan_iter(self, match: str = "*", count: Optional[int] = None) -> Iterable[str]:
        return [k for k in list(self._hashes) if fnmatch.fnmatchcase(k, match)]

    def set(self, key: str, value: Any, ex: Optional[int] = None) -> bool:
        self._strings[key] = str(value)
        return True

    def get(self, key: str) -> Optional[str]:
        return self._strings.get(key)

    def rpush(self, key: str, *values: Any) -> int:
        lst = self._lists.setdefault(key, [])
        lst.extend(str(v) for v in values)
        return len(lst)

    def blpop(self, keys: Any, timeout: int = 0):
        for k in [keys] if isinstance(keys, str) else keys:
            if self._lists.get(k):
                return k, self._lists[k].pop(0)
        return None


# --------------------------------------------------------------------------- #
# Telemetry database
# --------------------------------------------------------------------------- #
class RedisTelemetryDB:
    """Access layer for tm:* metadata and the stochastic simulation model."""

    def __init__(self, host: str = "localhost", port: int = 6379, db: int = 0,
                 username: Optional[str] = None, password: Optional[str] = None,
                 socket_timeout: float = 5.0, client: Any = None,
                 rng: Optional[random.Random] = None) -> None:
        if client is not None:
            self.client = client
        else:
            if redis is None:
                raise RedisUnavailableError("The 'redis' package is not installed (pip install redis)")
            self.client = redis.Redis(host=host, port=port, db=db, username=username,
                                      password=password, socket_timeout=socket_timeout,
                                      socket_connect_timeout=socket_timeout,
                                      decode_responses=True)
        self.rng = rng or random.Random()
        self.description = f"redis://{host}:{port}/{db}" if client is None else type(client).__name__

    @classmethod
    def in_memory(cls, seed_demo: bool = True, rng: Optional[random.Random] = None) -> "RedisTelemetryDB":
        inst = cls(client=InMemoryRedis(), rng=rng)
        inst.description = "in-memory"
        if seed_demo:
            inst.seed_demo()
        return inst

    # ---------------------------------------------------------------- utils
    @staticmethod
    def key(target: str, packet: str, item: str) -> str:
        return f"{KEY_PREFIX}:{target.upper()}:{packet.upper()}:{item.upper()}"

    def ping(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception as exc:  # redis.exceptions.ConnectionError, TimeoutError, ...
            raise RedisUnavailableError(f"Cannot reach Redis ({self.description}): {exc}") from exc

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except TelemetryDBError:
            raise
        except Exception as exc:
            if redis is not None and isinstance(exc, (redis.exceptions.ConnectionError,
                                                      redis.exceptions.TimeoutError)):
                raise RedisUnavailableError(f"Redis error ({self.description}): {exc}") from exc
            raise

    # ----------------------------------------------------------- write API
    def put_item(self, target: str, packet: str, item: str, *, type: str, subtype: str,
                 description: str = "", min_value: Optional[float] = None,
                 max_value: Optional[float] = None,
                 calibration_list: Optional[Sequence[str]] = None) -> str:
        mapping: Dict[str, Any] = {"name": item.upper(), "description": description,
                                   "type": type.upper(), "subtype": subtype.upper()}
        if min_value is not None:
            mapping["min_value"] = min_value
        if max_value is not None:
            mapping["max_value"] = max_value
        if calibration_list is not None:
            mapping["calibration_list"] = json.dumps(list(calibration_list))
        k = self.key(target, packet, item)
        self._validate(k, {k2: str(v) for k2, v in mapping.items()})
        self._call(self.client.hset, k, mapping=mapping)
        return k

    def seed_demo(self) -> int:
        """Load a representative INST telemetry dictionary."""
        defs = [
            ("INST", "HEALTH_STATUS", "TEMP1", "FLOAT", "NUMERIC", "Temperature #1 (C)", -100.0, 100.0, None),
            ("INST", "HEALTH_STATUS", "TEMP2", "FLOAT", "NUMERIC", "Temperature #2 (C)", -100.0, 100.0, None),
            ("INST", "HEALTH_STATUS", "COLLECTS", "UINT", "NUMERIC", "Collect counter", 0, 65535, None),
            ("INST", "HEALTH_STATUS", "DURATION", "FLOAT", "NUMERIC", "Collect duration (s)", 0.0, 10.0, None),
            ("INST", "HEALTH_STATUS", "MODE", "STRING", "CALIBRATION", "Subsystem mode", None, None,
             ["OFF", "NOMINAL", "DEGRADED", "CRITICAL"]),
            ("INST", "HEALTH_STATUS", "GROUND1STATUS", "STRING", "CALIBRATION", "Ground station link", None, None,
             ["CONNECTED", "UNAVAILABLE"]),
            ("INST", "POWER", "VOLTAGE", "FLOAT", "NUMERIC", "Bus voltage (V)", 22.0, 34.0, None),
            ("INST", "POWER", "CURRENT", "FLOAT", "NUMERIC", "Bus current (A)", 0.0, 5.0, None),
            ("INST", "POWER", "HEATER_OFFSET", "INT", "NUMERIC", "Heater offset (counts)", -50, 50, None),
        ]
        for t, p, i, ty, st, d, lo, hi, cal in defs:
            self.put_item(t, p, i, type=ty, subtype=st, description=d,
                          min_value=lo, max_value=hi, calibration_list=cal)
        return len(defs)

    # ------------------------------------------------------------ read API
    def list_items(self, target: str = "*", packet: str = "*") -> List[str]:
        pattern = f"{KEY_PREFIX}:{target.upper()}:{packet.upper()}:*"
        return sorted(self._call(lambda: list(self.client.scan_iter(match=pattern, count=500))))

    def get_item_meta(self, target: str, packet: str, item: str) -> Dict[str, Any]:
        k = self.key(target, packet, item)
        raw = self._call(self.client.hgetall, k)
        if not raw:
            raise TelemetryNotFoundError(f"Telemetry point '{target} {packet} {item}' not defined (missing key {k})")
        return self._validate(k, raw)

    @staticmethod
    def _validate(k: str, raw: Dict[str, str]) -> Dict[str, Any]:
        meta: Dict[str, Any] = dict(raw)
        ty = str(raw.get("type", "")).upper()
        st = str(raw.get("subtype", "")).upper()
        if ty not in VALID_TYPES:
            raise TelemetryDefinitionError(f"{k}: invalid type '{ty}' (expected one of {sorted(VALID_TYPES)})")
        if st not in VALID_SUBTYPES:
            raise TelemetryDefinitionError(f"{k}: invalid subtype '{st}' (expected NUMERIC or CALIBRATION)")
        meta["type"], meta["subtype"] = ty, st
        if st == "NUMERIC":
            try:
                lo, hi = float(raw["min_value"]), float(raw["max_value"])
            except KeyError as exc:
                raise TelemetryDefinitionError(f"{k}: NUMERIC item missing {exc.args[0]}") from None
            except ValueError as exc:
                raise TelemetryDefinitionError(f"{k}: non-numeric bound ({exc})") from None
            if math.isnan(lo) or math.isnan(hi) or lo > hi:
                raise TelemetryDefinitionError(f"{k}: invalid range [{lo}, {hi}]")
            if ty in ("INT", "UINT") and math.floor(hi) < math.ceil(lo):
                raise TelemetryDefinitionError(f"{k}: range [{lo}, {hi}] contains no integers")
            if ty == "UINT" and hi < 0:
                raise TelemetryDefinitionError(f"{k}: UINT item has negative max_value")
            meta["min_value"], meta["max_value"] = lo, hi
        else:
            try:
                cal = json.loads(raw.get("calibration_list", ""))
            except (TypeError, ValueError) as exc:
                raise TelemetryDefinitionError(f"{k}: calibration_list is not valid JSON ({exc})") from None
            if not isinstance(cal, list) or not cal:
                raise TelemetryDefinitionError(f"{k}: calibration_list must be a non-empty JSON array")
            meta["calibration_list"] = [str(c) for c in cal]
        return meta

    # ------------------------------------------------- simulation primitives
    def get_tm_value(self, target: str, packet: str, item: str,
                     strategy: str = "uniform", rng: Optional[random.Random] = None) -> Any:
        """Return a simulated value for a telemetry point.

        NUMERIC      -> uniform sample in the closed interval [min_value, max_value]
        CALIBRATION  -> random element of calibration_list

        Mutation strategies (used by the fuzzer when coverage stalls):
          uniform     - specification default
          boundary    - min/max/near-edge/mid values; first/last calibration states
          edge_heavy  - 50/50 mix of boundary and uniform
        """
        rng = rng or self.rng
        meta = self.get_item_meta(target, packet, item)
        if strategy == "edge_heavy":
            strategy = "boundary" if rng.random() < 0.5 else "uniform"

        if meta["subtype"] == "CALIBRATION":
            states = meta["calibration_list"]
            if strategy == "boundary":
                return rng.choice([states[0], states[-1]])
            return rng.choice(states)

        lo, hi = meta["min_value"], meta["max_value"]
        ty = meta["type"]
        if ty in ("INT", "UINT"):
            ilo, ihi = math.ceil(lo), math.floor(hi)
            if ty == "UINT":
                ilo = max(0, ilo)
            if strategy == "boundary":
                candidates = {ilo, ihi, min(ilo + 1, ihi), max(ihi - 1, ilo), (ilo + ihi) // 2}
                value: Any = rng.choice(sorted(candidates))
            else:
                value = rng.randint(ilo, ihi)
        else:
            if strategy == "boundary":
                candidates = [lo, hi, math.nextafter(lo, hi), math.nextafter(hi, lo), (lo + hi) / 2.0]
                value = rng.choice(candidates)
            else:
                value = lo if lo == hi else rng.uniform(lo, hi)
                value = min(max(value, lo), hi)  # guarantee closed interval despite FP rounding
        return str(value) if ty == "STRING" else value

    @staticmethod
    def send_command(target: str, command_name: str, params: Optional[Dict[str, Any]] = None,
                     rng: Optional[random.Random] = None) -> Dict[str, Any]:
        """Simulate command processing: SUCCESS 75 %, FAILURE 25 %."""
        chooser = rng.choices if rng is not None else random.choices
        status = chooser(["SUCCESS", "FAILURE"], weights=[75, 25], k=1)[0]
        return {"status": status, "target": target.upper(), "command": command_name.upper(),
                "params": dict(params or {}),
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}

    @staticmethod
    def handle_user_prompt(prompt_type: str, message: str,
                           valid_responses: Optional[Sequence[Any]] = None,
                           rng: Optional[random.Random] = None) -> Any:
        """Mock an operator dialog (ask, ask_string, message_box, prompt, combo_box...)."""
        rng = rng or random.Random()
        choices = [r for r in (valid_responses or []) if r is not None and str(r) != ""]
        if choices:
            return rng.choice(choices)
        alphabet = string.ascii_letters + string.digits
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 16)))
