"""Unit tests for redis_db: distributions, bounds, schema validation, error handling."""
import json
import os
import random
from collections import Counter

import pytest

from redis_db import (InMemoryRedis, RedisTelemetryDB, RedisUnavailableError,
                      TelemetryDefinitionError, TelemetryNotFoundError)


def test_default_command_ratio_is_75_25():
    db = RedisTelemetryDB.in_memory(seed_demo=False)
    rng = random.Random(1234)
    counts = Counter(db.send_command("X", "NOOP", rng=rng)["status"] for _ in range(20000))
    assert 0.74 <= counts["SUCCESS"] / 20000 <= 0.76


def test_per_command_success_rate(db):
    rng = random.Random(7)
    assert db.get_command_success_rate("INST", "SAFE") == 0.95
    safe = Counter(db.send_command("INST", "SAFE", rng=rng)["status"] for _ in range(10000))
    assert 0.94 <= safe["SUCCESS"] / 10000 <= 0.96
    db.put_command("INST", "NEVER", 0.0)
    assert all(db.send_command("INST", "NEVER", rng=rng)["status"] == "FAILURE" for _ in range(200))


def test_invalid_success_rate_rejected(db):
    db.client.hset("tc:INST:BAD", mapping={"success_rate": "1.5"})
    with pytest.raises(TelemetryDefinitionError):
        db.get_command_success_rate("INST", "BAD")
    with pytest.raises(TelemetryDefinitionError):
        db.put_command("INST", "X", -0.1)


@pytest.mark.parametrize("strategy", ["uniform", "boundary", "edge_heavy"])
def test_numeric_values_within_bounds(db, strategy):
    rng = random.Random(42)
    for key in db.list_items():
        _, t, p, i = key.split(":")
        meta = db.get_item_meta(t, p, i)
        for _ in range(500):
            v = db.get_tm_value(t, p, i, strategy=strategy, rng=rng)
            if meta["subtype"] == "NUMERIC":
                assert meta["min_value"] <= v <= meta["max_value"], (key, v)
                if meta["type"] in ("INT", "UINT"):
                    assert isinstance(v, int)
            else:
                assert v in meta["calibration_list"]


def test_boundary_strategy_hits_edges(db):
    rng = random.Random(3)
    values = {db.get_tm_value("INST", "HEALTH_STATUS", "COLLECTS", strategy="boundary", rng=rng) for _ in range(300)}
    assert {0, 65535} <= values


def test_uint_never_negative():
    db = RedisTelemetryDB.in_memory(seed_demo=False)
    db.put_item("T", "P", "U", type="UINT", subtype="NUMERIC", min_value=-5, max_value=3)
    rng = random.Random(0)
    assert all(0 <= db.get_tm_value("T", "P", "U", rng=rng) <= 3 for _ in range(500))


def test_missing_key_raises(db):
    with pytest.raises(TelemetryNotFoundError):
        db.get_tm_value("INST", "NOPE", "MISSING")


@pytest.mark.parametrize("raw", [
    {"type": "BOGUS", "subtype": "NUMERIC", "min_value": "0", "max_value": "1"},
    {"type": "FLOAT", "subtype": "NUMERIC", "min_value": "5", "max_value": "1"},
    {"type": "FLOAT", "subtype": "NUMERIC", "min_value": "abc", "max_value": "1"},
    {"type": "FLOAT", "subtype": "NUMERIC", "min_value": "0"},
    {"type": "INT", "subtype": "NUMERIC", "min_value": "0.2", "max_value": "0.8"},
    {"type": "STRING", "subtype": "CALIBRATION", "calibration_list": "not json"},
    {"type": "STRING", "subtype": "CALIBRATION", "calibration_list": "[]"},
])
def test_malformed_definitions_rejected(raw):
    client = InMemoryRedis()
    client.hset("tm:T:P:I", mapping=raw)
    db = RedisTelemetryDB(client=client)
    with pytest.raises(TelemetryDefinitionError):
        db.get_item_meta("T", "P", "I")


class _DeadClient(InMemoryRedis):
    def ping(self):
        raise ConnectionError("connection refused")

    def hgetall(self, key):
        raise ConnectionError("connection reset")


def test_connection_errors_wrapped():
    db = RedisTelemetryDB(client=_DeadClient())
    with pytest.raises(RedisUnavailableError):
        db.ping()
    with pytest.raises(RedisUnavailableError):
        db.get_tm_value("INST", "HEALTH_STATUS", "TEMP1")


def test_unreachable_real_redis():
    pytest.importorskip("redis")
    db = RedisTelemetryDB(host="127.0.0.1", port=1, socket_timeout=0.5)
    with pytest.raises(RedisUnavailableError):
        db.ping()


def test_prompt_handler():
    rng = random.Random(1)
    assert RedisTelemetryDB.handle_user_prompt("message_box", "?", ["A", "B"], rng) in ("A", "B")
    s = RedisTelemetryDB.handle_user_prompt("ask_string", "?", None, rng)
    assert isinstance(s, str) and 1 <= len(s) <= 16


@pytest.mark.skipif(not os.environ.get("FUZZER_TEST_REDIS"), reason="set FUZZER_TEST_REDIS=host:port")
def test_live_redis_roundtrip():
    host, port = os.environ["FUZZER_TEST_REDIS"].split(":")
    db = RedisTelemetryDB(host=host, port=int(port))
    db.ping()
    db.seed_demo()
    meta = db.get_item_meta("INST", "HEALTH_STATUS", "MODE")
    assert json.loads(json.dumps(meta["calibration_list"]))[0] == "OFF"
    assert -100 <= db.get_tm_value("INST", "HEALTH_STATUS", "TEMP1") <= 100
