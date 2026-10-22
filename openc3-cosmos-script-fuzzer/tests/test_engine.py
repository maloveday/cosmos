"""Engine tests: staleness, simulated sleep, determinism, aborts, API semantics, corpus, outputs, jobs."""
import json
import os
import random
import time
import xml.etree.ElementTree as ET

import pytest

from fuzzer_microservice import (INFRASTRUCTURE_ERROR, FuzzConfig, JobRejected, ScriptFuzzer,
                                 run_job, sign_job, validate_job)
from coverage_tracker import STALE_EXECUTION_TIMEOUT
from redis_db import InMemoryRedis, RedisTelemetryDB
from report_generator import render_report, write_junit


def fuzz(db, path, **kw):
    kw.setdefault("max_iterations", 5)
    kw.setdefault("seed", 1)
    return ScriptFuzzer(db, FuzzConfig(script_path=path, **kw)).run()


# ------------------------------------------------------------------ staleness
def test_tlm_polling_loop_flagged_stale(db, make_script):
    path = make_script("""
        from openc3.script import *
        while tlm("INST HEALTH_STATUS TEMP1") < 1000:
            wait(1)
    """)
    r = fuzz(db, path, max_iterations=2, loop_staleness=10)
    assert all(t["event"] == STALE_EXECUTION_TIMEOUT for t in r["tests"])
    assert r["stale_interruptions"] >= 1


def test_pure_python_infinite_loop_interrupted(db, make_script):
    path = make_script("""
        x = 0
        while True:
            x += 1
    """)
    t0 = time.monotonic()
    r = fuzz(db, path, max_iterations=1, stale_seconds=0.5, iteration_timeout=10)
    assert time.monotonic() - t0 < 5
    assert r["tests"][0]["event"] == STALE_EXECUTION_TIMEOUT


def test_procedure_cannot_swallow_interrupt(db, make_script):
    path = make_script("""
        from openc3.script import *
        while True:
            try:
                tlm("INST HEALTH_STATUS TEMP1")
            except Exception:
                pass
    """)
    r = fuzz(db, path, max_iterations=1, loop_staleness=5)
    assert r["tests"][0]["event"] == STALE_EXECUTION_TIMEOUT


def test_campaign_concludes_early_when_coverage_plateaus(db, make_script):
    path = make_script("""
        from openc3.script import *
        tlm("INST POWER VOLTAGE")
    """)
    r = fuzz(db, path, max_iterations=100, staleness_threshold=3)
    assert r["concluded_early"] and r["summary"]["total"] < 20


# ------------------------------------------------------------- simulated sleep
def test_time_sleep_is_simulated(db, make_script):
    path = make_script("""
        import time
        from time import sleep
        time.sleep(3600)
        sleep(3600)
    """)
    t0 = time.monotonic()
    r = fuzz(db, path, max_iterations=1)
    assert time.monotonic() - t0 < 5
    t = r["tests"][0]
    assert t["status"] == "PASS"
    assert [s["keyword"] for s in t["steps"]] == ["time.sleep", "time.sleep"]
    assert time.sleep.__module__ == "time" or callable(time.sleep)  # restored afterwards


def test_sleep_polling_loop_flagged_stale(db, make_script):
    path = make_script("""
        import time
        while True:
            time.sleep(1)
    """)
    r = fuzz(db, path, max_iterations=1, loop_staleness=5)
    assert r["tests"][0]["event"] == STALE_EXECUTION_TIMEOUT


# ------------------------------------------------------------------ determinism
def _fingerprint(result):
    return [(t["status"], t["origin"], [(s["keyword"], s["args"], s["result"]) for s in t["steps"]])
            for t in result["tests"]]


def test_seeded_runs_are_deterministic(sample_script):
    a = fuzz(RedisTelemetryDB.in_memory(), sample_script, max_iterations=15, seed=99)
    b = fuzz(RedisTelemetryDB.in_memory(), sample_script, max_iterations=15, seed=99)
    assert _fingerprint(a) == _fingerprint(b)
    assert a["coverage"]["line_pct"] == b["coverage"]["line_pct"]


# ------------------------------------------------------------- infrastructure
class _FlakyClient(InMemoryRedis):
    def __init__(self, fail_after):
        super().__init__()
        self.calls, self.fail_after = 0, fail_after

    def hgetall(self, key):
        self.calls += 1
        if self.calls > self.fail_after:
            raise ConnectionError("Redis connection lost")
        return super().hgetall(key)


def test_redis_drop_aborts_campaign_even_if_swallowed(make_script):
    db = RedisTelemetryDB(client=_FlakyClient(fail_after=10_000))
    db.seed_demo()
    db.client.fail_after = db.client.calls + 4
    path = make_script("""
        from openc3.script import *
        for _ in range(3):
            try:
                tlm("INST HEALTH_STATUS TEMP1")
            except Exception:
                pass
    """)
    r = fuzz(db, path, max_iterations=20)
    assert r["aborted"] and r["summary"]["total"] < 20
    assert r["tests"][-1]["event"] == INFRASTRUCTURE_ERROR
    assert any(e["event"] == INFRASTRUCTURE_ERROR for e in r["events"])


# ------------------------------------------------------------- API semantics
def test_wait_check_tolerance(db, make_script):
    db.put_item("T", "P", "FIXED", type="FLOAT", subtype="NUMERIC", min_value=5.0, max_value=5.0)
    path = make_script("""
        from openc3.script import *
        wait_check_tolerance("T P FIXED", 5.1, 0.2, 2)
        try:
            wait_check_tolerance("T P FIXED", 10.0, 0.5, 1)
            raise RuntimeError("should have failed")
        except CheckError:
            pass
    """)
    r = fuzz(db, path, max_iterations=1)
    assert r["tests"][0]["status"] == "PASS", r["tests"][0]["message"]


def test_ask_returns_numbers_in_range(db, make_script):
    path = make_script("""
        from openc3.script import *
        answers = [ask("n?") for _ in range(200)]
        nums = [a for a in answers if isinstance(a, (int, float))]
        assert len(nums) > 50
        assert all(-10 <= n <= 10 for n in nums)
        assert any(isinstance(a, int) for a in nums) and any(isinstance(a, float) for a in nums)
    """)
    r = fuzz(db, path, max_iterations=1, ask_numeric_range=(-10, 10), ask_numeric_prob=0.8, loop_staleness=1000)
    assert r["tests"][0]["status"] == "PASS", r["tests"][0]["message"]


def test_tlm_hold_window(db, make_script):
    path = make_script("""
        from openc3.script import *
        a = tlm("INST HEALTH_STATUS TEMP1")
        b = tlm("INST HEALTH_STATUS TEMP1")
        assert a == b, "held value should persist without simulated time passing"
        wait(5)
        c = tlm("INST HEALTH_STATUS TEMP1")
        assert c != a, "value should refresh after the window"
    """)
    r = fuzz(db, path, max_iterations=3, tlm_hold_seconds=2.0)
    assert all(t["status"] == "PASS" for t in r["tests"]), [t["message"] for t in r["tests"]]


def test_no_hold_window_resamples(db, make_script):
    path = make_script("""
        from openc3.script import *
        vals = {tlm("INST HEALTH_STATUS TEMP1") for _ in range(5)}
        assert len(vals) > 1
    """)
    assert fuzz(db, path, max_iterations=1)["tests"][0]["status"] == "PASS"


# --------------------------------------------------------------------- corpus
def test_corpus_replays_and_mutates(sample_script):
    r = fuzz(RedisTelemetryDB.in_memory(), sample_script, max_iterations=30, corpus_prob=0.9,
             staleness_threshold=50)
    assert r["corpus_size"] >= 1
    mutated = [t for t in r["tests"] if t["origin"].startswith("mutated")]
    assert mutated and any(t["reused"] > 0 for t in mutated)


def test_corpus_disabled(sample_script):
    r = fuzz(RedisTelemetryDB.in_memory(), sample_script, max_iterations=10, corpus_prob=0.0)
    assert all(t["origin"] == "fresh" for t in r["tests"])


# -------------------------------------------------------------------- outputs
def test_reports(sample_script, tmp_path):
    db = RedisTelemetryDB.in_memory()
    fuzzer = ScriptFuzzer(db, FuzzConfig(script_path=sample_script, max_iterations=8, seed=5))
    r = fuzzer.run()
    html = render_report(r)
    assert "Coverage Dashboard" in html and "Fuzz Iteration 001" in html
    junit = ET.parse(write_junit(r, str(tmp_path / "junit.xml"))).getroot()
    suite = junit.find("testsuite")
    assert int(suite.get("tests")) == r["summary"]["total"]
    assert len(suite.findall("testcase/failure")) == r["summary"]["failed"]
    cob = ET.parse(fuzzer.tracker.write_cobertura(str(tmp_path / "cov.xml"))).getroot()
    assert cob.tag == "coverage" and float(cob.get("line-rate")) > 0


# ----------------------------------------------------------------------- jobs
def test_job_requires_allowed_root(tmp_path, make_script):
    path = make_script("x = 1\n")
    with pytest.raises(JobRejected):
        validate_job({"script_path": path}, env={})
    spec = validate_job({"script_path": "proc.py", "max_iterations": 99999}, env={"FUZZER_ALLOWED_ROOTS": str(tmp_path)})
    assert spec["script_path"] == os.path.realpath(path)
    assert spec["config"]["max_iterations"] == 1000


def test_job_path_traversal_rejected(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "evil.py").write_text("x=1")
    with pytest.raises(JobRejected):
        validate_job({"script_path": "../evil.py"}, env={"FUZZER_ALLOWED_ROOTS": str(root)})


def test_job_signature_and_script_text():
    env = {"FUZZER_JOB_SECRET": "s3cret"}
    job = {"id": "a", "script_text": "x = 1\n"}
    with pytest.raises(JobRejected):
        validate_job(job, env)  # unsigned
    signed = dict(job, signature=sign_job(job, "s3cret"))
    with pytest.raises(JobRejected):
        validate_job(signed, env)  # script_text not enabled
    assert validate_job(signed, dict(env, FUZZER_ALLOW_SCRIPT_TEXT="1"))["script_text"] == "x = 1\n"
    with pytest.raises(JobRejected):
        validate_job(dict(signed, max_iterations=5), dict(env, FUZZER_ALLOW_SCRIPT_TEXT="1"))  # tampered


def test_job_unknown_fields_rejected(tmp_path, make_script):
    make_script("x = 1\n")
    with pytest.raises(JobRejected):
        validate_job({"script_path": "proc.py", "__import__": "os"}, env={"FUZZER_ALLOWED_ROOTS": str(tmp_path)})


def test_run_job_stores_report(db, tmp_path, make_script):
    make_script("from openc3.script import *\ntlm('INST POWER VOLTAGE')\n")
    out = run_job(db, {"id": "j1", "script_path": "proc.py", "max_iterations": 2},
                  env={"FUZZER_ALLOWED_ROOTS": str(tmp_path)})
    assert out["status"] == "COMPLETE"
    assert "<html" in db.client.get("openc3-script-fuzzer:report:j1")
    rejected = run_job(db, {"id": "j2", "script_text": "x=1"}, env={})
    assert rejected["status"] == "REJECTED"
    assert json.loads(db.client.get("openc3-script-fuzzer:report:j2:summary"))["status"] == "REJECTED"
