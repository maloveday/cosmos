import os
import sys
import textwrap

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "microservices", "FUZZER"))

from redis_db import RedisTelemetryDB  # noqa: E402


@pytest.fixture
def db():
    return RedisTelemetryDB.in_memory(seed_demo=True)


@pytest.fixture
def make_script(tmp_path):
    def _make(body: str, name: str = "proc.py") -> str:
        path = tmp_path / name
        path.write_text(textwrap.dedent(body), encoding="utf-8")
        return str(path)
    return _make


@pytest.fixture
def sample_script():
    return os.path.join(HERE, "..", "examples", "sample_test.py")
