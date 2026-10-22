# openc3-cosmos-script-fuzzer

Coverage-guided, headless fuzzer for OpenC3 COSMOS **Script Runner** procedures.

- Telemetry (`tlm`, `check`, `wait_check`, `wait_check_tolerance`, …) is sampled from Redis metadata at `tm:<TARGET>:<PACKET>:<ITEM>`. An optional hold window keeps values stable for a set span of simulated time.
- Commands (`cmd*`) succeed with probability `tc:<TARGET>:<CMD>.success_rate`. The default is 75 % SUCCESS / 25 % FAILURE.
- Operator dialogs get random valid answers. `ask()` returns a mix of ints, floats and strings.
- `time.sleep` and `wait` advance simulated time and never block.
- `Coverage.py` (`branch=True`) measures line and branch coverage across iterations.
- The fuzzer is coverage-guided. Input traces that found new coverage are kept in a corpus and replayed with some decisions re-drawn.
- Staleness heuristics interrupt stalled runs and switch mutation strategy (`uniform` → `boundary` → `edge_heavy`), or end the campaign early.
- Outputs:
  - a single-file HTML report styled after Robot Framework
  - JUnit XML
  - Cobertura XML
  - raw JSON

## Redis schema

`tm:<TARGET>:<PACKET>:<ITEM>` (hash):

| Field | Description |
|---|---|
| `name`, `description` | Mnemonic / description |
| `type` | `INT` / `UINT` / `FLOAT` / `STRING` |
| `subtype` | `NUMERIC` / `CALIBRATION` |
| `min_value`, `max_value` | Numeric bounds (NUMERIC) |
| `calibration_list` | JSON array of states (CALIBRATION) |

`tc:<TARGET>:<COMMAND>` (hash, optional): `success_rate` in `[0, 1]`, `description`.

```bash
redis-cli HSET tm:INST:HEALTH_STATUS:MODE name MODE type STRING subtype CALIBRATION \
  calibration_list '["OFF","NOMINAL","DEGRADED","CRITICAL"]'
redis-cli HSET tc:INST:SAFE success_rate 0.95
```

## CLI

```bash
pip install -r requirements.txt
python microservices/FUZZER/fuzzer_cli.py --script INST/procedures/subsystem_checkout.py \
  --redis-host localhost --redis-port 6379 --output report.html --staleness-threshold 10 \
  --junit-xml junit.xml --cobertura-xml coverage.xml

# Offline demo (no Redis server)
python microservices/FUZZER/fuzzer_cli.py --script examples/sample_test.py --in-memory --seed 1
```

| Option | Default | Purpose |
|---|---|---|
| `--staleness-threshold N` | 10 | Iterations with no new coverage before the run counts as stale |
| `--loop-staleness N` | 25 | Repeated API transitions in a single run before it is interrupted |
| `--stale-seconds T` | 30 | Seconds with no new transition before a run is interrupted |
| `--timeout` | 60 | Hard time limit per iteration |
| `--tlm-hold-seconds` | 0 | How long telemetry values persist, in simulated seconds (0 = new sample on every read) |
| `--ask-numeric-prob` / `--ask-numeric-range` | 0.5 / `-1000,1000` | Chance and range of numeric `ask()` answers |
| `--default-success-rate` | 0.75 | Command success rate when no `tc:*` key exists |
| `--corpus-prob` / `--mutation-rate` | 0.5 / 0.2 | Chance of replaying a corpus trace / share of decisions re-drawn |
| `--seed` | – | Makes the campaign reproducible |

Exit codes:
- `0`: all iterations passed
- `1`: procedure failures found
- `2`: configuration error, Redis unreachable, or Redis lost mid-campaign

A Redis outage always aborts the campaign, even when the procedure catches the exception.

## Staleness heuristics

| Detector | Trigger | Action |
|---|---|---|
| Across iterations | No new line or arc for `--staleness-threshold` iterations | Switch to the next strategy. Once all strategies are used up, end the campaign. |
| Loop inside a run | `--loop-staleness` API calls in a row that only repeat known (line, previous line) transitions | Raise `StaleExecutionError` in the procedure |
| Time inside a run | `--stale-seconds` with no new transition | Inject an async interrupt (this also catches pure-Python loops) |
| Hard limit | `--timeout` | `PROCEDURE_TIMEOUT` interrupt |

The interrupt exceptions subclass `BaseException`, so a procedure's `except Exception:` cannot swallow them.

## Microservice and job security

`plugin.txt` registers the `FUZZER` microservice. Jobs are JSON objects pushed onto `openc3-script-fuzzer:jobs`:

```json
{"id": "run42", "script_path": "INST/procedures/checkout.py", "max_iterations": 50, "signature": "<hmac>"}
```

Jobs are checked as follows:
- `script_path` must resolve to a file inside `FUZZER_ALLOWED_ROOTS`. Path traversal is rejected.
- If the `FUZZER_JOB_SECRET` secret is set, each job must carry `signature = HMAC-SHA256(secret, canonical JSON without "signature")`. You can generate it with `fuzzer_microservice.sign_job()`.
- Raw `script_text` is accepted only when `FUZZER_ALLOW_SCRIPT_TEXT=1` and a secret is set.
- Unknown fields are rejected. Numeric limits are clamped.

Results are saved in Redis:
- the HTML report at `openc3-script-fuzzer:report:<id>`
- the status (`COMPLETE` / `ABORTED` / `REJECTED`) at `...:<id>:summary`

## Development

```bash
pip install -r requirements-dev.txt
pytest tests -q                      # FUZZER_TEST_REDIS=localhost:6379 enables the live-Redis test
```

CI is defined in `.github/workflows/script-fuzzer.yml`. It runs:
- pytest on a Python matrix, with a Redis service container
- a live-Redis fuzz run of the sample procedure, uploading the HTML, JUnit and Cobertura outputs

## Build

```bash
rake build VERSION=1.0.0
```

## License

MIT. See [LICENSE.md](LICENSE.md).
