# openc3-cosmos-script-fuzzer

Coverage-guided, headless fuzzer for OpenC3 COSMOS **Script Runner** procedures.

- Telemetry (`tlm`, `check`, `wait_check`, …) is sampled from Redis metadata at `tm:<TARGET>:<PACKET>:<ITEM>`.
- Commands (`cmd*`) return `{"status": "SUCCESS"}` 75 % of the time and `{"status": "FAILURE"}` 25 % of the time.
- Operator dialogs (`ask`, `ask_string`, `message_box`, `combo_box`, `prompt`) get random valid answers.
- `Coverage.py` (`branch=True`) measures line and branch coverage across iterations.
- Staleness heuristics interrupt stalled runs and switch mutation strategy (`uniform` → `boundary` → `edge_heavy`), or end the campaign early.
- Output is a single-file HTML report styled after Robot Framework.

## Redis schema

| Field | Description |
|---|---|
| `name` | Mnemonic |
| `description` | Description |
| `type` | `INT` / `UINT` / `FLOAT` / `STRING` |
| `subtype` | `NUMERIC` / `CALIBRATION` |
| `min_value`, `max_value` | Numeric bounds (NUMERIC) |
| `calibration_list` | JSON array of states (CALIBRATION) |

```bash
redis-cli HSET tm:INST:HEALTH_STATUS:MODE name MODE description "Mode" type STRING \
  subtype CALIBRATION calibration_list '["OFF","NOMINAL","DEGRADED","CRITICAL"]'
```

## CLI

```bash
pip install -r requirements.txt
cd microservices/FUZZER
python fuzzer_cli.py --script INST/procedures/subsystem_checkout.py \
  --redis-host localhost --redis-port 6379 --output report.html --staleness-threshold 10

# Offline demo with no Redis server (uses the built-in demo dictionary)
python fuzzer_cli.py --script ../../examples/sample_test.py --in-memory --seed 1
```

Main options: `--seed-demo`, `--loop-staleness N`, `--stale-seconds T`, `--timeout`, `--iterations`, `--strategies`, `--seed`, `--json-output`.
Exit code: `0` = all passed, `1` = failures, `2` = configuration or Redis error.

## Staleness heuristics

| Detector | Trigger | Action |
|---|---|---|
| Across iterations | `--staleness-threshold` iterations with no new line or arc | Switch to the next strategy. Once all strategies are used up, end the campaign. |
| Loop inside a run | `--loop-staleness` API calls in a row that only repeat known (line, previous line) transitions | Raise `StaleExecutionError` in the procedure |
| Time inside a run | `--stale-seconds` with no new transition | Inject an async interrupt (this also catches pure-Python loops) |
| Hard limit | `--timeout` | `PROCEDURE_TIMEOUT` interrupt |

Every interruption is logged as a `STALE_EXECUTION_TIMEOUT` event. The interrupt exceptions subclass `BaseException`, so a procedure's `except Exception:` cannot swallow them.

## Microservice

`plugin.txt` registers the `FUZZER` microservice. To run a job, push JSON onto `openc3-script-fuzzer:jobs`:

```json
{"id": "run42", "script_text": "from openc3.script import *\n...", "max_iterations": 50, "staleness_threshold": 10}
```

The HTML report is saved to `openc3-script-fuzzer:report:run42`, with a summary at `...:run42:summary`.

## Build

```bash
rake build VERSION=1.0.0
```

## Notes

During fuzzing, `openc3.script` is temporarily replaced by a simulated module with the same function names. Procedures therefore need no edits, and nothing is sent to real hardware.

## License

MIT. See [LICENSE.md](LICENSE.md).
