"""
fuzzer_cli.py - Command line harness for the OpenC3 COSMOS Script Fuzzer.

Example:
    python fuzzer_cli.py --script INST/procedures/subsystem_checkout.py \
        --redis-host localhost --redis-port 6379 --output report.html --staleness-threshold 10

Exit codes: 0 all iterations passed, 1 failures found, 2 configuration/infrastructure error.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import json
import os
import sys

import click

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fuzzer_microservice import FuzzConfig, ScriptFuzzer  # noqa: E402
from redis_db import STRATEGIES, RedisTelemetryDB, TelemetryDBError  # noqa: E402
from report_generator import write_report  # noqa: E402


def _resolve_script(path: str) -> str:
    if os.path.isfile(path):
        return os.path.abspath(path)
    root = os.environ.get("FUZZER_SCRIPT_ROOT")  # e.g. a checked-out plugin's targets/ directory
    if root and os.path.isfile(os.path.join(root, path)):
        return os.path.abspath(os.path.join(root, path))
    raise click.BadParameter(f"Procedure '{path}' not found (cwd or $FUZZER_SCRIPT_ROOT)", param_hint="--script")


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--script", "script", required=True, help="Script Runner procedure to fuzz (e.g. INST/procedures/x.py).")
@click.option("--redis-host", default="localhost", show_default=True)
@click.option("--redis-port", default=6379, show_default=True, type=int)
@click.option("--redis-db", default=0, show_default=True, type=int)
@click.option("--redis-username", default=None, envvar="OPENC3_REDIS_USERNAME")
@click.option("--redis-password", default=None, envvar="OPENC3_REDIS_PASSWORD")
@click.option("--in-memory", is_flag=True, help="Use a built-in in-memory store instead of Redis (implies --seed-demo).")
@click.option("--seed-demo", is_flag=True, help="Load the demo INST telemetry dictionary into Redis first.")
@click.option("--output", default="report.html", show_default=True, help="HTML report path.")
@click.option("--json-output", default=None, help="Optional raw JSON results path.")
@click.option("--staleness-threshold", default=10, show_default=True, type=click.IntRange(min=1),
              help="N consecutive iterations without new line/branch coverage => stale.")
@click.option("--loop-staleness", default=25, show_default=True, type=click.IntRange(min=1),
              help="N repeated API transitions within one run => stale loop interrupt.")
@click.option("--stale-seconds", default=30.0, show_default=True, type=click.FloatRange(min=0.1),
              help="T seconds without a new transition within one run => stale interrupt.")
@click.option("--timeout", "iteration_timeout", default=60.0, show_default=True, type=click.FloatRange(min=0.1),
              help="Hard per-iteration timeout in seconds.")
@click.option("--iterations", "max_iterations", default=100, show_default=True, type=click.IntRange(min=1))
@click.option("--strategies", default=",".join(STRATEGIES), show_default=True,
              help="Comma-separated mutation strategy order.")
@click.option("--seed", default=None, type=int, help="RNG seed for reproducible campaigns.")
def main(script, redis_host, redis_port, redis_db, redis_username, redis_password, in_memory, seed_demo,
         output, json_output, staleness_threshold, loop_staleness, stale_seconds, iteration_timeout,
         max_iterations, strategies, seed):
    """Fuzz an OpenC3 COSMOS Script Runner procedure against a Redis-backed simulation."""
    script_path = _resolve_script(script)
    try:
        if in_memory:
            db = RedisTelemetryDB.in_memory(seed_demo=True)
        else:
            db = RedisTelemetryDB(host=redis_host, port=redis_port, db=redis_db,
                                  username=redis_username, password=redis_password)
            db.ping()
            if seed_demo:
                click.echo(f"Seeded {db.seed_demo()} demo telemetry definitions", err=True)
        if not db.list_items():
            click.echo("WARNING: no tm:* keys found in Redis; tlm() calls will fail (use --seed-demo)", err=True)

        cfg = FuzzConfig(script_path=script_path, staleness_threshold=staleness_threshold,
                         loop_staleness=loop_staleness, stale_seconds=stale_seconds,
                         iteration_timeout=iteration_timeout, max_iterations=max_iterations, seed=seed,
                         strategies=tuple(s.strip() for s in strategies.split(",") if s.strip()))
        result = ScriptFuzzer(db, cfg).run()
    except (TelemetryDBError, FileNotFoundError, ValueError, SyntaxError) as exc:
        click.echo(f"ERROR: {type(exc).__name__}: {exc}", err=True)
        sys.exit(2)

    path = write_report(result, output)
    if json_output:
        with open(json_output, "w", encoding="utf-8") as fh:
            json.dump({k: v for k, v in result.items() if k != "source"}, fh, indent=2, default=str)

    s, c = result["summary"], result["coverage"]
    click.echo(f"\n{s['total']} iterations, {s['passed']} passed, {s['failed']} failed ({s['pass_pct']}%)")
    click.echo(f"Line coverage {c['line_pct']}% | Branch coverage {c['branch_pct']}% | "
               f"Staleness interruptions {result['stale_interruptions']}")
    click.echo(f"{result['conclusion']}\nReport: {path}")
    sys.exit(0 if s["failed"] == 0 else 1)


if __name__ == "__main__":
    main()
