"""
sample_test.py - Verification procedure exercising TM, TC and operator dialogs.

Runs unmodified in COSMOS Script Runner, and headless under the fuzzer:
    python microservices/FUZZER/fuzzer_cli.py --script examples/sample_test.py --in-memory
"""
from openc3.script import *

# ---- 1. Mode-dependent branching on calibrated telemetry --------------------
mode = tlm("INST HEALTH_STATUS MODE")
if mode == "CRITICAL":
    answer = message_box("INST is CRITICAL. Safe the instrument?", "SAFE", "ABORT")
    if answer == "ABORT":
        raise RuntimeError("Operator aborted checkout in CRITICAL mode")
    cmd("INST SAFE")
elif mode == "DEGRADED":
    cmd("INST CLEAR")
elif mode == "OFF":
    cmd("INST POWER_ON with DELAY 2")
    wait(2)

# ---- 2. Numeric telemetry limits ---------------------------------------------
temp = tlm("INST", "HEALTH_STATUS", "TEMP1")
if temp > 80.0:
    cmd("INST HEATER with STATE 'OFF'")
elif temp < -80.0:
    cmd("INST HEATER with STATE 'ON'")

check("INST POWER VOLTAGE >= 22.0")
voltage = tlm("INST POWER VOLTAGE")
if voltage > 33.0:
    raise RuntimeError(f"Bus over-voltage detected: {voltage:.2f} V")

# ---- 3. Commanding with retry on stochastic failure -----------------------------
result = cmd("INST COLLECT with TYPE 'NORMAL', DURATION 1.0, TEMP 10.0")
retries = 0
while result["status"] != "SUCCESS" and retries < 3:
    retries += 1
    result = cmd("INST COLLECT with TYPE 'NORMAL', DURATION 1.0, TEMP 10.0")
if result["status"] != "SUCCESS":
    raise RuntimeError("COLLECT command failed after 3 retries")

wait_check("INST HEALTH_STATUS GROUND1STATUS == 'CONNECTED'", 5)

# ---- 4. Operator dialogs -----------------------------------------------------------
initials = ask_string("Enter operator initials")
collect_type = combo_box("Select collect type", "NORMAL", "SPECIAL", "ABORT")
if collect_type == "ABORT":
    prompt(f"Operator {initials} skipped the special collect")
elif collect_type == "SPECIAL":
    # Polling loop that rarely converges -> exercises staleness interruption
    while tlm("INST HEALTH_STATUS COLLECTS") < 65500:
        wait(0.5)
    cmd("INST COLLECT with TYPE 'SPECIAL'")
else:
    prompt("Verify NORMAL collect completed on the ground display")

print(f"Checkout complete by {initials}")
