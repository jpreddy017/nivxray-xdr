#!/usr/bin/env python3
"""P0-F.5/F.6 acceptance proof · real endpoint response, independently
verified.

A REAL process is started on this host, an analyst requests a kill through
the API, the REAL sensor claims the command and delivers SIGKILL, and the
platform marks it VERIFIED only after post-action evidence proves the pid
is gone. Then the negative cases: a pid never observed is refused, and
isolation is honestly reported as unavailable rather than faked.

    python3 /app/scripts/p0_f5_response_proof.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SENSOR = "/app/agents/nivxforge-linux/nivxforge_sensor.py"
STATE = "/tmp/nivx-p0f5"
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
FAILURES: list[str] = []


def call(path, body=None, bearer=None, method=None):
    r = urllib.request.Request(
        f"{API}{path}",
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0F5-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method=method or ("POST" if body is not None else "GET"))
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


pw = next(l.split("`")[1] for l in
          Path("/app/memory/test_credentials.md").read_text().splitlines()
          if l.startswith("- **Password**"))
admin = call("/api/auth/login",
             {"email": "admin@nivxray.com", "password": pw})["access_token"]
env = {**os.environ, "NIVXFORGE_SENSOR_STATE": STATE}

print("\n=== 1 · enrol a real sensor and observe a REAL target process")
tok = call("/api/edr/enrollment/tokens", {"label": "p0f5-proof"},
           bearer=admin)["enrollment_token"]
subprocess.run([sys.executable, SENSOR, "enrol", "--api", API, "--tenant",
                "default", "--token", tok], capture_output=True, env=env)
endpoint = json.loads(Path(f"{STATE}/identity.json").read_text())[
    "endpoint_id"]
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)          # baseline
victim = subprocess.Popen(["/bin/sleep", "600"])
time.sleep(2)
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)          # observe the victim
print(f"   endpoint {endpoint} · real target pid {victim.pid}")
check("the target process is genuinely running",
      Path(f"/proc/{victim.pid}").exists())

print("\n=== 2 · an analyst requests the kill (nothing happens yet)")
cmd = call("/api/edr/response/actions",
           {"endpoint_id": endpoint, "action": "KILL_PROCESS",
            "target": {"pid": victim.pid},
            "reason": "P0-F.5 acceptance proof"}, bearer=admin)
print("   " + json.dumps({k: cmd.get(k) for k in
                          ("command_id", "state", "action")}) )
print("   target enriched from evidence: "
      + json.dumps(cmd["target"])[:200])
check("the command is REQUESTED, not succeeded", cmd["state"] == "REQUESTED")
check("the target was resolved from OBSERVED evidence",
      bool(cmd["target"].get("observed_command_line")))
check("the process is still alive while merely REQUESTED",
      Path(f"/proc/{victim.pid}").exists())

print("\n=== 3 · the REAL sensor claims, executes and proves it")
run = subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
                     capture_output=True, text=True, env=env)
print("   " + "\n   ".join(
    l for l in (run.stdout + run.stderr).strip().splitlines()[-4:]))
time.sleep(1)
rows = call(f"/api/edr/response/actions?endpoint_id={endpoint}",
            bearer=admin)["commands"]
mine = [r for r in rows if r["command_id"] == cmd["command_id"]][0]
print("   states: " + " → ".join(h["state"] for h in mine["history"]))
print("   sensor said: " + json.dumps(mine["sensor_result"])[:220])
print("   verification: " + json.dumps(mine["verification"])[:260])
check("the command reached VERIFIED", mine["state"] == "VERIFIED",
      mine["state"])
check("the full state machine was recorded",
      [h["state"] for h in mine["history"]]
      == ["REQUESTED", "DISPATCHED", "EXECUTED", "VERIFIED"])
check("verification is INDEPENDENT post-action evidence",
      mine["verification"]["method"] == "post_action_proc_read"
      and mine["verification"]["probe"]["process_present"] is False)
check("the REAL process is actually gone",
      not Path(f"/proc/{victim.pid}").exists())
check("the OS agrees the process was killed",
      victim.poll() is not None or victim.wait(timeout=5) is not None)

print("\n=== 4 · NEGATIVE · a pid never observed is refused")
try:
    call("/api/edr/response/actions",
         {"endpoint_id": endpoint, "action": "KILL_PROCESS",
          "target": {"pid": 999999}, "reason": "negative"}, bearer=admin)
    check("a never-observed pid is refused", False)
except urllib.error.HTTPError as e:
    d = json.loads(e.read())
    print("   " + json.dumps(d)[:220])
    check("a never-observed pid is refused",
          d["detail"]["error"] == "TARGET_NOT_OBSERVED", f"HTTP {e.code}")

print("\n=== 5 · NEGATIVE · isolation is reported unavailable, never faked")
iso = call("/api/edr/response/actions",
           {"endpoint_id": endpoint, "action": "ISOLATE_ENDPOINT",
            "target": {}, "reason": "negative"}, bearer=admin)
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)
rows = call(f"/api/edr/response/actions?endpoint_id={endpoint}",
            bearer=admin)["commands"]
got = [r for r in rows if r["command_id"] == iso["command_id"]][0]
print("   " + json.dumps({"state": got["state"],
                          "detail": (got.get("sensor_result")
                                     or {}).get("detail")})[:300])
check("isolation is CAPABILITY_UNAVAILABLE, not success",
      got["state"] == "CAPABILITY_UNAVAILABLE", got["state"])
check("it was never marked VERIFIED", got["verified_at"] is None)

print("\n=== 6 · NEGATIVE · a revoked endpoint cannot be commanded")
call(f"/api/edr/enrollment/endpoints/{endpoint}/revoke",
     {"reason": "p0f5 proof"}, bearer=admin)
try:
    call("/api/edr/response/actions",
         {"endpoint_id": endpoint, "action": "KILL_PROCESS",
          "target": {"pid": 2}, "reason": "negative"}, bearer=admin)
    check("a revoked endpoint is refused", False)
except urllib.error.HTTPError as e:
    d = json.loads(e.read())
    check("a revoked endpoint is refused",
          d["detail"]["error"] in ("ENDPOINT_REVOKED",
                                   "TARGET_IDENTITY_UNPROVEN"),
          d["detail"]["error"])

print("\n" + "=" * 60)
print(f"endpoint under proof: {endpoint}")
print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
      else f"{len(FAILURES)} FAILED: {FAILURES}")
sys.exit(1 if FAILURES else 0)
