#!/usr/bin/env python3
"""P0-F.3 acceptance proof · the AUTHORED rule store bound to the ONE
runtime evaluator.

Two things are proven:

1. Every one of the authored rules in `xdr_detection_rules` is classified
   store → binding → evaluator, so "which authored rules can actually
   fire?" is answerable, and no rule is silently ignored.
2. A rule authored THROUGH THE STORE fires on REAL endpoint evidence via
   the existing evaluator — no second engine. The rule is real content
   and the behaviour is real; only the authoring step is scripted, which
   is the binding path under test. The rule is withdrawn afterwards.

    python3 /app/scripts/p0_f3_binding_proof.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, "/app/backend")
os.chdir("/app/backend")
from dotenv import load_dotenv                                  # noqa: E402
from motor.motor_asyncio import AsyncIOMotorClient              # noqa: E402
import asyncio                                                  # noqa: E402

load_dotenv("/app/backend/.env")
SENSOR = "/app/agents/nivxforge-linux/nivxforge_sensor.py"
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
ENDPOINT = "ep_2d57cbe6f80152062109"
STATE = "/tmp/nivx-p0f3"
PROOF_RULE_ID = "det_p0f3_proof_linux"
FAILURES: list[str] = []

PROOF_RULE = {
    "id": PROOF_RULE_ID, "upstream_id": "p0f3_proof_linux_devtcp",
    "title": "Authored proof rule · shell opening /dev/tcp",
    "description": "Store-authored Linux rule proving the runtime binding.",
    "source": "P0-F.3 binding proof", "license": "internal",
    "license_id": "internal", "license_policy_state": "PERMITTED",
    "license_policy_reason": "first-party content",
    "level": "high", "status": "stable", "state": "VALIDATED",
    "enabled": "True", "rule_type": "process_creation",
    "attack_techniques": "['T1071']",
    "logsource": {"category": "process_creation", "product": "linux"},
    "detection": {"selection": {"CommandLine|contains": "/dev/tcp/"},
                  "condition": "selection"},
}


def req(path, bearer=None):
    r = urllib.request.Request(
        f"{API}{path}",
        headers={"User-Agent": "NivXForge-P0F3-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})})
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


def post(path, body, bearer=None):
    r = urllib.request.Request(
        f"{API}{path}", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0F3-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})})
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


def store(op):
    async def run():
        db = AsyncIOMotorClient(os.environ["MONGO_URL"])[
            os.environ["DB_NAME"]]
        return await op(db["xdr_detection_rules"])
    return asyncio.run(run())


pw = next(l.split("`")[1] for l in
          Path("/app/memory/test_credentials.md").read_text().splitlines()
          if l.startswith("- **Password**"))
admin = post("/api/auth/login",
             {"email": "admin@nivxray.com", "password": pw})["access_token"]

print("\n=== 1 · every authored rule is classified, none ignored")
rep = req("/api/edr/wave0/detection-rule-bindings?refresh=true", bearer=admin)
print(f"   authored={rep['authored_rules']}  "
      f"{json.dumps(rep['by_binding_state'])}")
check("classification covers every authored rule",
      sum(rep["by_binding_state"].values()) == rep["authored_rules"])
check("the store is bound to the ONE existing runtime evaluator",
      rep["runtime_evaluator"]
      == "nivxray::detection_content::nivxray_native_sigma")
check("every rule states WHY it can or cannot fire",
      all(r["reason"] for r in rep["rules"]))
check("only BOUND rules claim a runtime evaluator",
      all((r["runtime_evaluator"] is not None)
          == (r["binding_state"] == "BOUND") for r in rep["rules"]))
baseline = rep["authored_rules"]

print("\n=== 2 · author a Linux rule THROUGH THE STORE")
store(lambda c: c.replace_one({"id": PROOF_RULE_ID}, PROOF_RULE,
                              upsert=True))
rep = req("/api/edr/wave0/detection-rule-bindings?refresh=true", bearer=admin)
mine = [r for r in rep["rules"] if r["rule_id"] == PROOF_RULE_ID]
print("   " + json.dumps(mine[0] if mine else {})[:320])
check("the authored rule BOUND to the runtime evaluator",
      bool(mine) and mine[0]["binding_state"] == "BOUND")
check("the store rule count grew by exactly one",
      rep["authored_rules"] == baseline + 1)

print("\n=== 3 · real endpoint behaviour, judged by the AUTHORED rule")
tok = post("/api/edr/enrollment/tokens", {"label": "p0f3-proof"},
           bearer=admin)["enrollment_token"]
env = {**os.environ, "NIVXFORGE_SENSOR_STATE": STATE}
subprocess.run([sys.executable, SENSOR, "enrol", "--api", API, "--tenant",
                "default", "--token", tok], capture_output=True, env=env)
ENDPOINT = json.loads(Path(f"{STATE}/identity.json").read_text())[
    "endpoint_id"]
print(f"   sensor enrolled as {ENDPOINT}")
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, text=True, env=env)   # baseline
probe = subprocess.Popen(
    ["/bin/bash", "-c",
     "while :; do exec 3<>/dev/tcp/127.0.0.1/9; sleep 4; done"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"   real pid {probe.pid} (connection refused — the ATTEMPT is real)")
time.sleep(3)
run = subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
                     capture_output=True, text=True, env=env)
print("   " + (run.stdout + run.stderr).strip()[-200:])
det = req(f"/api/edr/endpoint-detections?endpoint_id={ENDPOINT}&hours=1",
          bearer=admin)
hits = [d for d in (det.get("detections") or [])
        if PROOF_RULE_ID in (d.get("rule_ids") or [])]
print(f"   detections carrying the authored rule: {len(hits)}")
if hits:
    print("   " + json.dumps(hits[0])[:340])
check("the AUTHORED store rule fired on REAL endpoint evidence", bool(hits))
check("the authored detection carries full provenance",
      bool(hits) and all(h.get("raw_id") and h.get("canonical_event_id")
                         for h in hits))
check("it was evaluated by the SAME engine as the in-code content",
      bool(hits) and all(
          h.get("detection_engine")
          == "nivxray::detection_content::nivxray_native_sigma"
          for h in hits))

print("\n=== 4 · withdraw the proof rule; the store returns to its content")
probe.terminate()
store(lambda c: c.delete_one({"id": PROOF_RULE_ID}))
rep = req("/api/edr/wave0/detection-rule-bindings?refresh=true", bearer=admin)
check("the proof rule is gone", rep["authored_rules"] == baseline,
      f"authored={rep['authored_rules']}")
check("no authored rule claims to be runtime-active without being BOUND",
      all(r["binding_state"] == "BOUND" or r["runtime_evaluator"] is None
          for r in rep["rules"]))

print("\n" + "=" * 60)
print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
      else f"{len(FAILURES)} FAILED: {FAILURES}")
sys.exit(1 if FAILURES else 0)
