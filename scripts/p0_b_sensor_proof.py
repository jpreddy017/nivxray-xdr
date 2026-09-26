#!/usr/bin/env python3
"""P0-B / P0-D acceptance proof — real Linux activity → real sensor →
authenticated telemetry → immutable raw event → canonical bridge →
canonical evidence → Device Trajectory.

Repeatable. Nothing is seeded and nothing is simulated: the marker process
is genuinely executed on this host and the marker file is genuinely
written, then we assert the platform reports THOSE EXACT facts back.

    python3 /app/scripts/p0_b_sensor_proof.py
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

SENSOR = "/app/agents/nivxforge-linux/nivxforge_sensor.py"
STATE = Path(f"/tmp/nivx-proof-{int(time.time())}")
WATCH = STATE / "watched"
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
TENANT = "default"
MARKER = f"nivxforge-p0b-marker-{os.getpid()}"


def req(path: str, body=None, bearer=None, method=None):
    r = urllib.request.Request(
        f"{API}{path}",
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0B-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method=method or ("POST" if body is not None else "GET"))
    with urllib.request.urlopen(r, timeout=60) as resp:
        return json.loads(resp.read())


def step(n, msg):
    print(f"\n=== {n} · {msg}")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


FAILURES: list[str] = []

# 1 · admin auth + one-time enrolment token
step(1, "admin mints a one-time enrolment token")
creds = Path("/app/memory/test_credentials.md").read_text()
pw = next(l.split("`")[1] for l in creds.splitlines()
          if l.startswith("- **Password**"))
admin = req("/api/auth/login",
            {"email": "admin@nivxray.com", "password": pw})["access_token"]
tok = req("/api/edr/enrollment/tokens", {"label": "p0b-proof"},
          bearer=admin)["enrollment_token"]
check("one-time token minted", tok.startswith("enr_"))

# 2 · real sensor enrols from this real host
step(2, "the real sensor enrols with the one-time token")
env = {**os.environ, "NIVXFORGE_SENSOR_STATE": str(STATE)}
out = subprocess.run([sys.executable, SENSOR, "enrol", "--api", API,
                      "--tenant", TENANT, "--token", tok],
                     capture_output=True, text=True, env=env)
print("  " + out.stdout.strip().replace("\n", "\n  ") + out.stderr.strip())
ident = json.loads((STATE / "identity.json").read_text())
endpoint_id = ident["endpoint_id"]
check("endpoint_id minted BY THE PLATFORM", endpoint_id.startswith("ep_"),
      endpoint_id)
check("credential stored 0600",
      oct((STATE / "identity.json").stat().st_mode)[-3:] == "600")
check("token is single-use — a second enrol is refused",
      subprocess.run([sys.executable, SENSOR, "enrol", "--api", API,
                      "--tenant", TENANT, "--token", tok],
                     capture_output=True, text=True,
                     env={**env, "NIVXFORGE_SENSOR_STATE": str(STATE) + "-2"}
                     ).returncode != 0)

# 3 · generate KNOWN real activity on this host
step(3, "generate real, known activity on this host")
WATCH.mkdir(parents=True, exist_ok=True)
proc = subprocess.Popen([sys.executable, "-c",
                         "import time,sys; time.sleep(120)", MARKER])
marker_file = WATCH / f"{MARKER}.txt"
time.sleep(1)
print(f"  real process pid={proc.pid} argv marker={MARKER}")
print("  (the marker FILE is written after the first pass, so it is a real "
      "CREATE and not part of the sensor's baseline)")

# 4 · one sensor pass — collect + authenticated transmit
step(4, "sensor collects and transmits (authenticated)")
run = subprocess.run([sys.executable, SENSOR, "run", "--api", API,
                      "--once", "--watch", str(WATCH)],
                     capture_output=True, text=True, env=env)
print("  " + (run.stdout + run.stderr).strip()[-600:].replace("\n", "\n  "))
sent = int(run.stdout.split("sent=")[1].split()[0]) if "sent=" in run.stdout \
    else 0
check("telemetry accepted by the platform", sent > 0, f"sent={sent}")

# 5 · the immutable raw store holds THIS endpoint's evidence
step(5, "immutable edr_raw_events holds this endpoint's evidence")
stats = req("/api/edr/wave0/raw-events/stats?tenant_id=" + TENANT,
             bearer=admin)
print("  " + json.dumps(stats)[:400])
check("raw events present", (stats.get("total_raw_events") or 0) > 0,
      f"total={stats.get('total_raw_events')}")

# 6 · canonical evidence + Device Trajectory show the REAL facts
step(6, "Device Trajectory renders the real sensor evidence")
traj = req(f"/api/edr/device-trajectory?device={endpoint_id}&hours=24",
           bearer=admin)
events = traj.get("events") or []
blob = json.dumps(traj)
check("the platform-minted endpoint_id is a valid trajectory pivot",
      traj["identity"]["resolved"] and
      traj["identity"]["resolved_via"] == "endpoint_id",
      f"reason={traj.get('reason')}")
check("the REAL marker process appears in canonical evidence",
      MARKER in blob)
check("real observations counted", len(events) > 0, f"n={len(events)}")
ids = [e["id"] for e in events]
check("no duplicated evidence rows in the trajectory",
      len(ids) == len(set(ids)), f"{len(ids)} events / {len(set(ids))} unique")

# 6b · real ancestry survives the canonical projection
step("6b", "real PID/PPID ancestry survives into canonical evidence")
mark = [e for e in events if MARKER in (e.get("command_line") or "")]
check("marker process event present in the trajectory", bool(mark))
if mark:
    m = mark[0]
    print("   " + json.dumps({k: m.get(k) for k in
                              ("process", "command_line", "process_iid",
                               "parent_iid", "parent_name")}))
    check("parent lineage is a real, resolved relationship",
          bool(m.get("parent_iid")) and bool(m.get("parent_name")),
          f"parent={m.get('parent_name')}")
    parent_ev = [e for e in events
                 if e.get("process_iid") == m.get("parent_iid")]
    check("the parent lifeline is itself an observed process "
          "(the tree links)", bool(parent_ev),
          (parent_ev[0].get("process") if parent_ev else "not linked"))

# 6c · a sensor restart must not re-report the same real activity
step("6c", "a real file CREATE is captured; re-observation is not "
     "re-counted")
before = len(events)
marker_file.write_text("real file content written by the proof driver\n")
time.sleep(1)
run2 = subprocess.run([sys.executable, SENSOR, "run", "--api", API,
                       "--once", "--watch", str(WATCH)],
                      capture_output=True, text=True, env=env)
print("  " + (run2.stdout + run2.stderr).strip()[-300:])
traj2 = req(f"/api/edr/device-trajectory?device={endpoint_id}&hours=24",
            bearer=admin)
again = [e for e in (traj2.get("events") or [])
         if MARKER in (e.get("command_line") or "")]
check("the same real process is still held exactly once",
      len(again) == 1, f"held {len(again)}x")
blob2 = json.dumps(traj2)
check("the REAL file CREATE appears in canonical evidence",
      marker_file.name in blob2)
check("no duplicate ids after the second pass",
      len({e["id"] for e in traj2["events"]}) == len(traj2["events"]),
      f"{len(traj2['events'])} events, was {before}")

# 7 · replay / immutability — a byte-identical re-delivery is a duplicate
step(7, "byte-identical re-delivery is a duplicate, not a second event")
session = req("/api/edr/agent/session",
              {"tenant_id": TENANT,
               "agent_credential": ident["agent_credential"]})["session_token"]
payload = json.dumps({"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
                      "observed_at": "2026-06-01T00:00:00+00:00",
                      "start_time": f"2026-06-01T00:00:00+00:00/{MARKER}",
                      "pid": os.getpid(), "ppid": 1,
                      "image": "replay-probe",
                      "image_path": "/bin/replay-probe",
                      "command_line": f"replay-probe {MARKER}",
                      "user": "root", "sha256": None, "not_observed": []},
                     separators=(",", ":"))
a = req("/api/edr/agent/telemetry", {"payload": payload}, bearer=session)
b = req("/api/edr/agent/telemetry", {"payload": payload}, bearer=session)
check("first delivery stored + canonicalised",
      a.get("stored") and a["canonical"].get("canonicalized"))
check("second delivery deduped, NOT re-canonicalised",
      not b.get("stored") and not b["canonical"].get("canonicalized"))

# 8 · tenant isolation + endpoint attribution
step(8, "tenant isolation and endpoint attribution")
try:
    req("/api/edr/agent/session", {"tenant_id": "nivx-live",
                                   "agent_credential":
                                   ident["agent_credential"]})
    check("cross-tenant credential use refused", False)
except urllib.error.HTTPError as e:
    check("cross-tenant credential use refused", e.code in (401, 403),
          f"HTTP {e.code}")
who = req("/api/edr/agent/whoami", bearer=session)
check("evidence attributed to the authenticated endpoint",
      who["identity"]["endpoint_id"] == endpoint_id)

# 9 · a malformed payload is retained and replayable, never dropped
step(9, "unparseable payload → retained + PARSER_FAILED, never dropped")
bad = req("/api/edr/agent/telemetry",
          {"payload": "{not json at all " + MARKER}, bearer=session)
check("raw bytes retained", bool(bad.get("stored")))
check("parse failure reported honestly",
      bad["canonical"].get("parser_state") == "FAILED")
cands = req("/api/edr/wave0/raw-events/replay-candidates?tenant_id=" +
            TENANT + "&parser_state=FAILED", bearer=admin)
check("appears as a replay candidate",
      (cands.get("count") or len(cands.get("candidates") or [])) > 0)

proc.terminate()
shutil.rmtree(STATE, ignore_errors=True)
print("\n" + "=" * 60)
print(f"endpoint_id under proof: {endpoint_id}")
print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
      else f"{len(FAILURES)} FAILED: {FAILURES}")
sys.exit(1 if FAILURES else 0)
