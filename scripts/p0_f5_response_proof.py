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


def proc_state(pid):
    """The kernel's own state letter. Z = already terminated, awaiting a
    parent reap — /proc still holds the entry."""
    try:
        s = Path(f"/proc/{pid}/stat").read_text()
        return s[s.rindex(")") + 2:].split()[0]
    except OSError:
        return None


def orphan_sleep():
    """A real long-running process that is NOT a child of this script, so
    no parent of ours can hold it as a zombie after it is killed."""
    p = subprocess.Popen(["setsid", "/bin/sleep", "600"],
                         start_new_session=True)
    time.sleep(1)
    ps = subprocess.run(["ps", "-eo", "pid,ppid,args"], capture_output=True,
                        text=True).stdout
    for line in ps.splitlines():
        f = line.split(None, 2)
        if len(f) == 3 and f[2].strip() == "/bin/sleep 600" \
                and int(f[1]) != os.getpid() and int(f[1]) != p.pid:
            p.wait(timeout=5)
            return int(f[0])
    raise SystemExit("could not start an orphan victim process")


def mongo_set(command_id, ticks):
    """Reproduce the PID-REUSE condition faithfully: the command's OBSERVED
    start identity no longer matches the process now at that pid. Only the
    command's observed identity is rewritten; the real process and the real
    /proc are untouched, and the sensor must refuse on its own reading."""
    import pymongo
    from dotenv import dotenv_values
    cfg = dotenv_values("/app/backend/.env")
    cli = pymongo.MongoClient(cfg["MONGO_URL"])
    cli[cfg["DB_NAME"]]["edr_response_commands"].update_one(
        {"command_id": command_id},
        {"$set": {"target.observed_start_ticks": ticks}})
    cli.close()


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
check("the target is bound to a process START IDENTITY, not a bare pid",
      isinstance(cmd["target"].get("observed_start_ticks"), int)
      and cmd["target"].get("identity_basis")
      == "endpoint_id + pid + start_ticks")
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
print("   verification: " + json.dumps(mine["verification"])[:300])
check("the command reached VERIFIED", mine["state"] == "VERIFIED",
      mine["state"])
check("the full state machine was recorded",
      [h["state"] for h in mine["history"]]
      == ["REQUESTED", "DISPATCHED", "EXECUTED", "VERIFIED"])
check("verification is INDEPENDENT post-action evidence",
      mine["verification"]["method"] == "post_action_proc_read"
      and mine["verification"]["probe"]["process_present"] is False)
check("verification proved process IDENTITY, not pid occupancy",
      mine["verification"]["probe"].get("identity_basis") == "start_ticks"
      and mine["verification"]["probe"].get("observed_start_ticks")
      == mine["target"]["observed_start_ticks"])
# /proc/<pid> is NOT the right question for a process we are the parent of:
# after SIGKILL a child stays as an unreaped ZOMBIE, so /proc persists
# until we wait() for it. State Z means ALREADY TERMINATED.
zstate = proc_state(victim.pid)
print(f"   /proc/{victim.pid} before reap: state={zstate}")
check("before reaping, the target is absent or already-dead (Z)",
      zstate in (None, "Z"), f"state={zstate}")
status = victim.wait(timeout=10)
check("the OS reports termination BY SIGNAL 9, not a self-exit",
      status == -9, f"waitstatus={status}")
check("after reaping, the REAL process is actually gone",
      not Path(f"/proc/{victim.pid}").exists())

print("\n=== 3b · the unambiguous case · a victim that is NOT our child")
# Started with setsid and reparented to init, so nothing we control can
# hold it as a zombie: /proc/<pid> disappearing is unambiguous proof.
orphan = orphan_sleep()
print(f"   orphan pid {orphan} · ppid "
      f"{Path(f'/proc/{orphan}/stat').read_text().split(') ')[1].split()[1]}")
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)
c2 = call("/api/edr/response/actions",
          {"endpoint_id": endpoint, "action": "KILL_PROCESS",
           "target": {"pid": orphan},
           "reason": "P0-F.5 non-child kill proof"}, bearer=admin)
check("the orphan target bound to a real start identity",
      isinstance(c2["target"].get("observed_start_ticks"), int),
      str(c2["target"].get("observed_start_ticks")))
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)
rows = call(f"/api/edr/response/actions?endpoint_id={endpoint}",
            bearer=admin)["commands"]
got2 = [r for r in rows if r["command_id"] == c2["command_id"]][0]
print("   states: " + " → ".join(h["state"] for h in got2["history"]))
print("   verification: " + json.dumps(got2["verification"])[:300])
check("the non-child kill reached VERIFIED", got2["state"] == "VERIFIED",
      got2["state"])
check("/proc/<pid> is genuinely GONE, with no parent able to hold it",
      not Path(f"/proc/{orphan}").exists())
check("the platform's probe agrees the process is absent",
      got2["verification"]["probe"]["process_present"] is False
      and got2["verification"]["probe"]["proc_reason"] == "NO_PROC_ENTRY",
      got2["verification"]["probe"].get("proc_reason"))

print("\n=== 3c · NEGATIVE · PID REUSE · the wrong process is NOT killed")
# The condition a pid-reuse race creates is: the command's observed start
# identity no longer matches the process now sitting at that pid. It is
# reproduced faithfully by rewriting ONLY the command's observed start
# identity, then requiring the sensor to refuse.
bystander = subprocess.Popen(["/bin/sleep", "600"])
time.sleep(2)
subprocess.run([sys.executable, SENSOR, "run", "--api", API, "--once"],
               capture_output=True, env=env)
c3 = call("/api/edr/response/actions",
          {"endpoint_id": endpoint, "action": "KILL_PROCESS",
           "target": {"pid": bystander.pid},
           "reason": "P0-F.5 pid-reuse refusal proof"}, bearer=admin)
real_ticks = c3["target"]["observed_start_ticks"]
mongo_set(c3["command_id"], real_ticks + 5000)
print(f"   pid {bystander.pid} real start {real_ticks} ticks; the command "
      f"now claims {real_ticks + 5000} — a DIFFERENT process")
run3 = subprocess.run([sys.executable, SENSOR, "run", "--api", API,
                       "--once"], capture_output=True, text=True, env=env)
print("   " + "\n   ".join(
    l for l in (run3.stdout + run3.stderr).strip().splitlines()
    if "command" in l)[:400])
rows = call(f"/api/edr/response/actions?endpoint_id={endpoint}",
            bearer=admin)["commands"]
got3 = [r for r in rows if r["command_id"] == c3["command_id"]][0]
check("a start-identity mismatch is REFUSED, not killed",
      got3["state"] == "FAILED", got3["state"])
check("the refusal names PID reuse explicitly",
      "TARGET_IDENTITY_MISMATCH_PID_REUSE"
      in (got3["sensor_result"] or {}).get("detail", ""))
check("the bystander process is STILL ALIVE and was never signalled",
      Path(f"/proc/{bystander.pid}").exists()
      and bystander.poll() is None)
check("a refused kill is never marked VERIFIED",
      got3["verified_at"] is None and got3["verification"] is None)
bystander.kill()
bystander.wait(timeout=5)

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
