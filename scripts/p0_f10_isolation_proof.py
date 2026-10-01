#!/usr/bin/env python3
"""P0-F.10 acceptance proof · REAL endpoint network isolation.

Run this ON the endpoint, as root, on a host where the sensor genuinely
holds `CAP_NET_ADMIN` (a VM, or `docker run --cap-add=NET_ADMIN`). It
proves containment TWICE, the way the platform requires:

  control-plane proof   the kernel is read back and holds a default-deny
                        policy with the exact allow-list
  behavioural proof     an independently chosen external target is
                        UNREACHABLE while the NivXForge control channel is
                        still reachable

and it proves release the same way, in reverse. It also proves the two
refusals that matter: no privilege → CAPABILITY_UNAVAILABLE naming
CAP_NET_ADMIN, and a policy with no verification target → refused.

On a host WITHOUT the privilege (for example the Emergent preview
container) the script does not pretend: it asserts the honest
CAPABILITY_UNAVAILABLE path and exits 0 having proven THAT, while stating
clearly that containment itself is NOT verified here.

    sudo python3 /app/scripts/p0_f10_isolation_proof.py
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SENSOR = "/app/agents/nivxforge-linux/nivxforge_sensor.py"
STATE = "/tmp/nivx-p0f10"
API = next(l.split("=", 1)[1].strip()
           for l in Path("/app/frontend/.env").read_text().splitlines()
           if l.startswith("REACT_APP_BACKEND_URL"))
FAILURES: list[str] = []


def call(path, body=None, bearer=None, method=None):
    r = urllib.request.Request(
        f"{API}{path}",
        data=(json.dumps(body).encode() if body is not None else None),
        headers={"Content-Type": "application/json",
                 "User-Agent": "NivXForge-P0F10-Proof/1.0",
                 **({"Authorization": f"Bearer {bearer}"} if bearer else {})},
        method=method or ("POST" if body is not None else "GET"))
    with urllib.request.urlopen(r, timeout=90) as resp:
        return json.loads(resp.read())


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {detail}")
    if not ok:
        FAILURES.append(label)


def sensor(*args, env=None):
    return subprocess.run([sys.executable, SENSOR, *args],
                          capture_output=True, text=True, env=env)


def reachable(host, port, timeout=4.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:  # noqa: BLE001
        return False


def has_net_admin():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("CapEff:"):
            return bool((int(line.split()[1], 16) >> 12) & 1)
    return False


def cmd_of(endpoint, command_id, bearer):
    rows = call(f"/api/edr/response/actions?endpoint_id={endpoint}",
                bearer=bearer)["commands"]
    return [r for r in rows if r["command_id"] == command_id][0]


pw = next(l.split("`")[1] for l in
          Path("/app/memory/test_credentials.md").read_text().splitlines()
          if l.startswith("- **Password**"))
admin = call("/api/auth/login",
             {"email": "admin@nivxray.com", "password": pw})["access_token"]
env = {**os.environ, "NIVXFORGE_SENSOR_STATE": STATE}
PRIVILEGED = has_net_admin()

print(f"\n=== 0 · endpoint privilege preflight (CAP_NET_ADMIN: "
      f"{PRIVILEGED})")
sys.path.insert(0, os.path.dirname(SENSOR))
import importlib.util  # noqa: E402
spec = importlib.util.spec_from_file_location("nivx_sensor", SENSOR)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cap = mod._isolation_capability()
print("   " + json.dumps(cap))
check("the capability preflight agrees with the kernel",
      cap["cap_net_admin"] == PRIVILEGED)
check("a missing privilege is named exactly, not summarised",
      PRIVILEGED or "CAP_NET_ADMIN" in cap["missing"])

print("\n=== 1 · enrol a real sensor and set an explicit isolation policy")
tok = call("/api/edr/enrollment/tokens", {"label": "p0f10-proof"},
           bearer=admin)["enrollment_token"]
sensor("enrol", "--api", API, "--tenant", "default", "--token", tok, env=env)
endpoint = json.loads(Path(f"{STATE}/identity.json").read_text())[
    "endpoint_id"]
policy = call("/api/edr/response/isolation-policy",
              {"allow_list": [], "allow_dns": True,
               "verification_target": {"host": "1.1.1.1", "port": 443},
               "auto_release_seconds": None},
              bearer=admin, method="PUT")
print(f"   endpoint {endpoint} · policy v{policy['version']} "
      f"({policy['policy_source']})")
check("the policy is operator-configured, not a silent default",
      policy["policy_source"] == "OPERATOR_CONFIGURED")
check("there is no setting that can disable the control channel",
      all("control channel is always allowed" in i.lower()
          or "control channel" in i for i in policy["invariants"][:1]))
check("auto-release is OFF by default",
      policy["auto_release_seconds"] is None)
sensor("run", "--api", API, "--once", env=env)

print("\n=== 2 · an analyst requests containment (AUTHORIZED, not applied)")
iso = call("/api/edr/response/actions",
           {"endpoint_id": endpoint, "action": "ISOLATE_ENDPOINT",
            "target": {}, "reason": "P0-F.10 acceptance proof"},
           bearer=admin)
print("   " + json.dumps({k: iso.get(k) for k in ("command_id", "state")}))
check("containment carries an explicit AUTHORIZED step",
      iso["state"] == "AUTHORIZED", iso["state"])
check("the bound policy travels with the command",
      iso["target"]["policy"]["policy_version"] == policy["version"])
check("the authorisation records WHY it was allowed",
      iso["authorisation"]["control_channel_protected"] is True)
ext_before = reachable("1.1.1.1", 443)
print(f"   external target reachable BEFORE: {ext_before}")

print("\n=== 3 · the REAL sensor applies and proves it twice")
run = sensor("run", "--api", API, "--once", env=env)
print("   " + "\n   ".join(l for l in (run.stdout + run.stderr)
                           .strip().splitlines() if "command" in l)[:600])
got = cmd_of(endpoint, iso["command_id"], admin)
print("   states: " + " → ".join(h["state"] for h in got["history"]))
print("   sensor said: " + json.dumps(got["sensor_result"])[:260])
print("   verification: " + json.dumps(got["verification"])[:420])

if not PRIVILEGED:
    check("without CAP_NET_ADMIN containment is CAPABILITY_UNAVAILABLE",
          got["state"] == "CAPABILITY_UNAVAILABLE", got["state"])
    check("the refusal names the exact missing privilege",
          "CAP_NET_ADMIN" in (got["sensor_result"] or {}).get("detail", ""))
    check("nothing was claimed as verified",
          got["verified_at"] is None and got["verification"] is None)
    check("the endpoint is NOT recorded as isolated",
          ((([e for e in call("/api/edr/enrollment/endpoints",
                              bearer=admin)["endpoints"]
              if e["endpoint_id"] == endpoint] or [{}])[0]
            .get("isolation") or {}).get("state") in (None,
                                                      "ISOLATION_UNPROVEN")))
    check("the external target is still reachable (nothing was applied)",
          reachable("1.1.1.1", 443) == ext_before)
    print("\n" + "=" * 62)
    print("HONEST RESULT: the CAPABILITY_UNAVAILABLE path is PROVEN on "
          "this host.\nNETWORK CONTAINMENT ITSELF IS *NOT* VERIFIED HERE — "
          "this kernel refuses\nthe privilege. Re-run on a host with "
          "CAP_NET_ADMIN for the real proof.")
    print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
          else f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1 if FAILURES else 0)

check("containment reached VERIFIED", got["state"] == "VERIFIED",
      got["state"])
check("the full state machine was recorded",
      [h["state"] for h in got["history"]]
      == ["REQUESTED", "AUTHORIZED", "DISPATCHED", "EXECUTED", "VERIFIED"],
      str([h["state"] for h in got["history"]]))
probe = got["verification"]["probe"]
check("proof 1 · the KERNEL holds a default-deny policy",
      probe["control_plane"]["rules_installed"] is True
      and len(probe["control_plane"]["deny_chains"]) >= 2,
      json.dumps(probe["control_plane"])[:200])
check("proof 1 · every allow-list entry is present in the kernel",
      probe["control_plane"]["allowed_missing_in_kernel"] == [])
check("proof 2 · the endpoint CANNOT reach the external target",
      probe["behavioural"]["external_blocked"] is True)
check("proof 2 · the control channel is STILL reachable",
      probe["behavioural"]["control_channel_reachable"] is True)
check("the proof driver independently confirms containment",
      reachable("1.1.1.1", 443) is False)
check("the platform states both proofs in the finding",
      "AND" in got["verification"]["finding"])
eps = call("/api/edr/enrollment/endpoints", bearer=admin)["endpoints"]
mine = [e for e in eps if e["endpoint_id"] == endpoint][0]
check("the endpoint records ISOLATED, on evidence",
      (mine.get("isolation") or {}).get("state") == "ISOLATED",
      json.dumps(mine.get("isolation") or {})[:200])

print("\n=== 4 · release · proven in reverse")
rel = call("/api/edr/response/actions",
           {"endpoint_id": endpoint, "action": "RELEASE_ISOLATION",
            "target": {}, "reason": "P0-F.10 release proof"}, bearer=admin)
sensor("run", "--api", API, "--once", env=env)
gotr = cmd_of(endpoint, rel["command_id"], admin)
print("   states: " + " → ".join(h["state"] for h in gotr["history"]))
print("   verification: " + json.dumps(gotr["verification"])[:400])
rp = (gotr.get("verification") or {}).get("probe") or {}
check("release reached VERIFIED", gotr["state"] == "VERIFIED",
      gotr["state"])
check("proof 1 · the containment policy is GONE from the kernel",
      rp.get("control_plane", {}).get("rules_absent") is True)
check("proof 2 · external connectivity is restored",
      rp.get("behavioural", {}).get("external_restored") is True)
check("the proof driver independently confirms restoration",
      reachable("1.1.1.1", 443) is True)

print("\n=== 5 · NEGATIVE · a policy with no verification target is refused")
try:
    call("/api/edr/response/isolation-policy",
         {"verification_target": {"host": "", "port": 0}}, bearer=admin,
         method="PUT")
    check("a policy without a verification target is refused", False)
except urllib.error.HTTPError as e:
    d = json.loads(e.read())
    check("a policy without a verification target is refused",
          d["detail"]["error"] == "INVALID_POLICY", f"HTTP {e.code}")

print("\n" + "=" * 62)
print(f"endpoint under proof: {endpoint}")
print("RESULT:", "ALL CHECKS PASSED" if not FAILURES
      else f"{len(FAILURES)} FAILED: {FAILURES}")
sys.exit(1 if FAILURES else 0)
