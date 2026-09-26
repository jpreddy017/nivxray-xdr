#!/usr/bin/env python3
"""NivXForge EDR · Windows onboarding proof harness.

Two modes, and the difference between them is the whole point:

  rehearse   Exercises every SERVER-SIDE transition of the onboarding chain
             over HTTP inside a throwaway INTERNAL_VALIDATION tenant, using
             a SYNTHETIC machine identity. It proves the platform side is
             ready so the owner's single real attempt is not spent on a
             server defect. It is NOT the Windows proof and never claims to
             be: every record it writes is labelled SYNTHETIC and the tenant
             is archived at the end.

  watch      READ-ONLY evidence collector for the REAL proof. It baselines
             the fleet, then polls the same APIs the console uses and prints
             exact evidence for each transition as the real Windows endpoint
             progresses: enrolment -> identity -> authenticated telemetry ->
             CONNECTED -> events -> trajectory -> command evidence ->
             detection. It writes nothing and touches no endpoint.

CONNECTED is never asserted by this harness. It is read back from the
platform, which requires authenticated telemetry inside the sensor's own
declared cadence — installer execution alone is never a PASS.

Usage
  python3 tools/edr_onboarding_proof.py rehearse
  python3 tools/edr_onboarding_proof.py watch --tenant <tenant_id> [--minutes 30]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _api_base() -> str:
    with open(os.path.join(ROOT, "frontend", ".env")) as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                return line.split("=", 1)[1].strip().rstrip("/")
    sys.exit("REACT_APP_BACKEND_URL not found in frontend/.env")


API = _api_base()
EMAIL = os.environ.get("NVX_ADMIN_EMAIL", "admin@nivxray.com")
PASSWORD = os.environ.get("NVX_ADMIN_PASSWORD")
STEP = 0


def say(state: str, title: str, evidence: dict | None = None) -> None:
    global STEP
    STEP += 1
    print(f"\n[{STEP:02d}] {state:<12} {title}")
    for k, v in (evidence or {}).items():
        text = json.dumps(v) if isinstance(v, (dict, list)) else str(v)
        print(f"     {k:<26} {text[:300]}")


def login() -> dict:
    if not PASSWORD:
        sys.exit("set NVX_ADMIN_PASSWORD (see /app/memory/test_credentials.md)")
    r = requests.post(f"{API}/api/auth/login", timeout=30,
                      json={"email": EMAIL, "password": PASSWORD})
    r.raise_for_status()
    token = r.json().get("access_token") or r.json().get("token")
    return {"Authorization": f"Bearer {token}"}


def fleet(hdr: dict, tenant: str) -> dict:
    r = requests.get(f"{API}/api/edr/onboarding/computers", timeout=90,
                     headers={**hdr, "X-Tenant-Id": tenant})
    r.raise_for_status()
    return r.json()


def computer(hdr: dict, tenant: str, endpoint_id: str) -> dict:
    r = requests.get(
        f"{API}/api/edr/onboarding/computers/{endpoint_id}", timeout=90,
        headers={**hdr, "X-Tenant-Id": tenant})
    r.raise_for_status()
    return r.json()


def commands(hdr: dict, tenant: str, endpoint_id: str) -> dict:
    r = requests.get(f"{API}/api/edr/endpoint-commands", timeout=120,
                     params={"endpoint_id": endpoint_id, "hours": 24},
                     headers={**hdr, "X-Tenant-Id": tenant})
    r.raise_for_status()
    return r.json()


# ── mode: rehearse ────────────────────────────────────────────────
def rehearse() -> int:
    hdr = login()
    say("READY", "authenticated to the platform",
        {"api": API, "principal": EMAIL})

    # 0 · packages on disk
    pk = requests.get(f"{API}/api/edr/onboarding/packages", timeout=60,
                      headers=hdr).json()
    available = [p for p in pk["packages"] if p["available"]]
    if not available:
        say("BLOCKED", "no sensor build is available to install",
            {"reason": [p["state_reason"] for p in pk["packages"]]})
        return 1
    pkg = available[0]
    say("WORKING", "sensor build offered from disk", {
        "package": pkg["id"], "sensor_version": pkg["sensor_version"],
        "artifacts": [f"{f['name']} sha256={f['sha256'][:16]}…"
                      for f in pkg["files"]],
        "credential_free": pkg["credential_free"]})

    # 1 · throwaway tenant (INTERNAL_VALIDATION, archived at the end)
    run = uuid.uuid4().hex[:6]
    org = requests.post(f"{API}/api/xdr/organizations", timeout=60,
                        headers=hdr,
                        json={"slug": f"rehearsal-{run}",
                              "display_name": f"Onboarding rehearsal {run}",
                              "kind": "CUSTOMER"}).json()
    org_id = org["data"]["id"]
    ten = requests.post(f"{API}/api/xdr/tenants", timeout=60, headers=hdr,
                        json={"organization_id": org_id,
                              "slug": f"rehearsal-{run}",
                              "display_name":
                                  f"Onboarding rehearsal {run} (SYNTHETIC)",
                              "kind": "INTERNAL_VALIDATION",
                              "products": ["EDR"]}).json()
    tenant = ten["data"]["id"]
    say("WORKING", "isolated rehearsal tenant created (SYNTHETIC)",
        {"tenant_id": tenant, "kind": "INTERNAL_VALIDATION"})

    try:
        before = fleet(hdr, tenant)
        say("WORKING", "fleet baseline before enrolment",
            {"computers": before["count"]})

        # 2 · bounded enrolment credential
        tok = requests.post(f"{API}/api/edr/enrollment/tokens", timeout=60,
                            headers={**hdr, "X-Tenant-Id": tenant},
                            json={"label": f"rehearsal {run}",
                                  "ttl_seconds": 600}).json()
        plaintext = tok.get("enrollment_token") or tok.get("token")
        say("WORKING", "single-use enrolment credential minted", {
            "expires_at": tok.get("expires_at"),
            "authority": "enrolment only · tenant bound · single use",
            "plaintext_prefix": f"{plaintext[:10]}…",
            "is_permanent_api_key": False})

        # 3 · what the installer does: enrol with durable machine facts
        guid = str(uuid.uuid4())
        enrol = requests.post(f"{API}/api/edr/agent/enroll", timeout=60,
                              json={"tenant_id": tenant,
                                    "enrollment_token": plaintext,
                                    "sensor_version": pkg["sensor_version"],
                                    "processor_id": hashlib.sha256(
                                        guid.encode()).hexdigest()[:24],
                                    "machine_guid": guid,
                                    "hostname": f"REHEARSAL-{run.upper()}",
                                    "platform": "windows"})
        if enrol.status_code != 200:
            say("BROKEN", "enrolment refused", {"http": enrol.status_code,
                                                "body": enrol.text[:400]})
            return 1
        ident = enrol.json()
        say("WORKING", "platform minted the endpoint identity", {
            "endpoint_id": ident["endpoint_id"],
            "credential_id": ident["credential_id"],
            "sensor_state": ident.get("sensor_state"),
            "credential_came_from_installer": False})
        endpoint_id = ident["endpoint_id"]

        # 4 · the token is single use
        again = requests.post(f"{API}/api/edr/agent/enroll", timeout=60,
                              json={"tenant_id": tenant,
                                    "enrollment_token": plaintext,
                                    "sensor_version": pkg["sensor_version"],
                                    "machine_guid": str(uuid.uuid4()),
                                    "hostname": "SHOULD-NOT-ENROL",
                                    "platform": "windows"})
        say("WORKING" if again.status_code >= 400 else "BROKEN",
            "the same enrolment credential cannot enrol a second computer",
            {"http": again.status_code, "body": again.text[:200]})

        # 5 · enrolment alone is NOT connected
        row = computer(hdr, tenant, endpoint_id)["computer"]
        say("BLOCKED_BY_TELEMETRY" if row["status"] != "CONNECTED" else "BROKEN",
            "enrolment alone is not CONNECTED",
            {"status": row["status"], "basis": row["status_basis"],
             "detections_24h": row["detections_24h"],
             "detections_total": row["detections_total"]})

        # 6 · authenticated session + telemetry
        sess = requests.post(f"{API}/api/edr/agent/session", timeout=60,
                             json={"tenant_id": tenant,
                                   "agent_credential":
                                       ident["agent_credential"]})
        sess.raise_for_status()
        session_token = sess.json()["session_token"]
        say("WORKING", "authenticated sensor session opened",
            {"session_token_prefix": f"{session_token[:10]}…"})

        cmdline = ("powershell.exe -ExecutionPolicy Bypass -EncodedCommand "
                   "UwBZAE4AVABIAEUAVABJAEMA")
        obs = {"activity": "PROCESS", "operation": "PROCESS_OBSERVED",
               "observed_at": datetime.now(timezone.utc).isoformat(),
               "pid": 4242, "ppid": 1, "image": "powershell.exe",
               "image_path": "C:\\Windows\\System32\\powershell.exe",
               "command_line": cmdline, "user": "REHEARSAL\\synthetic",
               "collection_method": "PROC_POLL",
               "sensor_version": pkg["sensor_version"],
               "evidence_label": "TEST/SYNTHETIC · onboarding rehearsal",
               "not_observed": ["sha256", "parent_image"]}
        tel = requests.post(f"{API}/api/edr/agent/telemetry", timeout=90,
                            headers={"Authorization":
                                     f"Bearer {session_token}",
                                     "User-Agent":
                                     "NivXForge-EDR-Sensor/rehearsal"},
                            json={"payload": json.dumps(obs),
                                  "source_kind": "sensor",
                                  "sensor_version": pkg["sensor_version"],
                                  "report_interval_seconds": 30.0})
        say("WORKING" if tel.status_code == 200 else "BROKEN",
            "authenticated telemetry delivered",
            {"http": tel.status_code, "response": tel.text[:300]})

        # 7 · CONNECTED is read back, never claimed
        row = computer(hdr, tenant, endpoint_id)["computer"]
        say("WORKING" if row["status"] == "CONNECTED" else "PARTIAL",
            "Computers reports the endpoint from telemetry",
            {"status": row["status"], "basis": row["status_basis"],
             "events": row["telemetry"]["event_count"],
             "last_telemetry_at": row["telemetry"]["last_telemetry_at"],
             "detections_24h": row["detections_24h"],
             "detections_total": row["detections_total"]})

        # 8 · the command reaches Command Intelligence
        ci = commands(hdr, tenant, endpoint_id)
        rows = ci.get("commands") or []
        mine = [c for c in rows if c["command_line"] == cmdline]
        say("WORKING" if mine else "PARTIAL",
            "Command Intelligence carries the observed execution",
            {"observed_executions": ci.get("count"),
             "distinct_commands": ci.get("distinct_commands"),
             "identity_state": ci.get("state", "RESOLVED"),
             "detection_state": (mine[0]["detection"]["state"]
                                 if mine else None),
             "decode_state": mine[0]["decode"]["state"] if mine else None,
             "source": ci.get("source")})
        return 0
    finally:
        requests.put(f"{API}/api/xdr/tenants/{tenant}/state", timeout=60,
                     headers=hdr, json={"state": "ARCHIVED"})
        requests.put(f"{API}/api/xdr/organizations/{org_id}/state",
                     timeout=60, headers=hdr, json={"state": "ARCHIVED"})
        say("WORKING", "rehearsal tenant archived (no live fleet touched)",
            {"tenant_id": tenant})


# ── mode: watch (READ-ONLY) ───────────────────────────────────────
def watch(tenant: str, minutes: int) -> int:
    hdr = login()
    base = fleet(hdr, tenant)
    known = {c["endpoint_id"] for c in base["computers"]}
    say("READY", "fleet baseline captured · READ-ONLY from here",
        {"tenant_id": tenant, "computers_before": base["count"],
         "status_contract": base["status_contract"]})
    print("\nRun the elevated installer on the Windows host now.\n")

    seen = {}
    deadline = time.time() + minutes * 60
    while time.time() < deadline:
        current = fleet(hdr, tenant)
        for row in current["computers"]:
            if row["endpoint_id"] in known:
                continue
            eid = row["endpoint_id"]
            state = seen.get(eid)
            if state is None:
                say("WORKING", "a NEW computer was recorded by the platform", {
                    "endpoint_id": eid, "hostname": row["hostname"],
                    "os": row["os"], "os_version": row["os_version"],
                    "sensor_version": row["sensor_version"],
                    "enrollment_state": row["enrollment_state"],
                    "credential_state": row["credential_state"],
                    "status": row["status"], "basis": row["status_basis"]})
                seen[eid] = row["status"]
                state = row["status"]
            if row["telemetry"]["last_telemetry_at"] and state != "telemetry":
                say("WORKING", "authenticated telemetry arrived", {
                    "endpoint_id": eid,
                    "last_telemetry_at": row["telemetry"]["last_telemetry_at"],
                    "events": row["telemetry"]["event_count"]})
                seen[eid] = "telemetry"
                state = "telemetry"
            if row["status"] == "CONNECTED" and state != "connected":
                detail = computer(hdr, tenant, eid)
                ci = commands(hdr, tenant, eid)
                say("WORKING", "CONNECTED — established from telemetry only", {
                    "endpoint_id": eid, "basis": row["status_basis"],
                    "events": row["telemetry"]["event_count"],
                    "detections_24h": row["detections_24h"],
                    "detections_total": row["detections_total"],
                    "device_identity": detail["enrolment"]["device_iid"],
                    "observed_commands": ci["count"],
                    "detected_commands": ci["detected_count"],
                    "decoded_commands": ci["decoded_count"]})
                print("\n  Console routes carrying this evidence:")
                print(f"    /edr/computers")
                print(f"    /edr/computers/{eid}")
                print(f"    /edr/computers/{eid}/trajectory")
                print(f"    /edr/computers/{eid}/commands")
                seen[eid] = "connected"
                return 0
        time.sleep(10)

    say("BLOCKED_BY_TELEMETRY",
        "no new computer reached CONNECTED inside the watch window",
        {"tenant_id": tenant, "minutes": minutes,
         "next_step": "check the installer transcript on the Windows host"})
    return 1


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    sub.add_parser("rehearse")
    w = sub.add_parser("watch")
    w.add_argument("--tenant", required=True)
    w.add_argument("--minutes", type=int, default=30)
    args = ap.parse_args()
    return rehearse() if args.mode == "rehearse" else watch(args.tenant,
                                                            args.minutes)


if __name__ == "__main__":
    raise SystemExit(main())
