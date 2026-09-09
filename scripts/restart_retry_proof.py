"""REAL restart/retry proof — not a simulated crash.

Sends one telemetry delivery, kills and restarts the backend process via
supervisor, then replays the byte-identical envelope over HTTP and proves that
no second raw / canonical / detection / incident chain exists.

Run:  python /app/scripts/restart_retry_proof.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

import requests
from pymongo import MongoClient

sys.path.insert(0, "/app/backend")

API = os.environ["REACT_APP_BACKEND_URL"].rstrip("/") + "/api"
TENANT = "p0f-restart-retry-proof"
_db = MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]

CEF_LINE = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)
SEI = f"restart-{uuid.uuid4().hex[:8]}"
R: dict = {}


def jwt():
    r = requests.post(f"{API}/auth/login", json={
        "email": os.environ["ADMIN_EMAIL"],
        "password": os.environ["ADMIN_PASSWORD"]}, timeout=60)
    r.raise_for_status()
    return r.json()["access_token"]


def counts():
    return {
        "raw": _db["xdr_canonical_events"].count_documents(
            {"tenant_id": TENANT, "source_event_id": SEI}),
        "canonical": _db["xdr_canonical_evidence"].count_documents(
            {"tenant_id": TENANT}),
        "incidents": _db["workspace_cases"].count_documents(
            {"tenant_id": TENANT, "doc_type": "xdr_incident"}),
    }


ADM = {"Authorization": f"Bearer {jwt()}", "X-Tenant-Id": TENANT}
cr = requests.post(f"{API}/xdr/collectors", headers=ADM, json={
    "name": f"restart-proof-{uuid.uuid4().hex[:6]}", "protocol": "webhook",
    "description": "RESTART/RETRY PROOF · throwaway"}, timeout=60)
cr.raise_for_status()
COLLECTOR = cr.json()["data"]["id"]

KEY = requests.post(f"{API}/xdr/api-keys", headers=ADM, json={
    "name": f"restart-proof-{uuid.uuid4().hex[:6]}",
    "scopes": ["collectors.enroll"]}, timeout=60).json()["data"]["plaintext"]

ENVELOPE = {"envelopes": [{
    "tenant_id": TENANT, "collector_id": COLLECTOR,
    "collection_method": "webhook", "source": "fw",
    "connector_id": "webhook-restart-proof", "event_type": "alert",
    "source_event_id": SEI,
    "raw": {"line": CEF_LINE, "payload_format": "cef"}}]}
HDRS = {"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT}


def deliver(label):
    r = requests.post(f"{API}/xdr/ingest/telemetry", headers=HDRS,
                      json=ENVELOPE, timeout=180)
    body = r.json() if r.status_code == 200 else {"error": r.text[:200]}
    out = (body.get("reasoning") or [{}])[0]
    print(f"  {label}: http={r.status_code} duplicates={body.get('duplicates')} "
          f"resumed={body.get('resumed')} status={out.get('status')} "
          f"incident={out.get('incident_id')}")
    return r.status_code, body, out


print("── delivery 1 (before restart) ──")
c1, b1, o1 = deliver("first")
after_first = counts()
print("  counts:", after_first)
R["first"] = {"http": c1, "status": o1.get("status"),
              "incident_id": o1.get("incident_id"),
              "trace_id": o1.get("trace_id"), "counts": after_first}
assert c1 == 200 and o1["status"] == "REASONED", b1
assert after_first["raw"] == 1

print("── restarting the backend process ──")
subprocess.run(["sudo", "supervisorctl", "restart", "backend"], check=True,
               capture_output=True)
for _ in range(60):
    time.sleep(2)
    try:
        if requests.get(f"{API}/health", timeout=10).status_code < 500:
            break
    except requests.RequestException:
        continue
time.sleep(3)
print("  backend restarted")

print("── delivery 2 (identical envelope, AFTER restart) ──")
c2, b2, o2 = deliver("retry-after-restart")
after_retry = counts()
print("  counts:", after_retry)

claim = _db["xdr_ingest_dedupe"].find_one({"source_event_id": SEI})
ok = (c2 == 200
      and b2.get("duplicates") == 1
      and o2.get("status") == "DUPLICATE"
      and o2.get("incident_id") == o1.get("incident_id")
      and o2.get("duplicate_of_trace_id") == o1.get("trace_id")
      and after_retry == after_first
      and b2.get("reasoned") == 0
      and b2.get("incidents_promoted") == [])
R["retry_after_restart"] = {
    "http": c2, "duplicates": b2.get("duplicates"),
    "status": o2.get("status"), "incident_id": o2.get("incident_id"),
    "points_at_original": o2.get("incident_id") == o1.get("incident_id"),
    "duplicate_of_trace_id": o2.get("duplicate_of_trace_id"),
    "delivery_count": o2.get("delivery_count"),
    "counts": after_retry, "counts_unchanged": after_retry == after_first,
    "claim_status": (claim or {}).get("status"),
    "claim_attempt": (claim or {}).get("attempt"),
    "claim_delivery_count": (claim or {}).get("delivery_count"),
}
R["verdict"] = "PASS" if ok else "FAIL"

# cleanup
requests.post(f"{API}/xdr/collectors/{COLLECTOR}/disable", headers=ADM,
              timeout=60)
for k in requests.get(f"{API}/xdr/api-keys", headers=ADM,
                      timeout=60).json()["data"]["api_keys"]:
    requests.post(f"{API}/xdr/api-keys/{k['id']}/revoke", headers=ADM,
                  timeout=60)
R["cleanup"] = {"collector_disabled": COLLECTOR, "keys_revoked": True}

print("\n" + "=" * 60)
print("RESTART/RETRY VERDICT:", R["verdict"])
print(json.dumps(R, indent=1, default=str))
with open("/app/test_reports/restart_retry_proof.json", "w") as fh:
    json.dump(R, fh, indent=1, default=str)
