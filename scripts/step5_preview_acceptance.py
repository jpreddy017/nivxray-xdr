"""STEP 5 · ONE controlled PREVIEW-ONLY telemetry acceptance test.

Synthetic endpoint only. Never KUSHU, never DESKTOP-A9HGFJJ.
No secret is printed: tokens/credentials are held in memory and reported
only as a length + whether they were obtained.
"""
import json
import os
import sys
import time
import uuid

import requests
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv("/app/frontend/.env")
load_dotenv("/app/backend/.env")

API = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
TENANT = "default"
HOSTNAME = "LAB-STEP5-ACCEPT"

mongo_url = os.environ["MONGO_URL"]
if "localhost" not in mongo_url and "127.0.0.1" not in mongo_url:
    sys.exit("REFUSING: MONGO_URL is not local/preview")
db = MongoClient(mongo_url)[os.environ["DB_NAME"]]

GUARD = ("KUSHU", "DESKTOP-A9HGFJJ")
assert not any(g in HOSTNAME.upper() for g in GUARD)


def step(label, ok, extra=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label} {extra}")
    return ok


print(f"API={API}")
print("=== 1 · admin login (preview) ===")
r = requests.post(f"{API}/api/auth/login", json={
    "email": "admin@nivxray.com",
    "password": os.environ["NIVX_PREVIEW_ADMIN_PW"]}, timeout=30)
step("login", r.status_code == 200, f"http={r.status_code}")
jwt = r.json().get("access_token") or r.json().get("token")
step("jwt obtained", bool(jwt), f"len={len(jwt or '')}")
H = {"Authorization": f"Bearer {jwt}", "X-Tenant-Id": TENANT}

print("=== 2 · mint one-time enrolment token ===")
r = requests.post(f"{API}/api/edr/enrollment/tokens", headers=H,
                  json={"label": "step5 preview acceptance",
                        "ttl_seconds": 600}, timeout=30)
step("mint token", r.status_code == 200, f"http={r.status_code}")
enrol = (r.json().get("enrollment_token")
         or r.json().get("token") or r.json().get("plaintext"))
step("enrolment token obtained", bool(enrol), f"len={len(enrol or '')}")

print("=== 3 · enrol synthetic endpoint ===")
iid = f"step5-{uuid.uuid4()}"
r = requests.post(f"{API}/api/edr/agent/enroll", json={
    "tenant_id": TENANT, "enrollment_token": enrol,
    "hostname": HOSTNAME, "platform": "linux",
    "sensor_version": "step5-acceptance",
    "device_iid": iid}, timeout=30)
step("enroll", r.status_code == 200, f"http={r.status_code}")
body = r.json()
endpoint_id = body.get("endpoint_id")
cred = body.get("agent_credential") or body.get("credential")
step("endpoint_id minted", bool(endpoint_id), f"endpoint_id={endpoint_id}")
step("credential obtained", bool(cred), f"len={len(cred or '')}")

print("=== 4 · open session ===")
r = requests.post(f"{API}/api/edr/agent/session", json={
    "tenant_id": TENANT, "agent_credential": cred}, timeout=30)
step("session", r.status_code == 200, f"http={r.status_code}")
sess = r.json().get("session_token") or r.json().get("token")
step("session token obtained", bool(sess), f"len={len(sess or '')}")
AH = {"Authorization": f"Bearer {sess}", "X-Tenant-Id": TENANT}

print("=== 5 · ONE synthetic telemetry event ===")
marker = uuid.uuid4().hex
payload = json.dumps({
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "EventID": 1, "step5_acceptance_marker": marker,
    "Image": "C:\\\\Windows\\\\System32\\\\notepad.exe",
    "CommandLine": "notepad.exe step5", "ProcessId": 4242,
    "Computer": HOSTNAME})
t_ack0 = time.time()
r = requests.post(f"{API}/api/edr/agent/telemetry", headers=AH, json={
    "payload": payload, "source_kind": "sensor",
    "sensor_version": "step5-acceptance",
    "report_interval_seconds": 60}, timeout=30)
ack_ms = (time.time() - t_ack0) * 1000
step("telemetry ACK", r.status_code == 200, f"http={r.status_code}")
ack = r.json()
print("    ACK body:", json.dumps({k: v for k, v in ack.items()
                                   if k != "note"}, default=str))
raw_id = ack.get("raw_id")
step("raw_id returned", bool(raw_id), f"raw_id={raw_id}")
step("stored=True (new immutable raw event)", ack.get("stored") is True)
step("processing.durable=True", ack.get("processing", {}).get("durable")
     is True)
step("processing.created=True", bool(ack.get("processing", {}).get("created")))
step("canonicalized deferred (async)",
     ack.get("canonical", {}).get("canonicalized") is False,
     str(ack.get("canonical")))
print(f"    ACK latency = {ack_ms:.0f} ms")

print("=== 6 · durable ownership at ACK time (preview Mongo, read-only) ===")
raw = db.edr_raw_events.find_one({"tenant_id": TENANT, "raw_id": raw_id},
                                 {"_id": 0})
step("raw evidence persisted", bool(raw))
step("payload byte-identical", raw and raw.get("payload") == payload)
step("processing_contract == durable_queue_v1",
     raw and raw.get("processing_contract") == "durable_queue_v1",
     f"got={raw and raw.get('processing_contract')}")
step("trust_state == AUTHENTICATED",
     raw and raw.get("trust_state") == "AUTHENTICATED")
step("authentication provenance attached",
     bool(raw and isinstance(raw.get("authentication"), dict)))
job = db.edr_processing_queue.find_one({"tenant_id": TENANT,
                                       "raw_id": raw_id}, {"_id": 0})
step("queue obligation persisted", bool(job),
     f"state={job and job.get('state')}")

print("=== 7 · worker claim → canonical → DONE ===")
seen = []
final = None
for _ in range(60):
    j = db.edr_processing_queue.find_one({"tenant_id": TENANT,
                                          "raw_id": raw_id}, {"_id": 0})
    if j and (not seen or seen[-1][0] != j["state"]):
        seen.append((j["state"], j.get("attempts"), j.get("last_error")))
    if j and j["state"] == "DONE":
        final = j
        break
    time.sleep(1)
print("    observed transitions:",
      " -> ".join(f"{s}(attempts={a})" for s, a, _ in seen))
for s, a, err in seen:
    if err:
        print(f"    last_error at {s}: {str(err)[:200]}")
step("worker claimed (PROCESSING observed or already DONE)",
     any(s == "PROCESSING" for s, _, _ in seen) or bool(final))
step("final state DONE", bool(final),
     f"state={(final or db.edr_processing_queue.find_one({'raw_id': raw_id}) or {}).get('state')}")
step("attempts == 1 (no retry)", bool(final) and final.get("attempts") == 1,
     f"attempts={final and final.get('attempts')}")

raw2 = db.edr_raw_events.find_one({"raw_id": raw_id}, {"_id": 0})
derivs = (raw2 or {}).get("derivations") or []
step("canonical derivation appended", len(derivs) >= 1,
     f"derivations={len(derivs)} outcome="
     f"{derivs[-1].get('outcome') if derivs else None} "
     f"parser_state={derivs[-1].get('parser_state') if derivs else None}")
step("raw payload still byte-identical after processing",
     raw2 and raw2.get("payload") == payload)
step("payload_sha256 unchanged",
     raw2 and raw2.get("payload_sha256") == raw.get("payload_sha256"))
canon = db.v2_shadow_observations.count_documents(
    {"raw_id": raw_id}) if "v2_shadow_observations" in \
    db.list_collection_names() else -1
print(f"    canonical observation rows for this raw_id: {canon}")
ev_id = derivs[-1].get("event_id") if derivs else None
print(f"    canonical event_id: {ev_id}")

print("=== 8 · duplicate delivery of the SAME bytes ===")
before = raw2.get("duplicate_count", 0)
r = requests.post(f"{API}/api/edr/agent/telemetry", headers=AH, json={
    "payload": payload, "source_kind": "sensor",
    "sensor_version": "step5-acceptance",
    "report_interval_seconds": 60}, timeout=30)
step("duplicate ACK 200", r.status_code == 200, f"http={r.status_code}")
d = r.json()
print("    dup ACK:", json.dumps({k: v for k, v in d.items()
                                  if k != "note"}, default=str))
step("same raw_id returned", d.get("raw_id") == raw_id)
step("stored=False", d.get("stored") is False)
step("duplicate=True", d.get("duplicate") is True)
n_raw = db.edr_raw_events.count_documents({"tenant_id": TENANT,
                                           "raw_id": raw_id})
step("exactly ONE immutable raw object", n_raw == 1, f"count={n_raw}")
raw3 = db.edr_raw_events.find_one({"raw_id": raw_id}, {"_id": 0})
step("duplicate_count incremented",
     raw3.get("duplicate_count", 0) == before + 1,
     f"{before} -> {raw3.get('duplicate_count')}")
step("payload STILL byte-identical", raw3.get("payload") == payload)
n_job = db.edr_processing_queue.count_documents({"tenant_id": TENANT,
                                                 "raw_id": raw_id})
step("exactly ONE queue obligation (idempotent)", n_job == 1,
     f"count={n_job}")
step("duplicate did not resurrect the job",
     raw3 and db.edr_processing_queue.find_one(
         {"raw_id": raw_id})["state"] == "DONE")
step("processing.created=False on duplicate",
     d.get("processing", {}).get("created") is False,
     str(d.get("processing")))

print("=== 9 · post-test health ===")
r = requests.get(f"{API}/api/health", timeout=30)
step("/api/health", r.status_code == 200, f"http={r.status_code}")
hist = {x["_id"]: x["n"] for x in db.edr_processing_queue.aggregate(
    [{"$group": {"_id": "$state", "n": {"$sum": 1}}}])}
print("    queue histogram:", hist)
print("    RETRY total:", hist.get("RETRY", 0))
print(f"\nSYNTHETIC_ENDPOINT_ID={endpoint_id} HOSTNAME={HOSTNAME}")
print(f"RAW_ID={raw_id}")
print(f"MARKER={marker}")
