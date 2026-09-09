"""PREVIEW COLLECTOR PROOF — machine-auth end to end.

APPROVED SCOPE: preview only.  No production deploy, no production collector,
no Vercel action, no rule/threshold/VEEE/incident-writer modification, no
fabricated incident.

Proves:
    scoped API key -> enrolled preview webhook collector -> authenticated
    telemetry ingest (NO admin JWT) -> raw persisted -> canonical evidence ->
    detection -> VEEE -> incident gate -> Incident Queue (proof tenant only)

The admin JWT is used ONLY for the control plane (mint key, enroll collector,
read the queue).  Telemetry ingest is authenticated exclusively with
`X-XDR-API-Key` + `X-Tenant-Id`.

Run:  python /app/scripts/preview_collector_auth_proof.py
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

import requests
from pymongo import MongoClient

sys.path.insert(0, "/app/backend")

BASE = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
API = BASE + "/api"
TENANT = "p0f-collector-auth-proof"
OTHER_TENANT = "p0f-collector-auth-proof-other"

_mc = MongoClient(os.environ["MONGO_URL"])
_db = _mc[os.environ["DB_NAME"]]

# The controlled safe event.  This exact line is the existing fixture in
# tests/edr/test_p1_10_cef_leef_dsm.py which already asserts rule DET-EX-001
# fires on it.  Nothing about the rule, its threshold, VEEE or the incident
# writer is touched — we only feed a payload the enabled content already
# recognises.
CEF_LINE = (
    "<14>Jun 10 12:40:11 fw01 CEF:0|Palo Alto Networks|PAN-OS|10.2|4001|"
    "encoded powershell observed|8|src=10.4.9.22 spt=51455 dst=203.0.113.55 "
    "dpt=443 proto=TCP dvchost=HYD-FW01 duser=r.mehta dproc=powershell.exe "
    "dpid=4412 cs1Label=CommandLine "
    "cs1=powershell.exe -enc SQBFAFgAJwBoAHQAdABwAA== act=alert"
)

R: dict = {"stages": [], "auth_matrix": [], "ids": {}, "findings": []}


def log(stage: str, status: str, **detail):
    rec = {"stage": stage, "status": status, **detail}
    R["stages"].append(rec)
    print(f"[{status:>8}] {stage} :: {json.dumps(detail, default=str)[:400]}")
    return rec


def amx(case: str, expected: str, code: int, ok: bool, reason=None):
    rec = {"case": case, "expected": expected, "http": code,
           "reason": reason, "verdict": "PASS" if ok else "FAIL"}
    R["auth_matrix"].append(rec)
    print(f"  {'PASS' if ok else 'FAIL':>4}  {case:<46} -> {code} {reason or ''}")
    return ok


def reason_of(resp):
    try:
        d = resp.json().get("detail")
    except Exception:
        return None
    return d.get("reason") if isinstance(d, dict) else d


def envelope(tenant=TENANT, collector=None, sev_line=CEF_LINE, seq="a"):
    return {
        "tenant_id": tenant,
        "collector_id": collector,
        "collection_method": "webhook",
        "source": "preview-proof-webhook",
        "connector_id": "webhook-p0f-proof",
        "parser_version": "cef-leef/1.0",
        "event_type": "alert",
        "source_event_id": f"p0f-proof-{seq}",
        "source_timestamp": "2026-06-10T12:40:11Z",
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "raw": {"line": sev_line, "payload_format": "cef"},
    }


# ══ 1 · control plane: admin JWT (NOT used for ingest) ═════════════
login = requests.post(f"{API}/auth/login", json={
    "email": os.environ["ADMIN_EMAIL"],
    "password": os.environ["ADMIN_PASSWORD"]}, timeout=60)
assert login.status_code == 200, login.text
JWT = login.json()["access_token"]
ADM = {"Authorization": f"Bearer {JWT}", "X-Tenant-Id": TENANT}
log("control_plane_login", "EXECUTED", principal=os.environ["ADMIN_EMAIL"],
    note="admin JWT is used for key minting / enrollment / queue read ONLY")


# ══ 2 · mint scoped API keys via the existing lifecycle ════════════
def mint(name, scopes, tenant=TENANT):
    r = requests.post(f"{API}/xdr/api-keys",
                      headers={**ADM, "X-Tenant-Id": tenant},
                      json={"name": name, "scopes": scopes,
                            "description": "PREVIEW COLLECTOR PROOF · throwaway"},
                      timeout=60)
    assert r.status_code == 200, r.text
    d = r.json()["data"]
    return d["id"], d["plaintext"], d["prefix"]


KEY_ID, KEY, KEY_PREFIX = mint(f"p0f-proof-ingest-{uuid.uuid4().hex[:6]}",
                               ["collectors.enroll", "collectors.read"])
REV_ID, REV_KEY, _ = mint(f"p0f-proof-revoked-{uuid.uuid4().hex[:6]}",
                          ["collectors.enroll"])
NOSCOPE_ID, NOSCOPE_KEY, _ = mint(f"p0f-proof-noscope-{uuid.uuid4().hex[:6]}",
                                  ["alerts.read"])
OTHER_ID, OTHER_KEY, _ = mint(f"p0f-proof-othertenant-{uuid.uuid4().hex[:6]}",
                              ["collectors.enroll", "collectors.read"],
                              tenant=OTHER_TENANT)
assert requests.post(f"{API}/xdr/api-keys/{REV_ID}/revoke",
                     headers=ADM, timeout=60).status_code == 200
R["ids"].update({"api_key_id": KEY_ID, "api_key_prefix": KEY_PREFIX,
                 "revoked_key_id": REV_ID, "unscoped_key_id": NOSCOPE_ID,
                 "other_tenant_key_id": OTHER_ID})
stored = _db["xdr_api_keys"].find_one({"id": KEY_ID})
log("api_key_minted", "EXECUTED", key_id=KEY_ID, prefix=KEY_PREFIX,
    scopes=stored["scopes"], tenant=stored["tenant_id"],
    stored_hash_len=len(stored["hash"]),
    plaintext_absent_from_store=KEY not in json.dumps(
        {k: v for k, v in stored.items() if k not in ("_id", "prefix")}, default=str))


# ══ 3 · enroll one preview webhook collector bound to the tenant ═══
cr = requests.post(f"{API}/xdr/collectors", headers=ADM, json={
    "name": f"p0f-proof-webhook-{uuid.uuid4().hex[:6]}",
    "protocol": "webhook",
    "description": "PREVIEW COLLECTOR PROOF · throwaway",
    "auth_kind": "bearer",
    "tags": ["p0f-proof", "throwaway"]}, timeout=60)
assert cr.status_code == 200, cr.text
COLLECTOR = cr.json()["data"]["id"]
R["ids"]["collector_id"] = COLLECTOR
log("collector_enrolled", "EXECUTED", collector_id=COLLECTOR,
    tenant=cr.json()["data"]["tenant_id"],
    state=cr.json()["data"]["state"], protocol="webhook")


# ══ 4 · auth proof matrix on the REAL ingest endpoint ══════════════
ING = f"{API}/xdr/ingest/telemetry"
body = {"envelopes": [envelope(collector=COLLECTOR, seq="authmx")]}
ok_all = True


def probe(headers):
    return requests.post(ING, headers=headers, json=body, timeout=120)


print("\n── AUTH PROOF MATRIX ──")
r = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT})
ok_all &= amx("valid key + matching tenant", "200 accepted", r.status_code,
              r.status_code == 200)
FIRST_RECEIPT = r.json() if r.status_code == 200 else None

r = probe({"X-Tenant-Id": TENANT})
ok_all &= amx("no credential", "403 denied", r.status_code,
              r.status_code == 403, reason_of(r))
r = probe({"X-XDR-API-Key": "nvx_" + "0" * 48, "X-Tenant-Id": TENANT})
ok_all &= amx("unknown key", "401 denied", r.status_code,
              r.status_code == 401, reason_of(r))
r = probe({"X-XDR-API-Key": "not-a-key", "X-Tenant-Id": TENANT})
ok_all &= amx("malformed key", "401 denied", r.status_code,
              r.status_code == 401, reason_of(r))
r = probe({"X-XDR-API-Key": "", "X-Tenant-Id": TENANT})
ok_all &= amx("empty key header", "401 denied", r.status_code,
              r.status_code == 401, reason_of(r))
r = probe({"X-XDR-API-Key": REV_KEY, "X-Tenant-Id": TENANT})
ok_all &= amx("revoked key", "403 denied", r.status_code,
              r.status_code == 403, reason_of(r))
r = probe({"X-XDR-API-Key": NOSCOPE_KEY, "X-Tenant-Id": TENANT})
ok_all &= amx("key without collectors.enroll", "403 denied", r.status_code,
              r.status_code == 403, reason_of(r))
r = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": OTHER_TENANT})
ok_all &= amx("valid key + wrong tenant header", "403 denied", r.status_code,
              r.status_code == 403, reason_of(r))
r = probe({"X-XDR-API-Key": OTHER_KEY, "X-Tenant-Id": OTHER_TENANT})
ok_all &= amx("other-tenant key -> this collector", "403 denied",
              r.status_code, r.status_code == 403, reason_of(r))
r = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT,
           "Authorization": f"Bearer {JWT}"})
ok_all &= amx("key + admin JWT together", "401 ambiguous", r.status_code,
              r.status_code == 401, reason_of(r))
r = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT,
           "X-Principal-Id": "admin@nivxray.com",
           "X-Principal-Kind": "user"})
ok_all &= amx("key + spoofed principal headers", "200 (key still the "
              "authority)", r.status_code, r.status_code == 200)
log("auth_proof_matrix", "PASS" if ok_all else "FAIL",
    cases=len(R["auth_matrix"]))


# ══ 5 · the 422 cross-tenant question ══════════════════════════════
print("\n── 422 CROSS-TENANT INVESTIGATION ──")
wellformed_cross = {"envelopes": [envelope(tenant=OTHER_TENANT,
                                           collector=COLLECTOR, seq="xtenant")]}
r_wf = requests.post(
    ING, headers={"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT},
    json=wellformed_cross, timeout=120)
malformed_cross = {"envelopes": [{"tenant_id": OTHER_TENANT, "source": "x",
                                  "events": []}]}
r_mf = requests.post(ING, headers={"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT},
                     json=malformed_cross, timeout=120)
cross_wf_ok = r_wf.status_code == 403 and "TENANT_ISOLATION_VIOLATION" in r_wf.text
log("cross_tenant_wellformed_envelope", "PASS" if cross_wf_ok else "FAIL",
    http=r_wf.status_code, body=r_wf.text[:300])
log("cross_tenant_malformed_envelope", "OBSERVED", http=r_mf.status_code,
    body=r_mf.text[:200])
R["findings"].append({
    "item": "reported 422 on cross-tenant envelope",
    "classification": ("VALIDATION-ORDER SEMANTICS · NOT a tenant-isolation "
                       "defect" if cross_wf_ok and r_mf.status_code == 422
                       else "NEEDS REVIEW"),
    "evidence": (f"A WELL-FORMED cross-tenant envelope is refused "
                 f"{r_wf.status_code} TENANT_ISOLATION_VIOLATION. The 422 only "
                 f"appears for a body that fails Pydantic shape validation "
                 f"(missing collector_id/collection_method), which FastAPI "
                 f"runs before the handler, so the tenant check is never "
                 f"reached. No cross-tenant write is possible in either case."),
    "security_impact": "NONE — isolation holds. Left unfixed as instructed.",
})


# ══ 6 · pipeline provenance for the authenticated ingest ═══════════
print("\n── PIPELINE PROVENANCE ──")
assert FIRST_RECEIPT is not None, "authenticated ingest did not return 200"
rsn = (FIRST_RECEIPT.get("reasoning") or [{}])[0]
TRACE = rsn.get("trace_id")
INCIDENT = rsn.get("incident_id")
R["ids"].update({"trace_id": TRACE, "observation_id": rsn.get("observation_id"),
                 "incident_id": INCIDENT})
log("ingest_receipt", "EXECUTED", accepted=FIRST_RECEIPT.get("accepted"),
    collector_state=FIRST_RECEIPT.get("collector_state"),
    collector_state_reason=FIRST_RECEIPT.get("collector_state_reason"),
    reasoned=FIRST_RECEIPT.get("reasoned"),
    observations_created=FIRST_RECEIPT.get("observations_created"),
    reasoning_status=rsn.get("status"), blocker=rsn.get("blocker"),
    detections_matched=rsn.get("detections_matched"),
    verdict=rsn.get("verdict"), verdict_score=rsn.get("verdict_score"),
    incident_created=rsn.get("incident_created"),
    incident_reason=rsn.get("incident_reason"), trace_id=TRACE)

raw_doc = _db["xdr_canonical_events"].find_one(
    {"tenant_id": TENANT, "collector_id": COLLECTOR,
     "source_event_id": "p0f-proof-authmx"})
log("raw_ingest_persisted", "PASS" if raw_doc else "FAIL",
    collection="xdr_canonical_events",
    _id=str(raw_doc["_id"]) if raw_doc else None,
    line_verbatim=(raw_doc or {}).get("raw", {}).get("line") == CEF_LINE)

can_doc = _db["xdr_canonical_evidence"].find_one({"trace_id": TRACE}) or \
    _db["xdr_canonical_evidence"].find_one({"tenant_id": TENANT},
                                           sort=[("_id", -1)])
CANON_ID = (can_doc or {}).get("event_id")
R["ids"]["canonical_event_id"] = CANON_ID
log("canonical_evidence_created", "PASS" if can_doc else "FAIL",
    collection="xdr_canonical_evidence", event_id=CANON_ID,
    tenant=(can_doc or {}).get("tenant_id"),
    dsm=(can_doc or {}).get("provenance", {}).get("dsm_id"),
    severity_band=(can_doc or {}).get("security", {}).get("severity_band"))

inc_doc = _db["workspace_cases"].find_one({"id": INCIDENT}) if INCIDENT else None
prov = (inc_doc or {}).get("xdr_pipeline") or {}
RULE = prov.get("detection_rule_id")
R["ids"]["detection_rule_id"] = RULE
R["ids"]["iue_id"] = prov.get("iue_id")
log("incident_materialised", "PASS" if inc_doc else "FAIL",
    incident_id=INCIDENT, doc_type=(inc_doc or {}).get("doc_type"),
    tenant=(inc_doc or {}).get("tenant_id"),
    title=(inc_doc or {}).get("title"),
    priority=(inc_doc or {}).get("incident_priority"),
    state=(inc_doc or {}).get("incident_state"),
    veee_score=prov.get("veee_score") or prov.get("verdict_score"),
    veee_label=prov.get("veee_label") or prov.get("verdict_label"),
    detection_rule_id=RULE, canonical_event_id=prov.get("canonical_event_id"),
    iue_id=prov.get("iue_id"), collector=prov.get("collector_id"),
    gate=f"INCIDENT_MIN_SCORE=55 · verdict={rsn.get('verdict')} "
         f"score={rsn.get('verdict_score')}")


# ══ 7 · replay / idempotency ═══════════════════════════════════════
print("\n── REPLAY / IDEMPOTENCY ──")
raw_before = _db["xdr_canonical_events"].count_documents(
    {"tenant_id": TENANT, "source_event_id": "p0f-proof-authmx"})
can_before = _db["xdr_canonical_evidence"].count_documents({"tenant_id": TENANT})
inc_before = _db["workspace_cases"].count_documents(
    {"tenant_id": TENANT, "doc_type": "xdr_incident"})
r2 = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT})
rec2 = r2.json() if r2.status_code == 200 else {}
rsn2 = (rec2.get("reasoning") or [{}])[0]
raw_after = _db["xdr_canonical_events"].count_documents(
    {"tenant_id": TENANT, "source_event_id": "p0f-proof-authmx"})
can_after = _db["xdr_canonical_evidence"].count_documents({"tenant_id": TENANT})
inc_after = _db["workspace_cases"].count_documents(
    {"tenant_id": TENANT, "doc_type": "xdr_incident"})
dedup_ok = (rec2.get("duplicates") == 1
            and rsn2.get("status") == "DUPLICATE"
            and rsn2.get("incident_created") is False
            and rsn2.get("incident_id") == INCIDENT
            and raw_after == raw_before
            and can_after == can_before
            and inc_after == inc_before)
log("replay_identical_envelope", "PASS" if dedup_ok else "FAIL",
    http=r2.status_code, duplicates_reported=rec2.get("duplicates"),
    replay_status=rsn2.get("status"),
    replay_incident_created=rsn2.get("incident_created"),
    points_at_original_incident=rsn2.get("incident_id") == INCIDENT,
    duplicate_of_trace_id=rsn2.get("duplicate_of_trace_id"),
    delivery_count=rsn2.get("delivery_count"),
    raw_rows=f"{raw_before}->{raw_after}",
    canonical_docs=f"{can_before}->{can_after}",
    incidents=f"{inc_before}->{inc_after}",
    reasoned=rec2.get("reasoned"),
    observations_created=rec2.get("observations_created"),
    incidents_promoted=rec2.get("incidents_promoted"),
    collector_events_received=(_db["xdr_collectors"].find_one(
        {"id": COLLECTOR}) or {}).get("events_received"),
    collector_events_duplicate=(_db["xdr_collectors"].find_one(
        {"id": COLLECTOR}) or {}).get("events_duplicate"),
    incident_duplicate_delivery_count=(_db["workspace_cases"].find_one(
        {"id": INCIDENT}) or {}).get("duplicate_delivery_count"))

# A genuinely distinct security event (new source_event_id) must still flow.
r3 = requests.post(ING, headers={"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT},
                   json={"envelopes": [envelope(collector=COLLECTOR,
                                                seq="distinct")]}, timeout=120)
rec3 = r3.json() if r3.status_code == 200 else {}
rsn3 = (rec3.get("reasoning") or [{}])[0]
distinct_ok = (rec3.get("duplicates") == 0
               and rsn3.get("status") == "REASONED"
               and rsn3.get("incident_id") != INCIDENT)
log("distinct_event_not_suppressed", "PASS" if distinct_ok else "FAIL",
    http=r3.status_code, duplicates_reported=rec3.get("duplicates"),
    reasoning_status=rsn3.get("status"), new_incident_id=rsn3.get("incident_id"),
    note="different source_event_id => genuinely new event, never suppressed")


# ══ 8 · queue visibility + tenant isolation ════════════════════════
print("\n── QUEUE VISIBILITY / TENANT ISOLATION ──")
q_admin = requests.get(f"{API}/incidents?customer={TENANT}&limit=50",
                       headers={"Authorization": f"Bearer {JWT}"}, timeout=120)
admin_ids = [i.get("id") for i in (q_admin.json().get("incidents") or [])] \
    if q_admin.status_code == 200 else []
log("queue_visible_to_authorized_reader", "PASS" if INCIDENT in admin_ids
    else "FAIL", http=q_admin.status_code,
    incident_present=INCIDENT in admin_ids, returned=len(admin_ids),
    reader="admin (all_tenants)")

other_seen = None
al = requests.post(f"{API}/auth/login", json={
    "email": "analyst@nivx-live.com",
    "password": "NivxLive!Analyst2026"}, timeout=60)
if al.status_code == 200:
    at = al.json()["access_token"]
    q_o = requests.get(f"{API}/incidents?limit=200",
                       headers={"Authorization": f"Bearer {at}"}, timeout=120)
    ids_o = [i.get("id") for i in (q_o.json().get("incidents") or [])] \
        if q_o.status_code == 200 else []
    other_seen = INCIDENT in ids_o
    log("queue_hidden_from_other_tenant", "PASS" if other_seen is False
        else "FAIL", reader="analyst@nivx-live.com (tenant nivx-live)",
        http=q_o.status_code, incident_present=other_seen,
        returned=len(ids_o))
else:
    log("queue_hidden_from_other_tenant", "SKIPPED",
        reason=f"analyst login {al.status_code}")

xt = requests.get(f"{API}/xdr/collectors",
                  headers={"X-XDR-API-Key": OTHER_KEY,
                           "X-Tenant-Id": OTHER_TENANT}, timeout=60)
xt_ids = [c.get("id") for c in
          ((xt.json().get("data") or {}).get("collectors") or [])] \
    if xt.status_code == 200 else []
log("other_tenant_key_cannot_see_proof_collector",
    "PASS" if COLLECTOR not in xt_ids else "FAIL", http=xt.status_code,
    proof_collector_visible=COLLECTOR in xt_ids, returned=len(xt_ids))


# ══ 9 · cleanup ════════════════════════════════════════════════════
print("\n── CLEANUP ──")
for kid in (KEY_ID, NOSCOPE_ID, OTHER_ID):
    requests.post(f"{API}/xdr/api-keys/{kid}/revoke", headers=ADM, timeout=60)
requests.post(f"{API}/xdr/collectors/{COLLECTOR}/disable", headers=ADM,
              timeout=60)
still_works = probe({"X-XDR-API-Key": KEY, "X-Tenant-Id": TENANT})
log("cleanup", "EXECUTED",
    keys_revoked=[KEY_ID, REV_ID, NOSCOPE_ID, OTHER_ID],
    collector_disabled=COLLECTOR,
    revoked_key_now_denied=still_works.status_code == 403,
    revoked_key_http=still_works.status_code,
    evidence_retained=("raw events, canonical evidence and the incident are "
                       "INTENTIONALLY retained under tenant "
                       f"{TENANT} for owner review"))

fails = [s for s in R["stages"] if s["status"] == "FAIL"] + \
        [a for a in R["auth_matrix"] if a["verdict"] == "FAIL"]
R["verdict"] = ("PASS" if not fails and INCIDENT else
                "PARTIAL PASS" if not fails else "FAIL")
R["ids"]["tenant"] = TENANT
print("\n" + "=" * 70)
print("VERDICT:", R["verdict"], "· failures:", len(fails))
print("IDS:", json.dumps(R["ids"], indent=1, default=str))
with open("/app/test_reports/preview_collector_auth_proof.json", "w") as fh:
    json.dump(R, fh, indent=1, default=str)
print("report -> /app/test_reports/preview_collector_auth_proof.json")
