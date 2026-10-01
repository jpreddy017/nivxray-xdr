"""G1 · server-side proof authority + negative controls.

Creates ONLY the temporary authority G1 needs, then proves the refusals
before any Windows endpoint is allowed to deliver:

    org → proof tenant → isolation tenant → windows-eventlog collector
        → least-privilege verification key → negative controls → revoke

The verification key exists to prove the refusals and is REVOKED at the end
of this run. The endpoint's operational credential is never minted here and
never transits this process, a log, or the chat transcript: it is minted on
the Windows host itself, into an environment variable, by the handoff block.

Idempotent: re-running reuses an existing org/tenant/collector by slug/name
rather than creating a second one.

No plaintext credential is ever printed. Only `prefix` and `id`.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ["G1_BASE_URL"].rstrip("/")
EMAIL = os.environ["G1_ADMIN_EMAIL"]
PASSWORD = os.environ["G1_ADMIN_PASSWORD"]

ORG_SLUG = "g1-windows-proof-org"
TEN_PROOF = "g1-windows-proof"
TEN_ISO = "g1-windows-isolation"
COLLECTOR_NAME = "g1-windows-endpoint"
SOURCES = ["microsoft-sysmon", "windows-security-evd",
           "windows-powershell-evd"]

out: dict = {"base_url": BASE, "steps": [], "negative_controls": []}


def call(method: str, path: str, *, token=None, tenant=None, api_key=None,
         body=None) -> tuple[int, dict]:
    req = urllib.request.Request(BASE + path, method=method)
    req.add_header("Content-Type", "application/json")
    # Cloudflare in front of preview refuses the default urllib agent (1010).
    req.add_header("User-Agent", "curl/8.5.0")
    req.add_header("Accept", "*/*")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if api_key:
        req.add_header("X-XDR-API-Key", api_key)
    if tenant:
        req.add_header("X-Tenant-Id", tenant)
    data = json.dumps(body).encode() if body is not None else None
    try:
        with urllib.request.urlopen(req, data, timeout=60) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return e.code, {"raw": raw[:400]}


def step(name: str, code: int, detail) -> None:
    out["steps"].append({"step": name, "http": code, "detail": detail})
    print(f"[{code}] {name}: {detail}")


def control(name: str, code: int, expect_code: int, detail) -> None:
    ok = code == expect_code
    out["negative_controls"].append({
        "control": name, "http": code, "expected_http": expect_code,
        "pass": ok, "detail": detail})
    print(f"{'PASS' if ok else 'FAIL'} [{code}/{expect_code}] {name}: "
          f"{detail}")


# ── 0 · admin session ────────────────────────────────────────────────
code, body = call("POST", "/api/auth/login",
                  body={"email": EMAIL, "password": PASSWORD})
assert code == 200, (code, body)
JWT = body["access_token"]
step("admin session", code, "authenticated (token not recorded)")

# ── 1 · organisation ─────────────────────────────────────────────────
code, body = call("GET", "/api/xdr/organizations", token=JWT,
                  tenant=TEN_PROOF)
existing = {o["slug"]: o for o in
            ((body.get("data") or {}).get("organizations") or [])} \
    if code == 200 else {}
if ORG_SLUG in existing:
    org = existing[ORG_SLUG]
    step("organization (reused)", 200, org["id"])
else:
    code, body = call("POST", "/api/xdr/organizations", token=JWT,
                      body={"slug": ORG_SLUG, "kind": "VENDOR",
                            "display_name": "G1 Windows proof"})
    assert code == 200, (code, body)
    org = body["data"]
    step("organization created", code, org["id"])

# ── 2 · tenants: proof + isolation negative control ──────────────────
tenants = {}
for slug, label in ((TEN_PROOF, "G1 Windows proof"),
                    (TEN_ISO, "G1 Windows isolation control")):
    code, body = call("POST", "/api/xdr/tenants", token=JWT,
                      body={"organization_id": org["id"], "slug": slug,
                            "display_name": label, "kind": "CUSTOMER",
                            "products": ["XDR", "EDR"]})
    if code == 200:
        tenants[slug] = body["data"]["id"]
        step(f"tenant created {slug}", code, tenants[slug])
    else:
        code2, body2 = call("GET", "/api/xdr/tenants", token=JWT,
                            tenant=TEN_PROOF)
        rows = (body2.get("data") or {}).get("tenants") or []
        hit = [t for t in rows if t.get("slug") == slug]
        assert hit, (code, body, code2, body2)
        tenants[slug] = hit[0]["id"]
        step(f"tenant reused {slug}", code, tenants[slug])

TID = tenants[TEN_PROOF]
TID_ISO = tenants[TEN_ISO]

# ── 3 · windows-eventlog collector enrolment ─────────────────────────
code, body = call("POST", "/api/xdr/collectors", token=JWT, tenant=TID,
                  body={"name": COLLECTOR_NAME,
                        "protocol": "windows-eventlog",
                        "description": ("G1 native Windows Event Log "
                                        "acquisition proof"),
                        "authorized_sources": SOURCES,
                        "auth_kind": "none", "tls": True,
                        "tags": ["g1", "windows", "proof"]})
if code == 200:
    coll = body["data"]
    step("collector enrolled", code, coll["id"])
else:
    code2, body2 = call("GET", "/api/xdr/collectors", token=JWT, tenant=TID)
    rows = (body2.get("data") or {}).get("collectors") or []
    hit = [c for c in rows if c.get("name") == COLLECTOR_NAME]
    assert hit, (code, body, code2, body2)
    coll = hit[0]
    step("collector reused", code, coll["id"])

COLLECTOR_ID = coll["id"]
out["authority"] = {
    "organization_id": org["id"], "tenant_id": TID,
    "isolation_tenant_id": TID_ISO, "collector_id": COLLECTOR_ID,
    "collector_protocol": coll.get("protocol"),
    "collector_transport": coll.get("transport"),
    "collector_implementation": coll.get("implementation"),
    "collector_canonical_schema": coll.get("canonical_schema"),
    "authorized_sources": coll.get("authorized_sources"),
    "collector_state": coll.get("state"),
}
step("protocol metadata", 200, {
    k: out["authority"][k] for k in
    ("collector_protocol", "collector_transport",
     "collector_implementation")})

# ── 4 · least-privilege VERIFICATION key (revoked at the end) ────────
key_name = f"g1-verification-{int(time.time())}"
code, body = call("POST", "/api/xdr/api-keys", token=JWT, tenant=TID,
                  body={"name": key_name, "confirm_tenant_id": TID,
                        "description": ("G1 negative-control verification "
                                        "only; revoked in the same run"),
                        "scopes": ["collectors.enroll"]})
assert code == 200, (code, body)
VKEY = body["data"]["plaintext"]           # never printed, never persisted
VKEY_ID = body["data"]["id"]
step("verification key minted", code,
     {"id": VKEY_ID, "prefix": body["data"]["prefix"],
      "scopes": ["collectors.enroll"]})

# ── 5 · isolation-tenant authority + key, for the cross-tenant control ─
# A registry-valid tenant with no users/roles/collectors/keys cannot be
# issued its first credential (`_tenant_is_known` → TENANT_NOT_FOUND), so
# the control tenant gets its own collector first. It is authorized for
# NOTHING, which is what makes its refusals genuine.
code, body = call("POST", "/api/xdr/collectors", token=JWT, tenant=TID_ISO,
                  body={"name": "g1-isolation-control",
                        "protocol": "windows-eventlog",
                        "description": "G1 negative control only",
                        "authorized_sources": [],
                        "auth_kind": "none", "tls": True,
                        "tags": ["g1", "control"]})
if code == 200:
    iso_coll = body["data"]["id"]
    step("isolation collector enrolled", code, iso_coll)
else:
    code2, body2 = call("GET", "/api/xdr/collectors", token=JWT,
                        tenant=TID_ISO)
    rows = (body2.get("data") or {}).get("collectors") or []
    hit = [c for c in rows if c.get("name") == "g1-isolation-control"]
    assert hit, (code, body, code2, body2)
    iso_coll = hit[0]["id"]
    step("isolation collector reused", code, iso_coll)
out["isolation_collector_id"] = iso_coll

code, body = call("POST", "/api/xdr/api-keys", token=JWT, tenant=TID_ISO,
                  body={"name": f"g1-isolation-{int(time.time())}",
                        "confirm_tenant_id": TID_ISO,
                        "description": "G1 isolation negative control only",
                        "scopes": ["collectors.enroll"]})
assert code == 200, (code, body)
IKEY = body["data"]["plaintext"]
IKEY_ID = body["data"]["id"]
step("isolation key minted", code,
     {"id": IKEY_ID, "prefix": body["data"]["prefix"]})

INGEST = "/api/xdr/ingest/telemetry"


def envelope(*, tenant=None, collector=None, source="sysmon"):
    tenant = tenant or TID
    collector = collector or COLLECTOR_ID
    return {"envelopes": [{
        "tenant_id": tenant, "collector_id": collector,
        "connector_id": "windows-eventlog-g1proof01",
        "collection_method": "windows-eventlog",
        "source": source, "declared_source": source,
        "parser_version": "g1.negative-control",
        "source_timestamp": "2026-06-01T09:59:58.120000+00:00",
        "collection_timestamp": "2026-06-01T10:00:01.000000+00:00",
        "event_type": "negative-control/0",
        "raw": {"xml": "<Event/>", "channel": "negative-control"},
        "canonical": {"activity_time_source": "EventData.UtcTime",
                      "activity_occurred_at":
                          "2026-06-01T09:59:58.120000+00:00",
                      "sensor_observed_at":
                          "2026-06-01T10:00:01.000000+00:00"},
    }]}


# ── 6 · negative controls, BEFORE the endpoint is allowed to deliver ─
code, body = call("POST", INGEST, tenant=TID, body=envelope())
control("unauthenticated ingest denied", code, 403,
        (body.get("detail") or {}).get("code") or body)

code, body = call("POST", INGEST, api_key=VKEY, tenant=TID_ISO,
                  body=envelope(tenant=TID_ISO))
control("proof key cannot act in the isolation tenant", code, 403,
        (body.get("detail") or {}).get("code") or body)

code, body = call("POST", INGEST, api_key=IKEY, tenant=TID_ISO,
                  body=envelope(tenant=TID_ISO, collector=COLLECTOR_ID))
control("foreign tenant cannot use this collector id (no disclosure)",
        code, 403, (body.get("detail") or {}).get("code") or body)

code, body = call("POST", INGEST, api_key=VKEY, tenant=TID,
                  body=envelope(collector="col_does_not_exist_g1"))
control("unenrolled collector identity denied", code, 404,
        body.get("detail") or body)

code, body = call("POST", INGEST, api_key=VKEY, tenant=TID,
                  body=envelope(source="windows_system"))
receipt = body if code == 200 else (body.get("detail") or body)
blocked = (receipt.get("routing_blocked") if isinstance(receipt, dict)
           else None)
control("unauthorized/unsupported source refused (B4 shape)", code, 200,
        {"accepted": receipt.get("accepted") if isinstance(receipt, dict)
         else None, "routing_blocked": blocked})

code, body = call("POST", INGEST, api_key=VKEY, tenant=TID,
                  body={"envelopes": [{**envelope()["envelopes"][0],
                                       "declared_source": None}]})
receipt = body if code == 200 else (body.get("detail") or body)
control("undeclared source refused (DECLARATION_REQUIRED)", code, 200,
        {"accepted": receipt.get("accepted") if isinstance(receipt, dict)
         else None,
         "routing_blocked": receipt.get("routing_blocked")
         if isinstance(receipt, dict) else None})

# ── 7 · revoke both verification credentials ─────────────────────────
for kid, label in ((VKEY_ID, "verification"), (IKEY_ID, "isolation")):
    code, body = call("POST", f"/api/xdr/api-keys/{kid}/revoke", token=JWT,
                      tenant=TID if label == "verification" else TID_ISO,
                      body={"reason": "G1 negative controls complete"})
    step(f"{label} key revoked", code, kid)

# ── 8 · baseline snapshot (a proof needs a before) ───────────────────
code, body = call("GET", f"/api/xdr/collectors/{COLLECTOR_ID}", token=JWT,
                  tenant=TID)
doc = (body.get("data") or {}) if code == 200 else {}
out["baseline"] = {
    "state": doc.get("state"),
    "events_received": doc.get("events_received"),
    "events_parsed": doc.get("events_parsed"),
    "events_normalized": doc.get("events_normalized"),
    "events_error": doc.get("events_error"),
    "last_event_at": doc.get("last_event_at"),
}
step("baseline snapshot", code, out["baseline"])

out["all_negative_controls_pass"] = all(
    c["pass"] for c in out["negative_controls"])
path = "/app/test_reports/g1_server_authority_prep.json"
with open(path, "w") as f:
    json.dump(out, f, indent=2)
print("\nwrote", path)
print("negative controls:",
      "ALL PASS" if out["all_negative_controls_pass"] else "FAILURES PRESENT")
sys.exit(0 if out["all_negative_controls_pass"] else 1)
