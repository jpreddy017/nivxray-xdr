"""XDR Data Sources + Collectors + Ingest — P0-8 pytest.

Covers the full completion gate from the P0-8 directive:

  1  Data-source CRUD + audit
  2  Collector CRUD + audit + protocol registry
  3  Admin state-machine transitions
  4  ILLEGAL transitions rejected (admin cannot set CONNECTED)
  5  Ingest telemetry is the ONLY path to CONNECTED
  6  parse_ok=False → PARSE_ERROR (never CONNECTED)
  7  error_ratio > 10% → DEGRADED (never CONNECTED)
  8  Tenant isolation:
       · header tenant ≠ collector tenant → 403
       · envelope tenant ≠ collector tenant → 403
       · another tenant's list does NOT include this tenant's rows
  9  RBAC negative — scoped user is denied on every mutation
  10 Real telemetry E2E — one collector reaches CONNECTED entirely
      through the ingest path, with audit evidence recorded
  11 Persistence — counters + last_event_at are updated correctly
"""
from __future__ import annotations

import os
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("XDR_AUDIT_MASTER_SECRET", "test-master-secret")
os.environ.setdefault("XDR_SECRETS_MASTER", "test-secrets-master-passphrase")

from routers import xdr_audit_log as al
from routers import xdr_collectors as col
from routers import xdr_data_sources as ds
from routers import xdr_ingest as ing
from routers import xdr_rbac as rb
from server import app

client = TestClient(app)

TEN     = f"p08-{uuid.uuid4().hex[:8]}"
OTHER   = f"p08-other-{uuid.uuid4().hex[:8]}"
ADMIN   = "root@p08"
SCOPED  = "readonly@p08"
_SUF    = uuid.uuid4().hex[:6]


def _hdrs(email: str = ADMIN, tenant: str | None = None) -> dict:
    return {"X-Tenant-Id": tenant or TEN,
                "X-Principal-Id": email,
                "X-Principal-Kind": "user"}


def _skip_if_no_mongo():
    if col._db() is None:
        pytest.skip("MONGO_URL not configured")


@pytest.fixture(scope="module", autouse=True)
def _clean_slate():
    _skip_if_no_mongo()
    for c in (col._coll, ds._coll, ing._c_events):
        if c() is not None:
            c().delete_many({"tenant_id": {"$in": [TEN, OTHER]}})
    for c in (rb._c_users, rb._c_roles, rb._c_groups, rb._c_assignments):
        if c() is not None:
            c().delete_many({"tenant_id": {"$in": [TEN, OTHER]}})
    if al._get_coll() is not None:
        al._get_coll().delete_many({"tenant_id": {"$in": [TEN, OTHER]}})

    # Seed admin in our tenant (bootstrap allows the first user in).
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                          json={"email": ADMIN,
                                    "initial_roles": ["platform_admin"]})
    assert r.status_code == 200, r.text
    # Scoped read-only user: only collectors.read + data_sources.read.
    r = client.post("/api/xdr/rbac/roles", headers=_hdrs(ADMIN),
                          json={"name": f"p08_ro_{_SUF}", "display_name": "P08 RO",
                                    "permissions": ["collectors.read",
                                                            "data_sources.read"]})
    assert r.status_code == 200, r.text
    role_id = r.json()["data"]["id"]
    r = client.post("/api/xdr/rbac/users", headers=_hdrs(ADMIN),
                          json={"email": SCOPED, "initial_roles": [role_id]})
    assert r.status_code == 200, r.text
    yield


# ── 1 · Data-source CRUD ──────────────────────────────────────────
def test_data_source_crud_and_audit():
    _skip_if_no_mongo()
    # Create
    r = client.post("/api/xdr/data-sources", headers=_hdrs(),
                          json={"name": "syslog-firewall",
                                    "kind": "generic_syslog",
                                    "description": "perimeter fw"})
    assert r.status_code == 200, r.text
    ds_id = r.json()["data"]["id"]
    assert r.json()["data"]["state"] == "ADOPTED"
    assert r.json()["data"]["protocol"] == "syslog"

    # Read list
    r = client.get("/api/xdr/data-sources", headers=_hdrs())
    assert r.status_code == 200
    assert any(d["id"] == ds_id for d in r.json()["data"]["data_sources"])

    # Update
    r = client.put(f"/api/xdr/data-sources/{ds_id}", headers=_hdrs(),
                          json={"description": "updated desc",
                                    "tags": ["perimeter", "critical"]})
    assert r.status_code == 200
    assert r.json()["data"]["description"] == "updated desc"

    # Disable + enable
    r = client.post(f"/api/xdr/data-sources/{ds_id}/disable", headers=_hdrs())
    assert r.status_code == 200 and r.json()["data"]["enabled"] is False
    r = client.post(f"/api/xdr/data-sources/{ds_id}/enable",  headers=_hdrs())
    assert r.status_code == 200 and r.json()["data"]["enabled"] is True

    # Test probe
    r = client.post(f"/api/xdr/data-sources/{ds_id}/test", headers=_hdrs())
    assert r.status_code == 200
    # Probe reports honest problem (no collector bound yet)
    assert not r.json()["data"]["last_probe"]["ok"]
    assert "no collector bound" in r.json()["data"]["last_probe"]["problems"]

    # Audit chain valid
    r = client.get("/api/xdr/audit-log?action=DATA_SOURCE_CREATED",
                          headers=_hdrs())
    assert any(e["resource_id"] == ds_id for e in r.json()["data"]["events"])


def test_data_source_kind_validation():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/data-sources", headers=_hdrs(),
                          json={"name": "bad", "kind": "unknown_thing"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "INVALID_KIND"


# ── 2 · Collector CRUD + protocol registry ────────────────────────
def _create_syslog_collector(name_hint: str = "syslog-receiver") -> str:
    """Helper — returns collector id, not a test itself."""
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"{name_hint}-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog",
                                    "tls": False, "auth_kind": "none",
                                    "config": {"port": 5514}})
    assert r.status_code == 200, r.text
    return r.json()["data"]["id"]


def test_collector_crud_and_protocol_registry():
    _skip_if_no_mongo()
    # Protocol catalog honest split
    r = client.get("/api/xdr/collectors/protocols/catalog", headers=_hdrs())
    counts = r.json()["data"]["counts"]
    assert counts["implemented"] == 3, counts   # syslog / webhook / rest
    assert counts["scaffold"] >= 9, counts
    assert counts["blocked"] == 0

    cid = _create_syslog_collector("syslog-receiver-crud")
    doc = col._coll().find_one({"id": cid})
    assert doc["state"] == "ADOPTED"
    assert doc["implementation"] == "IMPLEMENTED"

    # Unknown protocol
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": "bad", "protocol": "nope"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "UNKNOWN_PROTOCOL"


# ── 3 · Admin state-machine transitions ───────────────────────────
def test_admin_state_machine_ADOPTED_to_STARTING():
    _skip_if_no_mongo()
    cid = _create_syslog_collector("syslog-sm")
    # ADOPTED → CONFIGURED (via update)
    r = client.put(f"/api/xdr/collectors/{cid}", headers=_hdrs(),
                          json={"description": "configured"})
    assert r.status_code == 200
    assert r.json()["data"]["state"] == "CONFIGURED"
    # CONFIGURED → STARTING
    r = client.post(f"/api/xdr/collectors/{cid}/start", headers=_hdrs())
    assert r.status_code == 200
    assert r.json()["data"]["state"] == "STARTING"
    # STARTING → DISABLED (stop)
    r = client.post(f"/api/xdr/collectors/{cid}/stop", headers=_hdrs())
    assert r.status_code == 200
    assert r.json()["data"]["state"] == "DISABLED"


def test_admin_cannot_promote_to_CONNECTED_directly():
    _skip_if_no_mongo()
    # Create fresh collector.
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    # Try to nudge to CONNECTED via /start-style transition — the
    # admin transition table simply has no CONNECTED target.  The
    # only way to get CONNECTED is through /api/xdr/ingest/telemetry.
    # We assert we can reach STARTING but not CONNECTED by admin API.
    doc = col._coll().find_one({"id": cid})
    assert doc["state"] in {"ADOPTED", "CONFIGURED"}
    # There is no admin route that names CONNECTED as target; verify
    # the internal transition helper refuses it.
    with pytest.raises(HTTPException):
        col._transition_state(doc, "CONNECTED",
                                            reason="admin says so",
                                            evidence={"by": "attacker"},
                                            admin=True)


# ── 4 · Ingest — parse_ok=False must NOT reach CONNECTED ─────────
def test_parse_failure_yields_PARSE_ERROR_never_CONNECTED():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    r = client.post(f"/api/xdr/collectors/{cid}/start", headers=_hdrs())
    assert r.json()["data"]["state"] == "STARTING"

    # Send a batch where the parser failed on every event.
    envelopes = [{
        "tenant_id": TEN, "collector_id": cid,
        "collection_method": "syslog",
        "raw": {"line": "corrupt"},
        "parser_ok": False, "normalized_ok": False,
    } for _ in range(3)]
    r = client.post("/api/xdr/ingest/telemetry", headers=_hdrs(),
                          json=envelopes)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["collector_state"] == "PARSE_ERROR"
    assert body["accepted"] == 0


# ── 5 · Ingest — real telemetry drives CONNECTED ─────────────────
def test_real_telemetry_reaches_CONNECTED():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    r = client.post(f"/api/xdr/collectors/{cid}/start", headers=_hdrs())
    assert r.json()["data"]["state"] == "STARTING"

    # 10 clean events → parsed + normalized succeed for each.
    envelopes = [{
        "tenant_id": TEN, "collector_id": cid,
        "collection_method": "syslog",
        "raw": {"line": f"good #{i}"},
        "normalized": {"message": f"good {i}"},
        "parser_ok": True, "normalized_ok": True,
    } for i in range(10)]
    r = client.post("/api/xdr/ingest/telemetry", headers=_hdrs(),
                          json=envelopes)
    body = r.json()
    assert body["collector_state"] == "CONNECTED", body
    assert body["accepted"] == 10

    # Counters and last_event_at are persisted honestly.
    doc = col._coll().find_one({"id": cid})
    assert doc["events_received"]   == 10
    assert doc["events_parsed"]     == 10
    assert doc["events_normalized"] == 10
    assert doc["state"] == "CONNECTED"
    assert doc["state_evidence"]["received"] == 10
    assert doc["state_evidence"]["parsed"]   == 10
    assert doc["state_evidence"]["normalized"] == 10
    assert doc["last_event_at"] is not None

    # Audit log captured the state change with the evidence block.
    r = client.get("/api/xdr/audit-log?action=COLLECTOR_STATE_CHANGED",
                          headers=_hdrs())
    events = r.json()["data"]["events"]
    conn = [e for e in events if e.get("resource_id") == cid
                 and e.get("after", {}).get("state") == "CONNECTED"]
    assert conn, "CONNECTED audit event missing"
    assert conn[0]["metadata"]["evidence"]["normalized"] == 10


def test_error_ratio_above_threshold_yields_DEGRADED():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    client.post(f"/api/xdr/collectors/{cid}/start", headers=_hdrs())
    # 5 good + 3 bad = 37% errors → DEGRADED (not CONNECTED).
    envelopes = (
        [{"tenant_id": TEN, "collector_id": cid, "collection_method": "syslog",
          "raw": {"line": f"g{i}"}, "normalized": {"m": i},
          "parser_ok": True, "normalized_ok": True} for i in range(5)]
        +
        [{"tenant_id": TEN, "collector_id": cid, "collection_method": "syslog",
          "raw": {"line": f"b{i}"},
          "parser_ok": False, "normalized_ok": False} for i in range(3)]
    )
    r = client.post("/api/xdr/ingest/telemetry", headers=_hdrs(),
                          json=envelopes)
    assert r.json()["collector_state"] == "DEGRADED"


# ── 6 · Tenant isolation ──────────────────────────────────────────
def test_tenant_isolation_envelope_mismatch_denied():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    # Envelope claims a DIFFERENT tenant than the collector owns.
    env = [{"tenant_id": "hostile-tenant", "collector_id": cid,
                "collection_method": "syslog", "raw": {}, "parser_ok": True,
                "normalized_ok": True}]
    r = client.post("/api/xdr/ingest/telemetry", headers=_hdrs(), json=env)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "TENANT_ISOLATION_VIOLATION"


def test_tenant_isolation_header_mismatch_denied():
    _skip_if_no_mongo()
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "syslog"})
    cid = r.json()["data"]["id"]
    # Header tenant does NOT match the collector's tenant.
    env = [{"tenant_id": TEN, "collector_id": cid,
                "collection_method": "syslog", "raw": {}, "parser_ok": True,
                "normalized_ok": True}]
    r = client.post("/api/xdr/ingest/telemetry",
                          headers=_hdrs(ADMIN, tenant="totally-other"),
                          json=env)
    assert r.status_code == 403


def test_tenant_isolation_list_does_not_leak():
    _skip_if_no_mongo()
    # Seed a user in OTHER so its bootstrap allows through, then list.
    client.post("/api/xdr/rbac/users",
                    headers=_hdrs(ADMIN, tenant=OTHER),
                    json={"email": "root@other",
                              "initial_roles": ["platform_admin"]})
    # Create a collector in OTHER.
    client.post("/api/xdr/collectors",
                    headers=_hdrs("root@other", tenant=OTHER),
                    json={"name": "other-only", "protocol": "syslog"})
    # From TEN, listing collectors MUST NOT include OTHER's.
    r = client.get("/api/xdr/collectors", headers=_hdrs())
    names = [c["name"] for c in r.json()["data"]["collectors"]]
    assert "other-only" not in names


# ── 7 · RBAC negative — scoped user is denied on mutations ────────
DENIED = [
    ("POST",   "/api/xdr/data-sources",
      {"name": "x", "kind": "generic_syslog"},
      "data_sources.create"),
    ("DELETE", "/api/xdr/data-sources/anything", None, "data_sources.delete"),
    ("POST",   "/api/xdr/collectors",
      {"name": "x", "protocol": "syslog"}, "collectors.create"),
    ("POST",   "/api/xdr/collectors/anything/start",
      None, "collectors.enable"),
    ("POST",   "/api/xdr/collectors/anything/stop",
      None, "collectors.disable"),
    ("POST",   "/api/xdr/ingest/telemetry",
      [{"tenant_id": TEN, "collector_id": "x", "collection_method": "syslog",
        "raw": {}}],
      "collectors.enroll"),
]


@pytest.mark.parametrize("method,path,body,perm", DENIED,
                                            ids=[f"{m}:{p}" for m, p, _, _ in DENIED])
def test_scoped_principal_denied(method, path, body, perm):
    _skip_if_no_mongo()
    req = getattr(client, method.lower())
    kwargs = {"headers": _hdrs(SCOPED)}
    if body is not None:
        kwargs["json"] = body
    r = req(path, **kwargs)
    assert r.status_code == 403, f"{method} {path} → {r.status_code}"
    assert r.json()["detail"]["code"] == "ACCESS_DENIED"
    assert r.json()["detail"]["permission"] == perm


def test_scoped_principal_can_read():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/data-sources", headers=_hdrs(SCOPED))
    assert r.status_code == 200
    r = client.get("/api/xdr/collectors",   headers=_hdrs(SCOPED))
    assert r.status_code == 200


# ── 8 · Data-source counters bubble up via ingest ───────────────
def test_data_source_counters_updated_by_ingest():
    _skip_if_no_mongo()
    # Fresh collector + data source bound to it.
    r = client.post("/api/xdr/collectors", headers=_hdrs(),
                          json={"name": f"c-{uuid.uuid4().hex[:6]}",
                                    "protocol": "webhook"})
    cid = r.json()["data"]["id"]
    r = client.post("/api/xdr/data-sources", headers=_hdrs(),
                          json={"name": f"ds-{uuid.uuid4().hex[:6]}",
                                    "kind": "generic_webhook",
                                    "collector_id": cid})
    dsid = r.json()["data"]["id"]
    client.post(f"/api/xdr/collectors/{cid}/start", headers=_hdrs())
    envs = [{"tenant_id": TEN, "collector_id": cid,
                "data_source_id": dsid,
                "collection_method": "webhook",
                "raw": {"a": 1}, "normalized": {"a": 1},
                "parser_ok": True, "normalized_ok": True} for _ in range(4)]
    r = client.post("/api/xdr/ingest/telemetry", headers=_hdrs(), json=envs)
    assert r.json()["collector_state"] == "CONNECTED"
    doc = ds._coll().find_one({"id": dsid})
    assert doc["events_received"]   == 4
    assert doc["events_normalized"] == 4
    assert doc["last_telemetry_at"] is not None


# ── 9 · Audit chain valid after all P0-8 activity ────────────────
def test_audit_chain_valid_after_p08():
    _skip_if_no_mongo()
    r = client.get("/api/xdr/audit-log/verify/chain", headers=_hdrs())
    assert r.json()["data"]["status"] == "valid"
