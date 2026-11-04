"""TASK 3A · Investigation pivots — server authority, fail closed.

What is locked here:

  1. A native console pivot exists ONLY when the tenant's OWN integration
     record declares the console route AND the incident carries the required
     identifier. Every refusal keeps its own distinct state and reason —
     `NOT_CONFIGURED`, `NOT_AUTHORIZED`, `UNSUPPORTED`,
     `REQUIRED_IDENTIFIER_MISSING`, `TEMPORARILY_UNAVAILABLE` are never
     collapsed into one "unavailable".
  2. Tenancy is fail-closed on BOTH planes: an out-of-scope incident is 404
     (existence is never disclosed), and another tenant's integration never
     appears in an incident's pivot set.
  3. Nothing is fabricated: no enrichment capability is ever reported
     AVAILABLE (no adapter exists in this build), telemetry origin stages
     with nothing recorded read `NOT_RECORDED`, and a recommendation exists
     only where an artifact justifies it.
"""
import os
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from server import app
from deps import get_current_user, init_database, validate_config

validate_config()
init_database()

client = TestClient(app)

ADMIN = {"email": "admin@nivxray.com", "role": "admin"}
OTHER_TENANT_ANALYST = {"email": "analyst@nivx-live.com", "role": "analyst"}

INC_FULL = "t3a-inc-full"
INC_BARE = "t3a-inc-bare"
TENANT = "default"
ENDPOINT = "ep_t3a_0001"


def _as(user):
    app.dependency_overrides[get_current_user] = lambda: user


def _db():
    from pymongo import MongoClient
    return MongoClient(os.environ["MONGO_URL"])[os.environ["DB_NAME"]]


@pytest.fixture
def seeded():
    db = _db()
    db.workspace_cases.delete_many({"id": {"$regex": "^t3a-"}})
    db.xdr_integrations.delete_many({"integration_id": {"$regex": "^t3a-"}})
    now = datetime.now(timezone.utc).isoformat()
    db.workspace_cases.insert_one({
        "id": INC_FULL, "doc_type": "xdr_incident", "tenant_id": TENANT,
        "incident_number": "INC000009701", "title": "task3a fixture",
        "incident_state": "new", "created_at": now, "updated_at": now,
        "iocs": {"ip": ["203.0.113.77"], "domain": ["moonlighthathel.org"],
                 "hash": ["a" * 64], "user": ["carol@nivxray.local"]},
        "endpoint_campaign": {"endpoint_id": ENDPOINT,
                              "hostname": "t3a-host", "rule_ids": ["EDR-T3A-1"]},
        "xdr_pipeline": {"detection_rule_id": "rule-t3a",
                         "trace_id": "trace-t3a"},
    })
    db.workspace_cases.insert_one({
        "id": INC_BARE, "doc_type": "xdr_incident", "tenant_id": TENANT,
        "incident_number": "INC000009702", "title": "task3a bare fixture",
        "incident_state": "new", "created_at": now, "updated_at": now,
    })
    yield db
    db.workspace_cases.delete_many({"id": {"$regex": "^t3a-"}})
    db.xdr_integrations.delete_many({"integration_id": {"$regex": "^t3a-"}})


def _integration(db, **over):
    doc = {"integration_id": "t3a-mde-1", "vendor_key": "mde",
           "tenant_id": TENANT, "label": "task3a", "connected": True}
    doc.update(over)
    db.xdr_integrations.delete_many({"vendor_key": doc["vendor_key"],
                                     "tenant_id": doc["tenant_id"]})
    db.xdr_integrations.insert_one(doc)


def _pivots(incident_id=INC_FULL, expect=200):
    r = client.get(f"/api/incidents/{incident_id}/pivots")
    assert r.status_code == expect, f"{r.status_code} · {r.text[:300]}"
    return r.json()


def _console(body, vendor_key):
    return next(c for c in body["native_consoles"]
                if c["vendor_key"] == vendor_key)


def teardown_module():
    app.dependency_overrides.clear()


# ── 1 · authorization ────────────────────────────────────────────────
def test_anonymous_cannot_read_pivots(seeded):
    app.dependency_overrides.clear()
    r = client.get(f"/api/incidents/{INC_FULL}/pivots")
    assert r.status_code in (401, 403), r.text[:200]


def test_cross_tenant_reads_404_and_discloses_nothing(seeded):
    _as(OTHER_TENANT_ANALYST)
    r = client.get(f"/api/incidents/{INC_FULL}/pivots")
    assert r.status_code == 404
    assert ENDPOINT not in r.text and "moonlighthathel.org" not in r.text


# ── 2 · telemetry origin is recorded fact or NOT_RECORDED ───────────
def test_telemetry_origin_reports_every_stage_honestly(seeded):
    _as(ADMIN)
    body = _pivots()
    stages = {s["origin_kind"]: s for s in body["telemetry_origin"]["sources"]}
    assert set(stages) == {"PRODUCT", "DSM", "COLLECTOR", "DETECTION",
                           "ENDPOINT_SENSOR"}
    # the fixture records a detection and an endpoint, but no canonical
    # evidence, collector or DSM — and the answer must say exactly that
    assert stages["DETECTION"]["state"] == "OBSERVED"
    assert stages["DETECTION"]["label"] == "rule-t3a"
    assert stages["ENDPOINT_SENSOR"]["state"] == "OBSERVED"
    assert stages["PRODUCT"]["state"] == "NOT_RECORDED"
    assert stages["COLLECTOR"]["state"] == "NOT_RECORDED"
    assert stages["DSM"]["state"] == "NOT_RECORDED"
    for s in stages.values():
        assert s["read_from"], "every stage must state the field it read"


# ── 3 · observables and external pivots ─────────────────────────────
def test_observables_are_read_from_the_record_with_their_field(seeded):
    _as(ADMIN)
    body = _pivots()
    by_value = {o["value"]: o for o in body["observables"]}
    assert by_value["203.0.113.77"]["kind"] == "ip"
    assert by_value["203.0.113.77"]["source_field"] == "iocs.ip"
    assert by_value["moonlighthathel.org"]["externally_verifiable"] is True
    # a user is recorded, but no external provider verifies one
    assert by_value["carol@nivxray.local"]["externally_verifiable"] is False
    assert by_value["carol@nivxray.local"]["actions"] == []


def test_external_pivot_urls_are_provider_hosts_and_carry_the_observable(seeded):
    _as(ADMIN)
    body = _pivots()
    ip = next(o for o in body["observables"] if o["kind"] == "ip")
    ext = [a for a in ip["actions"] if a["kind"] == "EXTERNAL"]
    assert ext, "an ip must have at least one external verification"
    for a in ext:
        if a["state"] != "AVAILABLE":
            # a provider that cannot serve this tenant is listed with its
            # state and NO url — never a link that would not work
            assert a["url"] is None and a["reason"]
            continue
        assert a["url"].startswith("https://")
        assert "203.0.113.77" in a["url"]
    internal = next(a for a in ip["actions"] if a["kind"] == "INTERNAL")
    assert internal["to"].startswith("/xdr/intelligence/iocs?")
    # a hash is not offered to an ip-only provider
    hashes = next(o for o in body["observables"] if o["kind"] == "hash")
    assert "abuseipdb" not in [a["provider"] for a in hashes["actions"]]


# ── 4 · the two capabilities stay independent, and enrichment is honest
def test_auto_enrichment_is_never_reported_available(seeded):
    _as(ADMIN)
    body = _pivots()
    assert body["providers"], "the provider register must not be empty"
    for p in body["providers"]:
        assert set(p["capabilities"]) == {"AUTO_ENRICHMENT", "EXTERNAL_PIVOT"}
        assert p["capabilities"]["AUTO_ENRICHMENT"]["state"] != "AVAILABLE"
        assert p["capabilities"]["AUTO_ENRICHMENT"]["reason"]


def test_licensed_provider_is_not_configured_without_an_integration(seeded):
    _as(ADMIN)
    body = _pivots()
    umbrella = next(p for p in body["providers"]
                    if p["key"] == "umbrella_investigate")
    assert umbrella["capabilities"]["EXTERNAL_PIVOT"]["state"] == "NOT_CONFIGURED"
    domain = next(o for o in body["observables"] if o["kind"] == "domain")
    blocked = next(a for a in domain["actions"]
                   if a["provider"] == "umbrella_investigate")
    assert blocked["state"] == "NOT_CONFIGURED" and blocked["url"] is None


# ── 5 · the native console state matrix, one state at a time ────────
def test_console_not_configured_when_the_tenant_has_no_integration(seeded):
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "NOT_CONFIGURED" and c["url"] is None


def test_console_unsupported_when_the_integration_declares_no_console_url(seeded):
    _integration(seeded)
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "UNSUPPORTED"
    assert "console URL" in c["reason"]


def test_console_unsupported_when_no_path_is_declared_for_the_target(seeded):
    _integration(seeded, console_url="https://security.microsoft.com")
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "UNSUPPORTED"
    assert "console path" in c["reason"]


def test_console_available_only_with_route_and_identifier(seeded):
    _integration(seeded, console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"})
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "AVAILABLE"
    assert c["url"] == f"https://security.microsoft.com/machines/{ENDPOINT}"


def test_console_identifier_missing_is_its_own_state(seeded):
    _integration(seeded, console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"})
    _as(ADMIN)
    c = _console(_pivots(INC_BARE), "mde")
    assert c["state"] == "REQUIRED_IDENTIFIER_MISSING" and c["url"] is None


def test_console_not_authorized_when_the_integration_is_revoked(seeded):
    _integration(seeded, console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"},
                 active=False)
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "NOT_AUTHORIZED" and c["url"] is None


def test_console_temporarily_unavailable_when_the_last_probe_failed(seeded):
    _integration(seeded, console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"},
                 connected=False, connect_detail="GET /api/health · HTTP 503")
    _as(ADMIN)
    c = _console(_pivots(), "mde")
    assert c["state"] == "TEMPORARILY_UNAVAILABLE"
    assert "HTTP 503" in c["reason"]


def test_another_tenants_integration_is_never_visible(seeded):
    _integration(seeded, tenant_id="nivx-live",
                 console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"})
    _as(ADMIN)
    body = _pivots()
    assert "mde" not in body["tenant_integrations"]
    assert _console(body, "mde")["state"] == "NOT_CONFIGURED"


# ── 6 · recommendations are artifact-derived, never generic ─────────
def test_recommendations_cite_reason_evidence_and_only_available_actions(seeded):
    _as(ADMIN)
    recs = _pivots()["recommendations"]
    assert recs, "an incident with observables must offer a pivot"
    for r in recs:
        assert r["reason"] and r["evidence"] and r["actions"]
        assert all(a["state"] == "AVAILABLE" for a in r["actions"])
    domain = next(r for r in recs if r["observable"]["kind"] == "domain")
    assert "moonlighthathel.org" in domain["reason"]
    assert "iocs.domain" in domain["reason"]


def test_an_incident_with_no_artifact_recommends_nothing(seeded):
    _as(ADMIN)
    body = _pivots(INC_BARE)
    assert body["observables"] == []
    assert body["recommendations"] == []


def test_native_console_recommendation_appears_only_when_it_can_execute(seeded):
    _as(ADMIN)
    assert not [r for r in _pivots()["recommendations"]
                if r["observable"]["kind"] == "endpoint"]
    _integration(seeded, console_url="https://security.microsoft.com",
                 console_pivot_paths={"endpoint": "/machines/{endpoint_id}"})
    rec = next(r for r in _pivots()["recommendations"]
               if r["observable"]["kind"] == "endpoint")
    assert rec["evidence"][0]["ref"] == ENDPOINT
    assert rec["actions"][0]["url"].endswith(ENDPOINT)
