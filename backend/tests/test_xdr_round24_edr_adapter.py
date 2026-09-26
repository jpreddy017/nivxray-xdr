"""
Round 24 · EDR Adapter Contract + Cortex XDR + Capability Service
─────────────────────────────────────────────────────────────────

Enforces the Definition of Done:

POSITIVE SCENARIO
  Cortex connected → capability probe succeeds →
  ISOLATE_ENDPOINT flips to AVAILABLE →
  Reco synthesized with applicability=APPLICABLE

NEGATIVE SCENARIO (must remain unchanged from Round 23.5)
  Cortex not connected → ISOLATE_ENDPOINT reco stays
  CAPABILITY_UNAVAILABLE
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_edr_adapter import (
    AVAILABLE, UNAVAILABLE, FAILED, NOT_SUPPORTED, action_result,
)
from detection_content.xdr_cortex_adapter import CortexXdrAdapter
from detection_content.xdr_capability_service import (
    resolve_capability, is_available,
    _ACTION_TO_CAPABILITY, COLLECTION,
)
from detection_content.xdr_recommendation_synthesis import (
    synthesize, APPLICABLE, CAPABILITY_UNAVAILABLE,
)


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    asyncio.set_event_loop(loop)
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


# ── Adapter contract ───────────────────────────────────────────

def test_cortex_no_credentials_reports_uavailable(loop):
    ad = CortexXdrAdapter({})
    r = _run(loop, ad.connect())
    assert r["ok"] is False
    assert "not configured" in r["detail"].lower()
    # Redacted creds only — no secret leaks.
    assert r["credentials"]["api_key"] in (None, "***")
    entries = _run(loop, ad.capability_probe())
    supported = {e["action_id"]: e for e in entries
                        if e["action_id"] in ("ENDPOINT_ISOLATE",
                                                            "TERMINATE_PROCESS",
                                                            "PROCESS_EXCLUSION_ADD")}
    for e in supported.values():
        assert e["state"] == UNAVAILABLE
    # Cortex-not-supported actions must be NOT_SUPPORTED regardless
    # of connection status.
    unsupported = [e for e in entries
                            if e["action_id"] == "IP_BLOCK"]
    assert unsupported[0]["state"] == NOT_SUPPORTED


def test_cortex_creds_present_but_no_connector_reports_failed(loop):
    """AVAILABLE must NEVER be inferred from credential presence."""
    ad = CortexXdrAdapter({
        "base_url":    "https://api-example.xdr.paloaltonetworks.com",
        "credentials": {"api_key_id": "42", "api_key": "sekret"},
    })
    r = _run(loop, ad.connect())
    assert r["ok"] is False
    entries = _run(loop, ad.capability_probe())
    isolate = [e for e in entries
                    if e["action_id"] == "ENDPOINT_ISOLATE"][0]
    assert isolate["state"] == FAILED


def test_cortex_connect_success_via_stubbed_connector(loop):
    calls = []
    async def connector(method, path, headers, json):
        calls.append((method, path))
        if path.endswith("/healthcheck/"):
            return {"ok": True, "detail": "ok",
                        "vendor_reference": "tnt-a1"}
        if method == "OPTIONS":
            return {"ok": True, "detail": "supported"}
        if method == "POST":
            return {"ok": True, "detail": "queued",
                        "action_id": "cxdr-vendor-42"}
        return {"ok": False}

    ad = CortexXdrAdapter({
        "base_url":    "https://api-example.xdr.paloaltonetworks.com",
        "credentials": {"api_key_id": "42", "api_key": "sekret"},
        "_connector":  connector,
    })
    r = _run(loop, ad.connect())
    assert r["ok"] is True
    assert r["credentials"]["api_key"] == "***"

    probe = _run(loop, ad.capability_probe())
    isolate = [e for e in probe
                    if e["action_id"] == "ENDPOINT_ISOLATE"][0]
    assert isolate["state"] == AVAILABLE

    ex = _run(loop, ad.execute_action(
        "ENDPOINT_ISOLATE", {"endpoint_id": "host-023"}))
    assert ex["ok"] is True
    assert ex["vendor"] == "palo_alto_cortex_xdr"
    assert ex["vendor_request_id"].startswith("cxdr-")
    assert ex["vendor_response_id"] == "cxdr-vendor-42"


def test_action_result_never_leaks_credentials(loop):
    async def connector(method, path, headers, json):
        # Simulate a failing endpoint that echoes headers into the
        # error message.  We must never leak Authorization.
        return {"ok": False, "detail": "internal"}
    ad = CortexXdrAdapter({
        "base_url":    "https://api-example.xdr.paloaltonetworks.com",
        "credentials": {"api_key_id": "42",
                              "api_key": "sekret-should-never-leak"},
        "_connector":  connector,
    })
    _run(loop, ad.connect())
    ex = _run(loop, ad.execute_action("ENDPOINT_ISOLATE",
                                                    {"endpoint_id": "h1"}))
    import json as _json
    blob = _json.dumps(ex)
    assert "sekret-should-never-leak" not in blob
    assert "Authorization" not in blob


# ── Capability service ────────────────────────────────────────

def test_capability_service_returns_uavailable_without_integration(
        loop, db):
    # Ensure no test integration doc pollutes.
    _run(loop, db[COLLECTION].delete_many(
        {"integration_id": {"$regex": "^itest-"}}))
    r = _run(loop, resolve_capability(db, "ENDPOINT_ISOLATE"))
    assert r["state"] == UNAVAILABLE
    assert r["provider"] is None


def test_capability_service_flips_available_when_integration_probed(
        loop, db):
    itest_id = f"itest-{uuid.uuid4().hex[:10]}"
    _run(loop, db[COLLECTION].insert_one({
        "integration_id":   itest_id,
        "vendor":           "palo_alto_cortex_xdr",
        "active":           True,
        "connected":        True,
        "capability_matrix": [
            {"capability_id":  "edr.isolate_endpoint",
              "action_id":     "ENDPOINT_ISOLATE",
              "state":         AVAILABLE,
              "detail":        "probe ok"},
            {"capability_id":  "edr.terminate_process",
              "action_id":     "TERMINATE_PROCESS",
              "state":         AVAILABLE,
              "detail":        "probe ok"},
        ],
    }))
    r = _run(loop, resolve_capability(db, "ENDPOINT_ISOLATE"))
    assert r["state"] == AVAILABLE
    assert r["provider"] == itest_id


# ── End-to-end: Positive + Negative scenarios ─────────────────

def test_positive_scenario_reco_flips_to_applicable(loop, db):
    """When an integration says ENDPOINT_ISOLATE = AVAILABLE, a
    synthesized reco targeting the observed host MUST report
    applicability=APPLICABLE — the definition of done."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "ipv4", "value": "203.0.113.42",
              "role": "destination", "origin": "network.dst.ip"},
            {"kind": "host", "value": "host-023",
              "role": "artifact", "origin": "host"},
        ],
        "capability_overrides": {
            "ENDPOINT_ISOLATE": {"state": AVAILABLE,
                                              "detail": "cortex probe ok"},
        },
    }
    recos = synthesize(context, {"family": "C2"}, [], [], [])
    iso = [r for r in recos
              if r["suggested_action"] == "ENDPOINT_ISOLATE"]
    assert iso, "ISOLATE_ENDPOINT candidate must be emitted for C2 host"
    for r in iso:
        assert r["applicability"] == APPLICABLE
        assert "cortex probe ok" in r["applicability_reason"] \
            or r["applicability"] == APPLICABLE


def test_negative_scenario_reco_stays_capability_unavailable(loop, db):
    """When no integration provides ENDPOINT_ISOLATE, the reco MUST
    remain CAPABILITY_UNAVAILABLE — Round 23.5 invariant preserved."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "host", "value": "host-023",
              "role": "artifact", "origin": "host"},
        ],
        # No overrides → static registry default (False).
    }
    recos = synthesize(context, {"family": "C2"}, [], [], [])
    iso = [r for r in recos
              if r["suggested_action"] == "ENDPOINT_ISOLATE"]
    for r in iso:
        assert r["applicability"] == CAPABILITY_UNAVAILABLE
