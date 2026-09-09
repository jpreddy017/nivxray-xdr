"""
Round 28.x · CrowdStrike Falcon acceptance suite.

Locked owner criteria (2026-02-14):
  1. Framework-leakage canary: shipping Falcon must NOT modify
     any of the protected files above the adapter boundary.
  2. Falcon connect() maps 401/403 → AUTHENTICATION_FAILED, DNS/
     timeout → CONNECTION_FAILED, 200 → AVAILABLE.
  3. Falcon capabilities() honestly reports NOT_SUPPORTED for
     actions it cannot do (PROCESS_KILL, DISABLE_USER,
     REVOKE_TOKEN).
  4. Falcon detection payloads translate into the vendor-neutral
     incident shape that CortexParser already consumes.
  5. Falcon execute_action honours the vendor response envelope
     — no fake success on rejection.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import pytest

from detection_content.xdr_vendor_registry import get_vendor_class
from detection_content.xdr_cortex_parser import parse_incident


PROTECTED_FILES = [
    "detection_content/xdr_credential_vault.py",
    "detection_content/xdr_cortex_executor.py",
    "detection_content/xdr_capability_service.py",
    "detection_content/xdr_cortex_ingest.py",
    "detection_content/xdr_cortex_promotion.py",
    "detection_content/xdr_vendor_adapter.py",
    "routers/xdr_vendor_wizard.py",
    "routers/xdr_cortex_actions.py",
]
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_protected_files_have_no_falcon_references():
    """Framework-leakage canary — the WORDS 'falcon' or
    'crowdstrike' must not appear in any protected file.  If they
    do, the adapter is leaking above the boundary."""
    leaks = []
    for rel in PROTECTED_FILES:
        with open(os.path.join(BACKEND_ROOT, rel), "r", encoding="utf-8") as f:
            body = f.read().lower()
        if "falcon" in body or "crowdstrike" in body:
            leaks.append(rel)
    assert not leaks, f"framework leak in {leaks}"


def test_falcon_metadata_shape():
    cls = get_vendor_class("falcon")
    meta = cls.metadata()
    assert meta["vendor_key"]   == "falcon"
    assert meta["lifecycle"]    == "PRODUCTION"
    schema_keys = [f["key"] for f in meta["credential_schema"]]
    assert schema_keys == ["cloud", "client_id", "client_secret"]
    # `cloud` is a select with the known Falcon regions.
    cloud_field = meta["credential_schema"][0]
    assert cloud_field["kind"] == "select"
    assert "us-1" in cloud_field["options"]


def test_falcon_connect_authentication_failed(monkeypatch):
    cls = get_vendor_class("falcon")
    async def bad_creds(_method, _url, _headers, _body):
        return {"ok": False, "reason": "AUTHENTICATION_FAILED",
                    "detail": "HTTP 401 · invalid_client",
                    "http_status": 401}
    adapter = cls(credentials={"cloud": "us-1", "client_id": "x",
                                        "client_secret": "y"},
                     connector=bad_creds)
    r = _run(adapter.connect())
    assert r["ok"] is False
    assert r["reason"] == "AUTHENTICATION_FAILED"


def test_falcon_connect_no_live_tenant_without_creds():
    cls = get_vendor_class("falcon")
    adapter = cls(credentials={"cloud": "us-1"})
    r = _run(adapter.connect())
    assert r["ok"] is False
    assert r["reason"] == "NO_LIVE_TENANT"


def test_falcon_connect_available_on_2xx():
    cls = get_vendor_class("falcon")
    async def ok_call(_m, _u, _h, _b):
        return {"ok": True, "http_status": 200,
                    "vendor_reference": "req-42",
                    "json": {"access_token": "tok-xyz",
                                "expires_in": 1799}}
    adapter = cls(credentials={"cloud": "us-1",
                                        "client_id": "x", "client_secret": "y"},
                     connector=ok_call)
    r = _run(adapter.connect())
    assert r["ok"] is True
    assert r["reason"] == "AVAILABLE"


def test_falcon_capabilities_honest_matrix():
    cls = get_vendor_class("falcon")
    adapter = cls(credentials={})
    caps = _run(adapter.capabilities())
    by = {c["action_id"]: c["state"] for c in caps}
    assert by["ENDPOINT_ISOLATE"] == "AVAILABLE"
    assert by["BLOCK_HASH"]       == "AVAILABLE"
    assert by["PROCESS_KILL"]     == "NOT_SUPPORTED"
    assert by["DISABLE_USER"]     == "NOT_SUPPORTED"
    assert by["REVOKE_TOKEN"]     == "NOT_SUPPORTED"


def test_falcon_detection_translates_to_neutral_incident():
    """Falcon detection → vendor-neutral incident shape →
    canonical evidence rows via the SAME CortexParser used for
    Cortex.  No parser divergence."""
    cls = get_vendor_class("falcon")
    adapter = cls(credentials={})
    det = {
        "detection_id": "det-42",
        "first_behavior":  "2026-09-01T02:54:04Z",
        "last_behavior":   "2026-09-01T02:54:06Z",
        "max_severity_displayname": "High",
        "status": "new",
        "device": {"hostname": "legion5", "device_id": "dev-abc"},
        "behaviors": [{
            "behavior_id": "beh-1",
            "timestamp": "2026-09-01T02:54:04Z",
            "scenario": "malicious_file",
            "severity": 70,
            "description": "ExecutedMalware.ioc",
            "filename": "idle_report.exe",
            "cmdline": "idle_report.exe --id 76758",
            "sha256": "806775d9a498229c66663683009b61a5a6c42ce2d3433c43ebcb782ac3ffc6b1",
            "user_name": "codexsandboxoffline",
            "tactic_id": "TA0002", "tactic": "Execution",
            "technique_id": "T1219", "technique": "Remote Access Software",
        }],
    }
    neutral = adapter._falcon_to_incident(det)
    assert neutral["incident_id"] == "det-42"
    assert neutral["hosts"] == ["legion5"]
    rows = parse_incident(neutral, integration_id="falcon-a")
    types = [r["source_object_type"] for r in rows]
    # incident + alert + key_artifact(sha256) + host + user = 5
    assert types == ["incident", "alert", "key_artifact", "host", "user"]
    alert = next(r for r in rows if r["source_object_type"] == "alert")
    assert alert["fields"]["file_sha256"] == det["behaviors"][0]["sha256"]
    assert alert["fields"]["mitre_technique"] == {"id": "T1219",
                                                            "name": "Remote Access Software"}


def test_falcon_execute_endpoint_isolate_success():
    cls = get_vendor_class("falcon")
    call_log = []
    async def stub(method, url, headers, body):
        call_log.append((method, url))
        if url.endswith("/oauth2/token"):
            return {"ok": True, "http_status": 200,
                        "json": {"access_token": "tok"}}
        # /devices/entities/devices-actions/v2 → success
        return {"ok": True, "http_status": 202,
                    "vendor_reference": "req-xyz",
                    "json": {"resources": [{"id": "action-1234",
                                                    "path": "..."}]}}
    adapter = cls(credentials={"cloud": "us-1",
                                        "client_id": "x",
                                        "client_secret": "y"},
                     connector=stub)
    r = _run(adapter.execute_action(
        "ENDPOINT_ISOLATE",
        {"target": {"kind": "host", "value": "dev-abc", "id": "dev-abc"}}))
    assert r["ok"] is True
    assert r["vendor_action_id"] == "action-1234"
    assert any("/devices-actions/v2" in url for _, url in call_log)


def test_falcon_execute_never_fakes_success_on_rejection():
    cls = get_vendor_class("falcon")
    async def rejecting(method, url, headers, body):
        if url.endswith("/oauth2/token"):
            return {"ok": True, "http_status": 200,
                        "json": {"access_token": "tok"}}
        return {"ok": False, "reason": "VENDOR_ERROR",
                    "detail": "HTTP 400 · sensor unreachable",
                    "http_status": 400}
    adapter = cls(credentials={"cloud": "us-1",
                                        "client_id": "x",
                                        "client_secret": "y"},
                     connector=rejecting)
    r = _run(adapter.execute_action(
        "BLOCK_HASH",
        {"target": {"kind": "sha256", "value": "a"*64}}))
    assert r["ok"] is False
    assert r["vendor_action_id"] is None
    assert "400" in r["detail"] or "sensor" in r["detail"]
