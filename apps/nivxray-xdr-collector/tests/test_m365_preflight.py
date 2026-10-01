"""The Microsoft preflight validator's state machine.

The validator exists so that "it connected" is never a human opinion. These
tests drive it against a stub and assert the one thing that matters:

    OAuth success alone must NEVER produce REAL_SOURCE_PROVEN.

That state requires records actually retrieved from the configured
Microsoft service AND accepted by the authoritative NivX ingest. Every
failure mode reports itself distinctly so an operator knows which step to
revisit.
"""
from __future__ import annotations

import importlib.util
import json

import httpx
import pytest

SPEC = importlib.util.spec_from_file_location(
    "m365_preflight", "/app/scripts/m365_preflight.py")
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)

MS_TENANT = "11111111-2222-3333-4444-555555555555"
STUB = "https://manage.example.test"


@pytest.fixture()
def env(monkeypatch):
    for k in ("M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET",
              "M365_CERT_THUMBPRINT", "M365_CONTENT_TYPES",
              "NIVX_INGEST_URL", "NIVX_INGEST_TOKEN", "NIVX_COLLECTOR_ID",
              "NIVX_TENANT_ID", "M365_BASE_URL", "M365_AUTHORITY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("M365_TENANT_ID", MS_TENANT)
    monkeypatch.setenv("M365_CLIENT_ID", "app-1")
    monkeypatch.setenv("M365_CLIENT_SECRET", "never-printed")
    monkeypatch.setenv("M365_CONTENT_TYPES", "Audit.Exchange")
    monkeypatch.setenv("M365_BASE_URL", f"{STUB}/api/v1.0")
    monkeypatch.setenv("M365_AUTHORITY", STUB)
    monkeypatch.setenv("NIVX_TENANT_ID", "acme")
    monkeypatch.setenv("NIVX_COLLECTOR_ID", "col-1")
    return monkeypatch


def _mock(monkeypatch, handler):
    transport = httpx.MockTransport(handler)
    orig = httpx.AsyncClient

    def _client(*a, **kw):
        kw["transport"] = transport
        return orig(*a, **kw)
    monkeypatch.setattr(httpx, "AsyncClient", _client)


def _run(capsys):
    import asyncio
    code = asyncio.run(preflight.run())
    out = capsys.readouterr().out
    state = out.strip().splitlines()[-1].replace("PREFLIGHT STATE: ", "")
    return code, state, out


def _record(rid="r1"):
    return {"Id": rid, "RecordType": 1, "CreationTime": "2026-06-04T08:10:00",
            "Operation": "New-InboxRule", "OrganizationId": MS_TENANT,
            "UserType": 2, "Workload": "Exchange", "ResultStatus": "True",
            "UserId": "u@corp.example",
            "Parameters": [{"Name": "ForwardTo", "Value": "a@evil.example"}]}


def test_missing_configuration_is_named_not_guessed(monkeypatch, capsys):
    for k in ("M365_TENANT_ID", "M365_CLIENT_ID", "M365_CLIENT_SECRET"):
        monkeypatch.delenv(k, raising=False)
    code, state, out = _run(capsys)
    assert code == 1 and state == "CONFIGURATION_INCOMPLETE"
    assert "M365_TENANT_ID" in out


def test_a_rejected_credential_is_authentication_failed(env, capsys):
    _mock(env, lambda r: httpx.Response(
        401, json={"error": "invalid_client",
                   "error_description": "AADSTS7000215"},
        headers={"content-type": "application/json"}))
    code, state, out = _run(capsys)
    assert code == 1 and state == "AUTHENTICATION_FAILED"
    assert "AADSTS7000215" in out
    assert "never-printed" not in out


def test_consent_missing_is_reported_separately_from_auth(env, capsys):
    def handler(request):
        if "oauth2" in str(request.url):
            return httpx.Response(200, json={"access_token": "t",
                                             "expires_in": 3600})
        return httpx.Response(403, text="forbidden")
    _mock(env, handler)
    code, state, out = _run(capsys)
    assert code == 1 and state == "PERMISSION_OR_CONSENT_FAILED"
    assert "APPLICATION permission" in out


def test_oauth_success_alone_is_never_a_proof(env, capsys):
    """Authorized, subscribed, but the tenant returned no records."""
    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return httpx.Response(200, json={"access_token": "t",
                                             "expires_in": 3600})
        if "subscriptions/list" in url:
            return httpx.Response(200, json=[])
        if "subscriptions/start" in url:
            return httpx.Response(200, json={"status": "enabled"})
        if "subscriptions/content" in url:
            return httpx.Response(200, json=[])
        return httpx.Response(404)
    _mock(env, handler)
    code, state, out = _run(capsys)
    assert code == 1 and state == "RETRIEVED_NO_CONTENT"
    assert "not a proof" in out


def test_retrieved_but_unaccepted_is_not_a_proof(env, capsys):
    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return httpx.Response(200, json={"access_token": "t",
                                             "expires_in": 3600})
        if "subscriptions/start" in url or "subscriptions/list" in url:
            return httpx.Response(200, json=[])
        if "subscriptions/content" in url:
            return httpx.Response(200, json=[{
                "contentType": "Audit.Exchange", "contentId": "c1",
                "contentUri": f"{STUB}/api/v1.0/blob/c1",
                "contentCreated": "2026-06-04T09:00:00Z"}])
        if "/blob/" in url:
            return httpx.Response(200, json=[_record()])
        return httpx.Response(404)
    _mock(env, handler)
    # NIVX_INGEST_URL deliberately unset: nothing reached the evidence path
    code, state, out = _run(capsys)
    assert code == 1 and state == "RETRIEVED_BUT_NOT_ACCEPTED"
    assert "authoritative evidence path" in out


def test_real_source_proven_requires_retrieval_and_acceptance(env, capsys):
    env.setenv("NIVX_INGEST_URL", f"{STUB}/api/xdr/ingest/telemetry")
    env.setenv("NIVX_INGEST_TOKEN", "collector-key-never-printed")
    delivered = {}

    def handler(request):
        url = str(request.url)
        if "oauth2" in url:
            return httpx.Response(200, json={"access_token": "t",
                                             "expires_in": 3600})
        if "ingest/telemetry" in url:
            delivered["headers"] = dict(request.headers)
            delivered["body"] = json.loads(request.content)
            return httpx.Response(200, json={"accepted": 1})
        if "subscriptions/start" in url or "subscriptions/list" in url:
            return httpx.Response(200, json=[])
        if "subscriptions/content" in url:
            return httpx.Response(200, json=[{
                "contentType": "Audit.Exchange", "contentId": "c1",
                "contentUri": f"{STUB}/api/v1.0/blob/c1",
                "contentCreated": "2026-06-04T09:00:00Z"}])
        if "/blob/" in url:
            return httpx.Response(200, json=[_record()])
        return httpx.Response(404)
    _mock(env, handler)
    code, state, out = _run(capsys)
    assert code == 0 and state == "REAL_SOURCE_PROVEN"
    # the evidence it cites is the retrieval, not the token exchange
    assert "OAuth success alone would not have produced this state" in out
    assert delivered["body"]["envelopes"][0]["declared_source"] == \
        "m365-unified-audit"
    # the credential goes in the header the boundary authenticates
    assert "x-xdr-api-key" in {k.lower() for k in delivered["headers"]}
    assert "collector-key-never-printed" not in out
    assert "never-printed" not in out
