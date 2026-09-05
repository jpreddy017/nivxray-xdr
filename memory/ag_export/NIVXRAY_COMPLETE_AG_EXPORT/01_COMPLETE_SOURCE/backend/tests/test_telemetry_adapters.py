"""
Phase 2 · Telemetry Adapter Framework regression suite.

Owner-rule invariants under test:

  · Vendor fields never leak past the adapter boundary — the
    returned `CanonicalEvent` uses only NivXRay XDR-canonical
    keys (actor, target, context, outcome).
  · Every emitted event carries a mandatory `Provenance` envelope
    with source_id, vendor, adapter version, raw_ref and
    ingested_at.
  · Capability declarations are honest: an adapter MUST list what
    it does and does not provide.
  · Adapters never modify verdict semantics or invent evidence.
"""
from __future__ import annotations

import pytest

from services.telemetry_adapters import (
    CanonicalEvent, Provenance, SourceKind, get_registry,
    OktaSystemLogAdapter, EntraSignInLogAdapter,
    AwsCloudTrailAdapter,
)


# ---------- Registry integrity ------------------------------------------
def test_registry_lists_three_adapters_by_default():
    names = {a["name"] for a in get_registry().list()}
    assert {"okta.system-log", "entra.signin-log",
                    "aws.cloudtrail"}.issubset(names)


def test_registry_rejects_duplicate_registration():
    reg = get_registry()
    with pytest.raises(ValueError):
        reg.register(OktaSystemLogAdapter())


# ---------- Okta System Log ---------------------------------------------
@pytest.mark.asyncio
async def test_okta_adapter_normalises_sign_in():
    a = OktaSystemLogAdapter()
    raw = [{
        "uuid": "evt-okta-1",
        "published": "2026-08-15T10:11:12Z",
        "eventType": "user.session.start",
        "outcome": {"result": "SUCCESS"},
        "severity": "INFO",
        "actor": {
            "id": "okta-user-1", "displayName": "Alice",
            "alternateId": "alice@corp.com", "type": "User",
        },
        "target": [{"id": "okta-app-1", "displayName": "SFDC",
                          "alternateId": "sfdc", "type": "AppInstance"}],
        "client": {
            "ipAddress": "203.0.113.4",
            "userAgent": {"rawUserAgent": "curl/8.0"},
            "geographicalContext": {"city": "Berlin",
                                                    "country": "Germany"},
        },
    }]
    events = await a.normalise(raw)
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, CanonicalEvent)
    assert ev.action == "identity.user.session.start"
    assert ev.source_kind == SourceKind.IDENTITY
    assert ev.outcome == "SUCCESS"
    assert ev.actor == {
        "id": "okta-user-1", "name": "Alice",
        "type": "User", "email": "alice@corp.com",
    }
    assert ev.target["name"] == "SFDC"
    assert ev.context["ip"] == "203.0.113.4"
    assert ev.context["geo_city"] == "Berlin"
    # Provenance mandatory.
    assert isinstance(ev.provenance, Provenance)
    assert ev.provenance.vendor == "okta"
    assert ev.provenance.raw_ref == "evt-okta-1"
    assert ev.provenance.adapter_name == "okta.system-log"


@pytest.mark.asyncio
async def test_okta_adapter_passes_unknown_event_type_through_honestly():
    a = OktaSystemLogAdapter()
    events = await a.normalise([{"uuid":"u",
                                                    "eventType":"security.exotic.thing"}])
    assert events[0].action == "identity.raw:security.exotic.thing"


# ---------- Entra Sign-in Log -------------------------------------------
@pytest.mark.asyncio
async def test_entra_adapter_maps_status_and_risk():
    a = EntraSignInLogAdapter()
    raw = [{
        "id": "entra-1",
        "createdDateTime": "2026-08-16T09:00:00Z",
        "userId": "u-1", "userDisplayName": "Bob",
        "userPrincipalName": "bob@corp.com",
        "appId": "app-1", "appDisplayName": "M365",
        "ipAddress": "198.51.100.5",
        "userAgent": "Mozilla/5.0",
        "deviceDetail": {"deviceId":"d-1","isCompliant":True},
        "location": {"city":"Dublin","countryOrRegion":"IE"},
        "riskLevelDuringSignIn": "high",
        "status": {"errorCode": 50126},
        "appliedConditionalAccessPolicies": [
            {"displayName":"Block foreign IPs"},
        ],
    }]
    events = await a.normalise(raw)
    ev = events[0]
    assert ev.outcome == "FAILURE"
    assert ev.severity_hint == "high"
    assert ev.context["conditional_access"] == ["Block foreign IPs"]
    assert ev.provenance.vendor == "entra"


# ---------- AWS CloudTrail ----------------------------------------------
@pytest.mark.asyncio
async def test_aws_cloudtrail_maps_assume_role_and_error():
    a = AwsCloudTrailAdapter()
    raw = [{
        "eventID": "aws-1",
        "eventTime": "2026-08-16T09:00:00Z",
        "eventSource": "sts.amazonaws.com",
        "eventName": "AssumeRole",
        "awsRegion": "eu-west-1",
        "sourceIPAddress": "192.0.2.10",
        "userAgent": "aws-cli/2",
        "requestID": "req-1",
        "recipientAccountId": "111122223333",
        "userIdentity": {
            "type": "AssumedRole", "arn": "arn:aws:sts::111:assumed-role/foo/session",
            "accountId": "999988887777", "userName": "foo",
            "sessionContext": {"sessionIssuer": {
                "arn": "arn:aws:iam::999:role/foo", "userName":"foo",
            }},
        },
        "resources": [{"ARN":"arn:aws:iam::999:role/foo"}],
        "errorCode": "AccessDenied",
        "errorMessage": "Not authorised",
    }]
    events = await a.normalise(raw)
    ev = events[0]
    assert ev.outcome == "FAILURE"
    assert ev.action == "cloud.api_call:sts.amazonaws.com:AssumeRole"
    assert ev.context["aws_region"] == "eu-west-1"
    assert ev.context["error_code"] == "AccessDenied"
    assert ev.actor["assumed_role"] == "arn:aws:iam::999:role/foo"
    assert ev.target["recipient_account_id"] == "111122223333"
    assert ev.provenance.vendor == "aws-cloudtrail"


# ---------- No vendor field leaks past the boundary ---------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("adapter,cls", [
    (OktaSystemLogAdapter(),    OktaSystemLogAdapter),
    (EntraSignInLogAdapter(),   EntraSignInLogAdapter),
    (AwsCloudTrailAdapter(),    AwsCloudTrailAdapter),
])
async def test_canonical_event_has_no_vendor_specific_keys(adapter, cls):
    """The `CanonicalEvent` dataclass MUST only expose canonical
    keys.  Vendor field names in `context` are allowed (they are
    inside the canonical `context` bag which is a governed
    namespace), but no vendor field may appear at the TOP level."""
    raw = [{
        "uuid":"x", "id":"y", "eventID":"z",
        "eventType":"user.session.start",
        "eventName":"AssumeRole", "eventSource":"sts.amazonaws.com",
        "userIdentity":{"arn":"arn:aws:iam::1:user/u"},
        "createdDateTime":"2026-08-16T09:00:00Z",
        "published":"2026-08-16T09:00:00Z",
        "userPrincipalName":"u@x", "userId":"u",
        "appId":"a", "appDisplayName":"A",
    }]
    events = await adapter.normalise(raw)
    assert events
    canonical_fields = set(CanonicalEvent.__dataclass_fields__.keys())
    top_level_keys = set(events[0].__dict__.keys())
    # Every top-level key must be part of the canonical dataclass.
    assert top_level_keys.issubset(canonical_fields)


# ---------- Capability declarations are honest --------------------------
@pytest.mark.parametrize("adapter", [
    OktaSystemLogAdapter(), EntraSignInLogAdapter(),
    AwsCloudTrailAdapter(),
])
def test_adapter_capability_is_declared_honestly(adapter):
    cap = adapter.declares()
    assert cap.provides, "adapter must declare what it provides"
    # No overlap: an adapter can't both provide and not-provide the same signal.
    assert set(cap.provides).isdisjoint(cap.does_not_provide)


# ---------- Provenance is mandatory -------------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize("adapter", [
    OktaSystemLogAdapter(), EntraSignInLogAdapter(),
    AwsCloudTrailAdapter(),
])
async def test_every_event_carries_provenance(adapter):
    # Feed minimal shape per adapter.
    raw = [{"uuid":"a","id":"a","eventID":"a",
                  "eventType":"user.session.start",
                  "eventName":"X","eventSource":"s",
                  "userIdentity":{"arn":"arn:aws:iam::1:user/u"}}]
    events = await adapter.normalise(raw)
    assert events
    for ev in events:
        assert ev.provenance is not None
        assert ev.provenance.source_id
        assert ev.provenance.vendor
        assert ev.provenance.adapter_name == adapter.name
        assert ev.provenance.adapter_version == adapter.version
        assert ev.provenance.raw_ref
        assert ev.provenance.ingested_at
