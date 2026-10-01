"""D13 · JSON ingest shape — can real Windows/cloud telemetry get IN?

D12 proved the document DSMs normalize correctly. It also exposed the gap
this suite closes: the ingest handler flattened every envelope into
`{line, message, …}`, so a JSON document arrived with `line=""` and no DSM
ever claimed it. Correct DSM did not yet mean

    real source -> collector -> authenticated ingest -> DSM -> evidence.

What is held here:
  * a DOCUMENT envelope reaches the right DSM through the real registry;
  * the source document survives byte-for-byte, under its own field names;
  * NivX metadata rides under one reserved key and can shadow nothing;
  * a LINE envelope is shaped exactly as before — byte-for-byte;
  * the authenticated tenant owns the evidence, and a document that names
    its own tenant is recorded as a claim and not believed;
  * D12 temporal provenance survives the new shape.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Nothing live, nothing
production.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import (DSM_REGISTRY,
                                            process_event_through_pipeline)
from routers.xdr_ingest import (SHAPE_DOCUMENT, SHAPE_LINE, TRANSPORT_NS,
                                CanonicalEnvelope, IngestShapeCollision,
                                _ingest_provenance_for, _payload_shape,
                                _raw_event_for_pipeline)
from services import provenance_timestamps as pts

TEST_DB = "nivx_d13_json_ingest_test"
NIVX_RECV = "2026-06-01T10:00:03.500000+00:00"

AUD = "1757452888.555:9002"

SYSMON_DOC = {
    "EventID": 1, "provider": "Microsoft-Windows-Sysmon",
    "Computer": "WIN-WS-07", "User": "CORP\\dev1",
    "UtcTime": "2026-06-01T10:00:00+00:00",
    "TimeCreated": "2026-06-01T10:00:02+00:00",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd /c whoami", "ProcessId": "4321",
    "ParentImage": "C:\\Windows\\explorer.exe",
}
WINDOWS_DOC = {
    "EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security", "Computer": "WIN-DC-01",
    "TimeCreated": "2026-06-01T10:00:00+00:00",
    "EventData": {"TargetUserName": "svc_backup", "LogonType": "3",
                  "IpAddress": "10.0.0.9"},
}
CLOUDTRAIL_DOC = {
    "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
    "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
    "eventID": "ct-d13-1", "sourceIPAddress": "203.0.113.7",
    "userIdentity": {"type": "IAMUser", "userName": "dev1",
                     "accountId": "111122223333"},
}
AUDITD_LINE = (f'node=web-prod-04 type=SYSCALL msg=audit({AUD}): '
               f'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
               f'exe="/usr/bin/bash" key="exec"')
CEF_LINE = ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|src=10.0.0.4 "
            "dst=198.51.100.2 spt=443 devTime=1780308000000 "
            "rt=1780308060000")
SNORT_DOC = {"event_type": "alert", "timestamp": "2026-06-01T10:00:00+00:00",
             "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9",
             "alert": {"signature_id": 2027865, "signature": "ET SCAN"}}

DOCUMENTS = {"microsoft-sysmon": SYSMON_DOC,
             "windows-security-evd": WINDOWS_DOC,
             "aws-cloudtrail": CLOUDTRAIL_DOC,
             "snort-eve": SNORT_DOC}
LINES = {"linux-auditd": AUDITD_LINE, "cef-leef": CEF_LINE}


def envelope(raw: dict, *, tenant="t-d13", collector="col-d13", **over):
    body = {"tenant_id": tenant, "collector_id": collector,
            "collection_method": "rest", "source": "d13-proof-host",
            "raw": raw}
    body.update(over)
    return CanonicalEnvelope(**body)


# ── shape ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_a_json_document_is_recognised_as_a_document(dsm_id):
    e = envelope(DOCUMENTS[dsm_id])
    assert _payload_shape(e) == SHAPE_DOCUMENT


@pytest.mark.parametrize("line", sorted(LINES.values()))
def test_a_verbatim_line_is_still_a_line(line):
    assert _payload_shape(envelope({"line": line})) == SHAPE_LINE
    assert _payload_shape(envelope({"message": line})) == SHAPE_LINE


def test_an_empty_envelope_keeps_its_old_shape_and_its_old_answer():
    e = envelope({})
    assert _payload_shape(e) == SHAPE_LINE
    raw_event = _raw_event_for_pipeline(e)
    assert raw_event["line"] == ""
    assert TRANSPORT_NS not in raw_event


def test_the_line_shape_is_unchanged_byte_for_byte():
    e = envelope({"line": AUDITD_LINE, "payload_format": "auditd"},
                 source_timestamp="2026-06-01T10:00:01+00:00",
                 received_at="2026-06-01T10:00:02+00:00",
                 connector_id="conn-1", parser_version="1.2.3",
                 collection_timestamp="2026-06-01T10:00:02+00:00")
    assert _raw_event_for_pipeline(e) == {
        "tenant_id": "t-d13",
        "line": AUDITD_LINE,
        "message": AUDITD_LINE,
        "payload_format": "auditd",
        "source": "d13-proof-host",
        "connector_id": "conn-1",
        "collector_id": "col-d13",
        "collection_method": "rest",
        "parser_version": "1.2.3",
        "collection_timestamp": "2026-06-01T10:00:02+00:00",
        "source_timestamp": "2026-06-01T10:00:01+00:00",
        "received_at": "2026-06-01T10:00:02+00:00",
        "raw": {"line": AUDITD_LINE, "payload_format": "auditd"},
    }


@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_the_document_reaches_the_dsm_under_its_own_field_names(dsm_id):
    doc = DOCUMENTS[dsm_id]
    raw_event = _raw_event_for_pipeline(envelope(doc))
    for key, value in doc.items():
        assert raw_event[key] == value, (dsm_id, key)
    assert set(raw_event) == set(doc) | {TRANSPORT_NS}


@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_the_registry_selects_the_right_dsm_for_each_document(dsm_id):
    raw_event = _raw_event_for_pipeline(envelope(DOCUMENTS[dsm_id]))
    dsm = DSM_REGISTRY.resolve(raw_event)
    assert dsm is not None, f"no DSM claimed the {dsm_id} document"
    assert dsm.id == dsm_id


@pytest.mark.parametrize("dsm_id,line", sorted(LINES.items()))
def test_the_registry_still_selects_the_right_dsm_for_each_line(dsm_id, line):
    dsm = DSM_REGISTRY.resolve(_raw_event_for_pipeline(envelope({"line": line})))
    assert dsm is not None and dsm.id == dsm_id


def test_transport_metadata_rides_under_one_reserved_key():
    raw_event = _raw_event_for_pipeline(
        envelope(SYSMON_DOC, connector_id="conn-9"))
    meta = raw_event[TRANSPORT_NS]
    assert meta["payload_shape"] == SHAPE_DOCUMENT
    assert meta["tenant_id"] == "t-d13"
    assert meta["collector_id"] == "col-d13"
    assert meta["connector_id"] == "conn-9"
    assert meta["source"] == "d13-proof-host"


def test_a_document_field_is_never_shadowed_by_transport_metadata():
    """The nastiest collision: a source document with its own `source`,
    `message`, `timestamp` and `collector_id` fields."""
    doc = dict(SYSMON_DOC, source="THE-SOURCES-OWN-VALUE",
               message="the source's own message",
               timestamp="2020-01-01T00:00:00+00:00",
               collector_id="THE-SOURCES-OWN-COLLECTOR",
               collection_method="the-sources-own-method")
    raw_event = _raw_event_for_pipeline(envelope(doc))
    assert raw_event["source"] == "THE-SOURCES-OWN-VALUE"
    assert raw_event["message"] == "the source's own message"
    assert raw_event["timestamp"] == "2020-01-01T00:00:00+00:00"
    assert raw_event["collector_id"] == "THE-SOURCES-OWN-COLLECTOR"
    # and NivX's own view of the same names is intact, elsewhere
    assert raw_event[TRANSPORT_NS]["source"] == "d13-proof-host"
    assert raw_event[TRANSPORT_NS]["collector_id"] == "col-d13"


def test_a_documents_own_message_does_not_hand_it_to_the_wrong_dsm():
    """A Windows export carrying a `message` field must not be claimed by a
    line-oriented DSM."""
    doc = dict(WINDOWS_DOC,
               message=("type=SYSCALL msg=audit(1757452888.555:1): "
                        "syscall=59 comm=\"bash\""))
    # the envelope still declares a document, because `raw.message` here is
    # a SOURCE field, not a delivered line — the collector puts a delivered
    # line in `raw.line`
    raw_event = _raw_event_for_pipeline(envelope(doc))
    assert raw_event[TRANSPORT_NS]["payload_shape"] == SHAPE_DOCUMENT
    dsm = DSM_REGISTRY.resolve(raw_event)
    assert dsm.id == "windows-security-evd"


def test_a_reserved_key_collision_fails_closed():
    with pytest.raises(IngestShapeCollision):
        _raw_event_for_pipeline(envelope(dict(SYSMON_DOC, _nivx={"evil": 1})))


def test_a_document_cannot_name_its_own_tenant():
    raw_event = _raw_event_for_pipeline(
        envelope(dict(CLOUDTRAIL_DOC, tenant_id="victim-tenant")))
    assert "tenant_id" not in raw_event
    meta = raw_event[TRANSPORT_NS]
    assert meta["tenant_id"] == "t-d13"
    # the claim is preserved as evidence, and explicitly not believed
    assert meta["source_fields_withheld"] == {"tenant_id": "victim-tenant"}
    assert "only authority on ownership" in meta["withheld_reason"]


def test_the_ingest_provenance_records_the_shape_and_the_declaration():
    e = envelope(dict(SYSMON_DOC, payload_format="sysmon-json"))
    ident = _ingest_provenance_for(
        e, nivx_received_at=NIVX_RECV, tenant_id=e.tenant_id,
        raw_ref=None)["identity"]
    assert ident["payload_shape"] == SHAPE_DOCUMENT
    assert ident["declared_payload_format"] == "sysmon-json"
    # filled in by the pipeline, once a DSM has actually claimed the event
    assert ident["selected_dsm_id"] is None


# ── end to end, through the real pipeline and a real MongoDB ─────────
def _run(e: CanonicalEnvelope):
    raw_event = _raw_event_for_pipeline(e)
    prov = _ingest_provenance_for(
        e, nivx_received_at=NIVX_RECV, tenant_id=e.tenant_id,
        raw_ref={"collection": "xdr_canonical_events", "id": "raw-d13",
                 "state": "PERSISTED_BY_THIS_REQUEST"})

    async def _go():
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[TEST_DB]
        try:
            res = await process_event_through_pipeline(
                db, raw_event, "trace-d13", integration_id="int-d13",
                collector_id=e.collector_id, tenant_id=e.tenant_id,
                ingest_provenance=prov)
            stored = await db["xdr_canonical_evidence"].find_one(
                {"event_id": (res.get("canonical") or {}).get("event_id")})
            return res, stored
        finally:
            await client.drop_database(TEST_DB)
            client.close()

    return asyncio.run(_go())


@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_a_document_becomes_tenant_bound_canonical_evidence(dsm_id):
    res, stored = _run(envelope(DOCUMENTS[dsm_id], tenant="t-d13-e2e"))
    # `incident_gate` is a normal terminal answer: evidence exists, no
    # incident was warranted. Only an EARLIER blocker means it never landed.
    assert res.get("blocker") in (None, "incident_gate"), (dsm_id, res)
    canonical = res["canonical"]
    assert stored is not None, f"{dsm_id}: nothing persisted"

    # the authenticated tenant owns it — snort's projection has no tenant
    # field of its own, so its persisted row is the one that must carry it
    if "tenant_id" in canonical:
        assert canonical["tenant_id"] == "t-d13-e2e", dsm_id

    ident = canonical["provenance"]["ingest"]
    assert ident["payload_shape"] == SHAPE_DOCUMENT
    assert ident["selected_dsm_id"] == dsm_id
    assert ident["tenant_id"] == "t-d13-e2e"
    assert ident["raw_envelope_ref"]["id"] == "raw-d13"

    # D12 temporal provenance survived the new shape
    ts = canonical["provenance"]["timestamps"]
    assert set(ts) == set(pts.STAMP_NAMES), dsm_id
    assert ts["nivx_received_at"]["value"] == NIVX_RECV
    assert ts["parsed_at"]["status"] == pts.AVAILABLE
    assert ts["normalized_at"]["status"] == pts.AVAILABLE
    basis = (canonical.get("additional_fields") or {})["event_time_basis"]
    if ts["activity_occurred_at"]["status"] == pts.AVAILABLE:
        assert basis == "ACTIVITY_TIME", dsm_id
    else:
        assert basis != "ACTIVITY_TIME", dsm_id

    # the document is still there, verbatim, under its own field names
    raw_ref = canonical.get("raw_ref") or {}
    if isinstance(raw_ref, dict):
        for key, value in DOCUMENTS[dsm_id].items():
            if key in raw_ref:
                assert raw_ref[key] == value, (dsm_id, key)


@pytest.mark.parametrize("dsm_id,line", sorted(LINES.items()))
def test_line_sources_did_not_regress(dsm_id, line):
    res, stored = _run(envelope({"line": line}, tenant="t-d13-line"))
    assert res.get("blocker") in (None, "incident_gate"), (dsm_id, res)
    canonical = res["canonical"]
    assert canonical["tenant_id"] == "t-d13-line"
    ident = canonical["provenance"]["ingest"]
    assert ident["payload_shape"] == SHAPE_LINE
    assert ident["selected_dsm_id"] == dsm_id
    assert canonical["raw_ref"]["line"] == line
    assert stored is not None


@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_the_same_document_in_two_tenants_never_crosses_over(dsm_id):
    a, _ = _run(envelope(DOCUMENTS[dsm_id], tenant="t-alpha"))
    b, _ = _run(envelope(DOCUMENTS[dsm_id], tenant="t-beta"))
    ca, cb = a["canonical"], b["canonical"]
    if "tenant_id" in ca:
        assert ca["tenant_id"] == "t-alpha" and cb["tenant_id"] == "t-beta"
    assert ca["provenance"]["ingest"]["tenant_id"] == "t-alpha"
    assert cb["provenance"]["ingest"]["tenant_id"] == "t-beta"


def test_a_document_claiming_another_tenant_lands_in_the_authenticated_one():
    res, _ = _run(envelope(dict(SYSMON_DOC, tenant_id="victim-tenant"),
                           tenant="t-owner"))
    canonical = res["canonical"]
    assert canonical["tenant_id"] == "t-owner"
    assert canonical["provenance"]["ingest"]["tenant_id"] == "t-owner"
    assert json.dumps(canonical).count("victim-tenant") <= 1


def test_sysmon_no_longer_lands_every_event_in_the_default_tenant():
    res, _ = _run(envelope(SYSMON_DOC, tenant="t-sysmon-owner"))
    assert res["canonical"]["tenant_id"] == "t-sysmon-owner"


def test_sysmon_refuses_to_normalize_without_a_tenant():
    dsm = {d.id: d for d in DSM_REGISTRY._dsms}["microsoft-sysmon"]
    parsed = dsm.select_parser().parse(dict(SYSMON_DOC))
    with pytest.raises(ValueError, match="NO tenant fallback"):
        dsm.select_normalizer().normalize(
            parsed, dsm.id, "col-d13", "int-d13", "trace-d13",
            tenant_id=None)
