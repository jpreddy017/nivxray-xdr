"""D15 · Snort tenant contract + declared source routing.

Two things are held here, because they are one trust boundary:

1.  Snort EVE joins the D14 tenant contract. The authenticated delivery is
    the only authority on ownership for EVERY supported source — snort-eve
    was the last one outside it.

2.  Routing is DECLARED, never guessed:

        authenticated collector identity
          → the collector's server-side authorized source set
          → this delivery's explicit declaration
          → declaration / allowlist validation
          → DSM selection
          → content compatibility validation
          → canonical evidence

    Content may VALIDATE a declaration. It may never select a DSM, never
    override a declaration and never rescue one. Registry ordering is not
    an authority: before D15 a payload that happened to satisfy an earlier
    DSM's `supports()` was interpreted by that DSM.

Every disagreement is a refusal with the reason recorded, and no refusal
produces canonical evidence.

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Nothing live, nothing
production.
"""
from __future__ import annotations

import asyncio
import os

import pytest
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_pipeline import (DSM_REGISTRY, SnortEveParser,
                                            SnortNormalizer,
                                            process_event_through_pipeline)
from routers.xdr_ingest import (CanonicalEnvelope, TRANSPORT_NS,
                                _document_for_pipeline,
                                _raw_event_for_pipeline, route_batch)
from services import source_routing as sr
from services import tenant_authority

TEST_DB = "nivx_d15_routing_test"
TEN = "t-d15-owner"
VICTIM = "t-d15-victim"
COL = "col-d15"

SNORT_DOC = {"event_type": "alert", "timestamp": "2026-06-01T10:00:00+00:00",
             "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9", "proto": "TCP",
             "alert": {"signature_id": 2027865, "signature": "ET SCAN"}}
WINDOWS_DOC = {
    "EventID": 4624, "provider": "Microsoft-Windows-Security-Auditing",
    "channel": "Security", "Computer": "WIN-DC-01",
    "TimeCreated": "2026-06-01T10:00:00+00:00",
    "EventData": {"TargetUserName": "svc_backup", "LogonType": "3",
                  "IpAddress": "10.0.0.9"}}
SYSMON_DOC = {
    "EventID": 1, "provider": "Microsoft-Windows-Sysmon",
    "Computer": "WIN-WS-07", "User": "CORP\\dev1",
    "UtcTime": "2026-06-01T10:00:00+00:00",
    "Image": "C:\\Windows\\System32\\cmd.exe",
    "CommandLine": "cmd /c whoami", "ProcessId": "4321"}
CLOUDTRAIL_DOC = {
    "eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com",
    "eventTime": "2026-06-01T10:00:00Z", "awsRegion": "us-east-1",
    "eventID": "ct-d15-1", "sourceIPAddress": "203.0.113.7",
    "userIdentity": {"type": "IAMUser", "userName": "dev1",
                     "accountId": "111122223333"}}
AUDITD_LINE = ('node=web-prod-04 type=SYSCALL msg=audit(1757452888.777:9101): '
               'arch=c000003e syscall=59 uid=0 euid=0 comm="bash" '
               'exe="/usr/bin/bash" key="exec"')
CEF_LINE = ("CEF:0|NivX|Firewall|1.0|100|Blocked|5|src=10.0.0.4 "
            "dst=198.51.100.2 spt=443 devTime=1780308000000")

DOCUMENTS = {"snort-eve": SNORT_DOC,
             "windows-security-evd": WINDOWS_DOC,
             "microsoft-sysmon": SYSMON_DOC,
             "aws-cloudtrail": CLOUDTRAIL_DOC}
LINES = {"linux-auditd": AUDITD_LINE, "cef-leef": CEF_LINE}
ALL_SOURCES = sorted(sr.SOURCE_CATALOG)


def envelope(raw: dict, *, declared: str | None, tenant=TEN, collector=COL,
             **over) -> CanonicalEnvelope:
    body = {"tenant_id": tenant, "collector_id": collector,
            "collection_method": "rest", "source": "d15-host",
            "declared_source": declared, "raw": raw}
    body.update(over)
    return CanonicalEnvelope(**body)


def route_one(env: CanonicalEnvelope, *, authorized: list[str]):
    routed, blocked, rows = route_batch(
        [env], authorized=authorized, tenant_id=env.tenant_id,
        collector_id=env.collector_id, nivx_received_at="2026-06-01T10:00:03Z")
    return routed, blocked, rows


# ══ 1 · the happy path is the DECLARED path ═══════════════════════
@pytest.mark.parametrize("dsm_id", sorted(DOCUMENTS))
def test_authorized_declaration_with_matching_content_is_accepted(dsm_id):
    routed, blocked, rows = route_one(
        envelope(DOCUMENTS[dsm_id], declared=dsm_id), authorized=ALL_SOURCES)
    assert not blocked and not rows
    decision = routed[0][1]
    assert decision["routing_result"] == sr.ACCEPTED
    assert decision["selected_dsm_id"] == dsm_id
    assert decision["routing_authority"] == sr.DECLARED_AUTHORITY
    assert decision["content_compatible"] is True


@pytest.mark.parametrize("dsm_id,line", sorted(LINES.items()))
def test_line_sources_are_routed_by_declaration_too(dsm_id, line):
    routed, blocked, _ = route_one(
        envelope({"line": line}, declared=dsm_id), authorized=ALL_SOURCES)
    assert not blocked
    assert routed[0][1]["selected_dsm_id"] == dsm_id


def test_a_mixed_batch_routes_each_envelope_by_its_own_declaration():
    envs = ([envelope(DOCUMENTS[d], declared=d) for d in sorted(DOCUMENTS)]
            + [envelope({"line": ln}, declared=d)
               for d, ln in sorted(LINES.items())])
    routed, blocked, _ = route_batch(envs, authorized=ALL_SOURCES,
                                     tenant_id=TEN, collector_id=COL)
    assert not blocked
    assert [d["selected_dsm_id"] for _e, d in routed] == \
        sorted(DOCUMENTS) + sorted(LINES)


def test_one_bad_declaration_in_a_batch_blocks_only_itself():
    envs = [envelope(WINDOWS_DOC, declared="windows-security-evd"),
            envelope(CLOUDTRAIL_DOC, declared="linux-auditd"),
            envelope({"line": CEF_LINE}, declared="cef-leef")]
    routed, blocked, rows = route_batch(envs, authorized=ALL_SOURCES,
                                        tenant_id=TEN, collector_id=COL)
    assert [d["selected_dsm_id"] for _e, d in routed] == \
        ["windows-security-evd", "cef-leef"]
    assert len(blocked) == len(rows) == 1
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH


# ══ 2 · every refusal, with its OWN distinct reason ════════════════
def test_a_missing_declaration_is_declaration_required_not_a_mismatch():
    _routed, blocked, rows = route_one(
        envelope(WINDOWS_DOC, declared=None), authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.DECLARATION_REQUIRED
    assert blocked[0].mismatch_reason != sr.SOURCE_FORMAT_MISMATCH
    assert rows[0]["routing"]["selected_dsm_id"] is None


@pytest.mark.parametrize("declared", ["", "   ", "\t"])
def test_a_blank_declaration_is_also_declaration_required(declared):
    _routed, blocked, _ = route_one(
        envelope(WINDOWS_DOC, declared=declared), authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.DECLARATION_REQUIRED


@pytest.mark.parametrize("declared", ["totally-unknown", "windows-secutiry",
                                      "crowdstrike-falcon", "../linux-auditd"])
def test_an_unknown_declaration_is_unsupported_source(declared):
    _routed, blocked, _ = route_one(
        envelope(WINDOWS_DOC, declared=declared), authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.UNSUPPORTED_SOURCE


def test_a_declaration_outside_the_collectors_allowlist_is_refused():
    _routed, blocked, rows = route_one(
        envelope(CLOUDTRAIL_DOC, declared="aws-cloudtrail"),
        authorized=["linux-auditd"])
    assert blocked[0].mismatch_reason == sr.SOURCE_NOT_AUTHORIZED
    assert rows[0]["routing"]["collector_authorized_sources"] == \
        ["linux-auditd"]


def test_collector_a_cannot_send_what_only_collector_b_is_authorized_for():
    # Same authenticated tenant, same valid payload, same valid declaration —
    # only the collector's registered authorization differs.
    payload = envelope(CLOUDTRAIL_DOC, declared="aws-cloudtrail")
    b_routed, b_blocked, _ = route_one(payload,
                                       authorized=["aws-cloudtrail"])
    a_routed, a_blocked, _ = route_one(payload, authorized=["linux-auditd"])
    assert b_routed and not b_blocked
    assert a_blocked and not a_routed
    assert a_blocked[0].mismatch_reason == sr.SOURCE_NOT_AUTHORIZED


def test_an_empty_allowlist_authorizes_nothing_not_everything():
    for dsm_id, doc in DOCUMENTS.items():
        _routed, blocked, _ = route_one(envelope(doc, declared=dsm_id),
                                        authorized=[])
        assert blocked[0].mismatch_reason == sr.SOURCE_NOT_AUTHORIZED, dsm_id
    assert sr.authorized_sources({}) == []
    assert sr.authorized_sources({"authorized_sources": None}) == []
    assert sr.authorized_sources(None) == []


def test_a_declaration_naming_an_unloaded_dsm_fails_closed(monkeypatch):
    monkeypatch.setitem(sr.SOURCE_CATALOG, "ghost-source", "ghost-dsm")
    _routed, blocked, _ = route_one(
        envelope(WINDOWS_DOC, declared="ghost-source"),
        authorized=["ghost-source"])
    assert blocked[0].mismatch_reason == sr.SOURCE_DSM_UNAVAILABLE


# ══ 3 · cross-parser confusion — content never reroutes ═══════════
CONFUSION = [
    # a document crafted to resemble another DSM
    ("windows-security-evd", SYSMON_DOC, ["microsoft-sysmon"]),
    ("microsoft-sysmon", WINDOWS_DOC, ["windows-security-evd"]),
    # Snort EVE delivered under the wrong declaration
    ("linux-auditd", SNORT_DOC, ["snort-eve"]),
    ("aws-cloudtrail", SNORT_DOC, ["snort-eve"]),
    # CloudTrail under another declaration
    ("snort-eve", CLOUDTRAIL_DOC, ["aws-cloudtrail"]),
]


@pytest.mark.parametrize("declared,payload,recognized", CONFUSION)
def test_content_resembling_another_source_does_not_reroute(
        declared, payload, recognized):
    _routed, blocked, rows = route_one(envelope(payload, declared=declared),
                                       authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    decision = rows[0]["routing"]
    # the DECLARED DSM is still the only one named as selected — the DSM the
    # content resembles is reported as evidence, never as a substitute
    assert decision["selected_dsm_id"] == sr.SOURCE_CATALOG[declared]
    assert decision["content_recognized_as"] == recognized
    assert decision["content_compatible"] is False


def test_cef_content_under_another_declaration_is_refused():
    _routed, blocked, rows = route_one(
        envelope({"line": CEF_LINE}, declared="linux-auditd"),
        authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    assert "cef-leef" in rows[0]["routing"]["content_recognized_as"]


def test_an_auditd_line_under_the_cef_declaration_is_refused():
    _routed, blocked, _ = route_one(
        envelope({"line": AUDITD_LINE}, declared="cef-leef"),
        authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH


def test_a_legitimate_windows_document_carrying_message_still_routes():
    doc = dict(WINDOWS_DOC, message="type=SYSCALL msg=audit(1.1:1): uid=0")
    routed, blocked, _ = route_one(
        envelope(doc, declared="windows-security-evd"),
        authorized=ALL_SOURCES)
    assert not blocked
    assert routed[0][1]["selected_dsm_id"] == "windows-security-evd"
    # content recognition would have offered auditd as well — and it is
    # never consulted for selection
    probe = _raw_event_for_pipeline(envelope(doc, declared=None))
    assert "linux-auditd" in DSM_REGISTRY.recognize(probe)


def test_registry_order_is_not_an_authority():
    # snort-eve sits at registry position 0. A payload it would claim is
    # NOT given to it unless that is what the collector declared.
    ids = [d["id"] for d in DSM_REGISTRY.list()]
    assert ids[0] == "snort-eve", ids
    probe = _raw_event_for_pipeline(envelope(SNORT_DOC, declared=None))
    assert DSM_REGISTRY.recognize(probe) == ["snort-eve"]
    _routed, blocked, _ = route_one(
        envelope(SNORT_DOC, declared="windows-security-evd"),
        authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH


def test_misleading_source_and_timestamp_fields_change_nothing():
    doc = dict(CLOUDTRAIL_DOC, source="linux-auditd",
               payload_format="auditd", timestamp="2026-06-01T10:00:00Z")
    _routed, blocked, _ = route_one(
        envelope(doc, declared="linux-auditd", source="cef-leef"),
        authorized=ALL_SOURCES)
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    routed, blocked2, _ = route_one(
        envelope(doc, declared="aws-cloudtrail", source="linux-auditd"),
        authorized=ALL_SOURCES)
    assert not blocked2
    assert routed[0][1]["selected_dsm_id"] == "aws-cloudtrail"


# ══ 4 · the catalog and the allowlist contract ════════════════════
def test_every_declared_source_names_exactly_one_loaded_dsm():
    loaded = {d["id"] for d in DSM_REGISTRY.list()}
    for declared, dsm_id in sr.SOURCE_CATALOG.items():
        assert dsm_id in loaded, (declared, dsm_id)
        assert DSM_REGISTRY.get(dsm_id) is not None


def test_aliases_can_only_narrow_never_widen():
    for alias, target in sr.SOURCE_ALIASES.items():
        assert target in sr.SOURCE_CATALOG, alias
        assert sr.canonical_source(alias) == target
        assert sr.canonical_source(alias.upper()) == target


def test_an_unknown_allowlist_entry_is_reported_not_dropped():
    keys, unknown = sr.normalize_declarations(
        ["linux-auditd", "not-a-source", "cef"])
    assert keys == ["linux-auditd", "cef-leef"]
    assert unknown == ["not-a-source"]


def test_a_registry_get_miss_is_none_not_a_nearby_dsm():
    assert DSM_REGISTRY.get("nope-not-loaded") is None


# ══ 5 · Snort joins the D14 tenant contract ═══════════════════════
def _snort_canonical(tenant, payload=None):
    parsed = SnortEveParser().parse(dict(payload or SNORT_DOC))
    return SnortNormalizer().normalize(parsed, "snort-eve", COL, "int-d15",
                                       "trace-d15", tenant_id=tenant)


def test_snort_evidence_is_owned_by_the_authenticated_tenant():
    out = _snort_canonical(TEN)
    assert out["tenant_id"] == TEN


@pytest.mark.parametrize("tenant", [None, "", "   "])
def test_snort_refuses_to_normalize_without_an_authenticated_tenant(tenant):
    with pytest.raises(tenant_authority.TenantAuthorityError):
        _snort_canonical(tenant)


def test_snort_never_defaults_to_the_default_tenant():
    import inspect
    sig = inspect.signature(SnortNormalizer().normalize)
    assert sig.parameters["tenant_id"].default is None


def test_a_snort_payload_claiming_another_tenant_is_recorded_not_believed():
    doc = dict(SNORT_DOC, tenant_id=VICTIM)
    env = envelope(doc, declared="snort-eve")
    # the ingest boundary withholds the source tenant_id …
    document = _document_for_pipeline(env)
    assert "tenant_id" not in document
    assert document[TRANSPORT_NS]["source_fields_withheld"]["tenant_id"] \
        == VICTIM
    # … and the normalizer records it as an untrusted claim, unused
    out = _snort_canonical(TEN, document)
    claim = out["additional_fields"]["tenant_claim"]
    assert out["tenant_id"] == TEN
    assert claim["state"] == tenant_authority.UNTRUSTED_SOURCE_CLAIM
    assert claim["claimed_tenant_id"] == VICTIM
    assert claim["used"] is False
    assert claim["agrees_with_authenticated"] is False
    assert claim["claim_source"]


def test_every_dsm_normalizer_takes_the_authenticated_tenant_explicitly():
    import inspect
    for entry in DSM_REGISTRY.list():
        dsm = DSM_REGISTRY.get(entry["id"])
        params = inspect.signature(dsm.select_normalizer().normalize).parameters
        assert "tenant_id" in params, entry["id"]
        assert params["tenant_id"].default in (None,
                                               inspect.Parameter.empty), \
            entry["id"]


# ══ 6 · the pipeline obeys the routing decision ═══════════════════
def _run(raw_event, *, routing, tenant=TEN):
    async def _go():
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[TEST_DB]
        try:
            res = await process_event_through_pipeline(
                db, raw_event, "trace-d15", integration_id="int-d15",
                collector_id=COL, tenant_id=tenant, routing=routing)
            stored = await db["xdr_canonical_evidence"].count_documents({})
            return res, stored
        finally:
            await client.drop_database(TEST_DB)
            client.close()

    return asyncio.run(_go())


def _accepted(dsm_id, declared):
    return {"routing_result": sr.ACCEPTED,
            "routing_authority": sr.DECLARED_AUTHORITY,
            "declared_source": declared, "declared_source_resolved": declared,
            "collector_authorized_sources": [declared],
            "selected_dsm_id": dsm_id, "content_compatible": True,
            "content_recognized_as": None, "mismatch_reason": None,
            "reason": "test"}


def test_the_declared_dsm_interprets_the_event_and_the_decision_is_recorded():
    env = envelope(SNORT_DOC, declared="snort-eve")
    res, stored = _run(_raw_event_for_pipeline(env),
                       routing=_accepted("snort-eve", "snort-eve"))
    assert res.get("blocker") in (None, "incident_gate"), res
    canonical = res["canonical"]
    assert canonical["tenant_id"] == TEN
    routing = canonical["provenance"]["routing"]
    assert routing["routing_authority"] == sr.DECLARED_AUTHORITY
    assert routing["declared_source"] == "snort-eve"
    assert routing["selected_dsm_id"] == "snort-eve"
    assert routing["routing_result"] == sr.ACCEPTED
    assert stored == 1


def test_the_pipeline_never_reroutes_when_the_declared_parser_refuses():
    # A snort document handed to the windows parser must FAIL honestly.
    # Nothing is re-resolved by content, and no evidence is produced.
    env = envelope(SNORT_DOC, declared="windows-security-evd")
    res, stored = _run(_raw_event_for_pipeline(env),
                       routing=_accepted("windows-security-evd",
                                         "windows-security-evd"))
    assert res["blocker"] == "parser"
    assert "canonical" not in res
    assert stored == 0
    assert [s["stage"] for s in res["stages"]] == ["dsm", "parser"]


def test_a_routing_decision_naming_an_unloaded_dsm_produces_no_evidence():
    env = envelope(SNORT_DOC, declared="snort-eve")
    res, stored = _run(_raw_event_for_pipeline(env),
                       routing=_accepted("ghost-dsm", "snort-eve"))
    assert res["blocker"] == "dsm"
    assert "canonical" not in res
    assert stored == 0
    assert res["stages"][0]["mismatch_reason"] == sr.SOURCE_DSM_UNAVAILABLE


def test_an_internal_caller_is_labelled_as_such_never_as_declared():
    env = envelope(SNORT_DOC, declared=None)
    res, _stored = _run(_raw_event_for_pipeline(env), routing=None)
    routing = res["canonical"]["provenance"]["routing"]
    assert routing["routing_authority"] == sr.CONTENT_RESOLVED_INTERNAL
    assert routing["declared_source"] is None
    assert routing["selected_dsm_id"] == "snort-eve"


# ══ 7 · a refused delivery leaves nothing behind ══════════════════
BLOCKED_CASES = [
    (None, WINDOWS_DOC, ALL_SOURCES, sr.DECLARATION_REQUIRED),
    ("unknown-source", WINDOWS_DOC, ALL_SOURCES, sr.UNSUPPORTED_SOURCE),
    ("aws-cloudtrail", CLOUDTRAIL_DOC, ["linux-auditd"],
     sr.SOURCE_NOT_AUTHORIZED),
    ("linux-auditd", SNORT_DOC, ALL_SOURCES, sr.SOURCE_FORMAT_MISMATCH),
]


@pytest.mark.parametrize("declared,payload,authorized,code", BLOCKED_CASES)
def test_a_blocked_delivery_is_never_routed_onward(declared, payload,
                                                   authorized, code):
    routed, blocked, rows = route_one(envelope(payload, declared=declared),
                                      authorized=authorized)
    assert routed == []
    assert len(blocked) == len(rows) == 1
    assert blocked[0].status == "BLOCKED"
    assert blocked[0].blocker == "source_routing"
    assert blocked[0].mismatch_reason == code
    assert blocked[0].routing_result == sr.BLOCKED


@pytest.mark.parametrize("declared,payload,authorized,code", BLOCKED_CASES)
def test_the_refusal_keeps_the_evidence_an_auditor_needs(declared, payload,
                                                         authorized, code):
    _routed, _blocked, rows = route_one(envelope(payload, declared=declared),
                                        authorized=authorized)
    row = rows[0]
    assert row["tenant_id"] == TEN
    assert row["collector_id"] == COL
    assert row["payload_shape"] == "DOCUMENT"
    assert row["payload_keys"] == sorted(payload)
    decision = row["routing"]
    for field in ("routing_result", "routing_authority", "declared_source",
                  "declared_source_resolved", "collector_authorized_sources",
                  "selected_dsm_id", "content_compatible",
                  "content_recognized_as", "mismatch_reason", "reason"):
        assert field in decision, field
    assert decision["mismatch_reason"] == code
    assert decision["routing_result"] == sr.BLOCKED


def test_no_secret_material_is_written_into_routing_evidence():
    env = envelope(dict(WINDOWS_DOC), declared=None,
                   parser_version="1.2.3", connector_id="conn-1")
    _routed, _blocked, rows = route_one(env, authorized=ALL_SOURCES)
    blob = repr(rows[0])
    for forbidden in ("Authorization", "X-XDR-API-Key", "api_key", "nvx_",
                      "password", "secret"):
        assert forbidden not in blob, forbidden
