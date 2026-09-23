"""B4 · Raw forensic retention + the refusal-semantics split.

The G1 Windows Security investigation could name the MECHANISM of 24 refusals
and not the EventID of a single one, because an AUTHENTICATED,
TENANT-AUTHORIZED, DECLARED delivery was refused and then discarded. Two
defects sat behind that:

1.  a record whose EventID the DSM does not interpret was reported as
    `SOURCE_FORMAT_MISMATCH` — a COVERAGE gap presented as a malformed
    source, which made a healthy Security channel look broken;
2.  nothing of the record survived the refusal, so the evidence needed to
    explain it no longer existed.

These tests hold both corrections, and the invariant that makes retention
safe:

    RAW RETAINED  ≠  PARSED  ≠  NORMALIZED  ≠  EVALUATED  ≠  DETECTED

EVIDENCE LABELLING — TEST/SYNTHETIC throughout. Nothing live, nothing
production. No G1 endpoint state and no historical dead letters are touched.
"""
from __future__ import annotations

import os

import pytest

from detection_content.telemetry import evtx_xml
from detection_content.xdr_pipeline import DSM_REGISTRY
from routers.xdr_ingest import CanonicalEnvelope, route_batch
from services import ingest_idempotency as idem
from services import raw_forensic_retention as b4
from services import source_routing as sr

TEN = "ten_b4_synthetic_owner"
OTHER_TEN = "ten_b4_synthetic_victim"
COL = "col-b4-synthetic"
WINDOWS_SOURCES = ["windows-security-evd", "microsoft-sysmon",
                   "windows-powershell-evd", "windows-defender-evd"]


def _xml(*, provider: str, event_id: int, channel: str,
         record_id: int = 1000, data: str = "") -> str:
    body = data or "<EventData><Data Name='X'>1</Data></EventData>"
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><Provider Name='{provider}'/><EventID>{event_id}</EventID>"
        "<Version>0</Version><Level>4</Level><Task>0</Task>"
        "<TimeCreated SystemTime='2026-06-01T12:00:00.1234567Z'/>"
        f"<EventRecordID>{record_id}</EventRecordID>"
        "<Execution ProcessID='4' ThreadID='8'/>"
        f"<Channel>{channel}</Channel><Computer>WIN-B4-LAB</Computer>"
        "<Security UserID='S-1-5-18'/></System>"
        f"{body}"
        "</Event>")


SEC_SUPPORTED = _xml(provider="Microsoft-Windows-Security-Auditing",
                     event_id=4624, channel="Security", record_id=239165,
                     data=("<EventData>"
                           "<Data Name='SubjectUserSid'>S-1-5-18</Data>"
                           "<Data Name='TargetUserName'>svc_b4</Data>"
                           "<Data Name='TargetDomainName'>WIN-B4-LAB</Data>"
                           "<Data Name='LogonType'>3</Data>"
                           "<Data Name='IpAddress'>10.0.0.9</Data>"
                           "</EventData>"))
#: 4798 — "a user's local group membership was enumerated". Real, extremely
#: common on an idle desktop, and outside the DSM's supported set. This is the
#: exact shape of the 24 G1 refusals.
SEC_UNSUPPORTED = _xml(provider="Microsoft-Windows-Security-Auditing",
                       event_id=4798, channel="Security", record_id=239192)
SEC_MALFORMED = SEC_SUPPORTED.replace("</Event>", "")
SYSMON_UNSUPPORTED = _xml(provider="Microsoft-Windows-Sysmon", event_id=10,
                          channel="Microsoft-Windows-Sysmon/Operational",
                          record_id=3286060)
PS_UNSUPPORTED = _xml(provider="Microsoft-Windows-PowerShell", event_id=40961,
                      channel="Microsoft-Windows-PowerShell/Operational",
                      record_id=77)
DEF_UNSUPPORTED = _xml(provider="Microsoft-Windows-Windows Defender",
                       event_id=2000,
                       channel=("Microsoft-Windows-Windows "
                                "Defender/Operational"), record_id=42)
SNORT_DOC = {"event_type": "alert", "timestamp": "2026-06-01T12:00:00+00:00",
             "src_ip": "10.0.0.5", "dest_ip": "198.51.100.9", "proto": "TCP",
             "alert": {"signature_id": 2027865, "signature": "ET SCAN"}}


def _delivery(xml: str, channel: str) -> dict:
    """Exactly what the W2-1 Windows adapter delivers."""
    return {"xml": xml, "channel": channel}


def envelope(raw: dict, *, declared: str | None, tenant: str = TEN,
             collector: str = COL, event_id: str | None = None,
             **over) -> CanonicalEnvelope:
    body = {"tenant_id": tenant, "collector_id": collector,
            "collection_method": "windows-eventlog", "source": "b4-host",
            "connector_id": "windows-eventlog-b4", "declared_source": declared,
            "source_event_id": event_id, "raw": raw,
            "source_timestamp": "2026-06-01T12:00:00.1234567Z",
            "collection_timestamp": "2026-06-01T12:00:02+00:00",
            "parser_version": "windows-eventlog/1.0.0"}
    body.update(over)
    return CanonicalEnvelope(**body)


def route_one(env: CanonicalEnvelope, *, authorized=None):
    return route_batch([env], authorized=authorized or WINDOWS_SOURCES,
                       tenant_id=env.tenant_id, collector_id=env.collector_id,
                       nivx_received_at="2026-06-01T12:00:03+00:00")


@pytest.fixture(autouse=True)
def _clean_retention():
    c = b4._coll()                                          # noqa: SLF001
    if c is not None:
        c.delete_many({"tenant_id": {"$in": [TEN, OTHER_TEN]}})
    yield
    if c is not None:
        c.delete_many({"tenant_id": {"$in": [TEN, OTHER_TEN]}})


def _retained(tenant=TEN):
    c = b4._coll()                                          # noqa: SLF001
    return list(c.find({"tenant_id": tenant})) if c is not None else []


# ══ A · a supported event still takes the normal path ══════════════
def test_a_supported_security_event_is_accepted_and_retains_nothing():
    routed, blocked, rows = route_one(
        envelope(_delivery(SEC_SUPPORTED, "Security"),
                 declared="windows_security", event_id="b4-sec-4624"))
    assert not blocked and not rows
    decision = routed[0][1]
    assert decision["routing_result"] == sr.ACCEPTED
    assert decision["selected_dsm_id"] == "windows-security-evd"
    assert decision["content_compatible"] is True
    assert decision["raw_retention_eligible"] is False
    # Acceptance goes down the canonical path; retention is for refusals.
    assert _retained() == []


# ══ B · recognized format, unsupported record type ════════════════
@pytest.mark.parametrize("declared,xml,channel,dsm", [
    ("windows_security", SEC_UNSUPPORTED, "Security",
     "windows-security-evd"),
    ("sysmon", SYSMON_UNSUPPORTED, "Microsoft-Windows-Sysmon/Operational",
     "microsoft-sysmon"),
    ("windows_powershell", PS_UNSUPPORTED,
     "Microsoft-Windows-PowerShell/Operational", "windows-powershell-evd"),
    ("microsoft_defender", DEF_UNSUPPORTED,
     "Microsoft-Windows-Windows Defender/Operational",
     "windows-defender-evd"),
])
def test_b_unsupported_record_is_not_a_format_mismatch(declared, xml,
                                                       channel, dsm):
    _routed, blocked, rows = route_one(
        envelope(_delivery(xml, channel), declared=declared,
                 event_id=f"b4-{dsm}-unsupported"))
    decision = rows[0]["routing"]
    assert blocked[0].mismatch_reason == sr.SOURCE_RECORD_NOT_SUPPORTED
    assert decision["mismatch_reason"] != sr.SOURCE_FORMAT_MISMATCH
    assert decision["selected_dsm_id"] == dsm
    assert decision["content_compatible"] is False
    assert decision["declared_format_recognized"] is True
    assert decision["raw_retention_eligible"] is True


def test_b_unsupported_record_retains_verbatim_raw_and_claims_nothing():
    _routed, _blocked, rows = route_one(
        envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                 declared="windows_security", event_id="b4-sec-4798"))
    row = rows[0]
    assert row["raw_retention"]["state"] == "RETAINED"
    rid = row["retained_raw_id"]
    assert rid and rid.startswith("rr_")

    docs = _retained()
    assert len(docs) == 1
    doc = docs[0]
    # verbatim, byte-for-byte
    assert doc["raw"]["xml"] == SEC_UNSUPPORTED
    assert doc["raw_format"] == "WINDOWS_RENDERED_EVTX_XML"
    # the RCA gap is closed: the EventID is now recoverable server-side
    assert doc["record_hints"]["event_id"] == "4798"
    assert doc["record_hints"]["event_record_id"] == "239192"
    assert doc["record_hints"]["channel"] == "Security"
    assert doc["record_hints"]["extraction"] == "DECODED_FROM_RETAINED_RAW"
    # clocks are kept apart, never merged into one manufactured timestamp
    clocks = doc["clocks"]
    assert clocks["activity_time_declared_by_source"] == \
        "2026-06-01T12:00:00.1234567Z"
    assert clocks["collection_timestamp"] == "2026-06-01T12:00:02+00:00"
    assert clocks["nivx_received_at"] == "2026-06-01T12:00:03+00:00"
    # authority chain
    assert doc["tenant_id"] == TEN and doc["collector_id"] == COL
    assert doc["declared_source_resolved"] == "windows-security-evd"


def test_b_retention_asserts_nothing_about_processing():
    route_one(envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                       declared="windows_security", event_id="b4-sec-disp"))
    disposition = _retained()[0]["disposition"]
    assert disposition["state"] == b4.DISPOSITION_NOT_EVALUATED
    assert disposition["parsed"] is False
    assert disposition["normalized"] is False
    assert disposition["detection_evaluated"] is False
    assert disposition["canonical_evidence_created"] is False
    assert disposition["verdict"] is None
    assert disposition["benign_assertion"] is False
    assert disposition["counts_toward_connected_gate"] is False
    assert disposition["ingest_idempotency_claim_consumed"] is False
    assert disposition["reprocessable_when_coverage_exists"] is True


def test_b_no_canonical_evidence_is_created_for_a_retained_record():
    routed, blocked, _rows = route_one(
        envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                 declared="windows_security", event_id="b4-sec-nocanon"))
    # nothing is routed onward, so nothing can be parsed or normalized
    assert routed == []
    assert blocked[0].status == "BLOCKED"
    assert blocked[0].incident_created is False


# ══ C · an invalid format is still an invalid format ══════════════
def test_c_malformed_security_xml_is_a_format_mismatch_not_unsupported():
    _routed, blocked, rows = route_one(
        envelope(_delivery(SEC_MALFORMED, "Security"),
                 declared="windows_security", event_id="b4-sec-malformed"))
    decision = rows[0]["routing"]
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    assert decision["declared_format_recognized"] is False
    # truthful: the format could not be read, and it is retained anyway so the
    # transport/collection fault can be investigated
    assert decision["raw_retention_eligible"] is True
    doc = _retained()[0]
    assert doc["raw"]["xml"] == SEC_MALFORMED
    assert doc["record_hints"]["event_id"] is None
    assert doc["record_hints"]["extraction"] in ("UNREADABLE",
                                                 "NO_EVENT_ID_PRESENT")


def test_c_a_foreign_payload_under_a_windows_declaration_is_a_mismatch():
    _routed, blocked, rows = route_one(
        envelope(SNORT_DOC, declared="windows_security",
                 event_id="b4-foreign"))
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    assert rows[0]["routing"]["declared_format_recognized"] is False


def test_c_a_security_record_declared_as_powershell_is_a_mismatch():
    """Format recognition is per SOURCE FAMILY, not "is this EVTX"."""
    _routed, blocked, rows = route_one(
        envelope(_delivery(SEC_SUPPORTED, "Security"),
                 declared="windows_powershell", event_id="b4-cross"))
    assert blocked[0].mismatch_reason == sr.SOURCE_FORMAT_MISMATCH
    assert rows[0]["routing"]["declared_format_recognized"] is False


# ══ authority failures retain NOTHING ════════════════════════════
@pytest.mark.parametrize("declared,authorized,code", [
    (None, WINDOWS_SOURCES, sr.DECLARATION_REQUIRED),
    ("nivx-not-a-source", WINDOWS_SOURCES, sr.UNSUPPORTED_SOURCE),
    ("windows_security", ["microsoft-sysmon"], sr.SOURCE_NOT_AUTHORIZED),
])
def test_an_authority_failure_never_retains_raw(declared, authorized, code):
    _routed, blocked, rows = route_one(
        envelope(_delivery(SEC_UNSUPPORTED, "Security"), declared=declared,
                 event_id="b4-authority"), authorized=authorized)
    assert blocked[0].mismatch_reason == code
    assert rows[0]["routing"]["raw_retention_eligible"] is False
    assert rows[0]["retained_raw_id"] is None
    assert rows[0]["raw_retention"]["state"] == "NOT_ELIGIBLE"
    assert _retained() == []


def test_retention_eligibility_vocabulary_is_explicit():
    assert sr.raw_retention_eligible(sr.SOURCE_RECORD_NOT_SUPPORTED)
    assert sr.raw_retention_eligible(sr.SOURCE_FORMAT_MISMATCH)
    assert sr.raw_retention_eligible(sr.SOURCE_DSM_UNAVAILABLE)
    for code in (sr.DECLARATION_REQUIRED, sr.UNSUPPORTED_SOURCE,
                 sr.SOURCE_NOT_AUTHORIZED, None, "ACCEPTED"):
        assert not sr.raw_retention_eligible(code)


# ══ D · a duplicate unsupported delivery retains ONE identity ════
def test_d_repeated_unsupported_delivery_does_not_multiply_evidence():
    env = envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                   declared="windows_security", event_id="b4-sec-dup")
    first = route_one(env)[2][0]
    ids = {first["retained_raw_id"]}
    states = [first["raw_retention"]["state"]]
    for _ in range(4):
        row = route_one(env)[2][0]
        ids.add(row["retained_raw_id"])
        states.append(row["raw_retention"]["state"])
    assert len(ids) == 1                       # ONE forensic identity
    assert states[0] == "RETAINED"
    assert set(states[1:]) == {"ALREADY_RETAINED"}
    docs = _retained()
    assert len(docs) == 1
    assert docs[0]["delivery_count"] == 5
    assert docs[0]["first_seen_at"] <= docs[0]["last_seen_at"]


# ══ E · future coverage can still process the same event ═════════
def test_e_retention_does_not_consume_the_ingest_idempotency_claim():
    """The decisive property: a record refused for missing coverage must be
    processable once coverage exists."""
    env = envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                   declared="windows_security", event_id="b4-sec-future")
    rows = route_one(env)[2]
    assert rows[0]["raw_retention"]["state"] == "RETAINED"

    ident = idem.event_identity(env.tenant_id, env.collector_id, env.source,
                                env.source_event_id, env.raw)
    claim = idem._coll().find_one({"key": ident["key"]})     # noqa: SLF001
    assert claim is None, ("raw retention must take NO idempotency claim, or "
                           "the same delivery would look like a DUPLICATE "
                           "forever")

    # Now simulate coverage arriving for EventID 4798.
    dsm = DSM_REGISTRY.get("windows-security-evd")
    from detection_content.telemetry import windows_security_dsm as wsd
    original = wsd.SUPPORTED_EVENT_IDS
    wsd.SUPPORTED_EVENT_IDS = original + (4798,)
    try:
        routed, blocked, _ = route_one(env)
        assert not blocked
        assert routed[0][1]["routing_result"] == sr.ACCEPTED
        assert routed[0][1]["selected_dsm_id"] == "windows-security-evd"
    finally:
        wsd.SUPPORTED_EVENT_IDS = original
    assert dsm is not None
    # and with coverage removed again the refusal is truthful once more
    assert route_one(env)[1][0].mismatch_reason == \
        sr.SOURCE_RECORD_NOT_SUPPORTED


# ══ F · tenant isolation ═════════════════════════════════════════
def test_f_retained_raw_is_scoped_to_the_owning_tenant():
    route_one(envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                       declared="windows_security", event_id="b4-sec-tenA"))
    route_one(envelope(_delivery(SYSMON_UNSUPPORTED,
                                 "Microsoft-Windows-Sysmon/Operational"),
                       declared="sysmon", tenant=OTHER_TEN,
                       collector="col-b4-other", event_id="b4-sysmon-tenB"))
    mine = _retained(TEN)
    theirs = _retained(OTHER_TEN)
    assert len(mine) == 1 and len(theirs) == 1
    assert mine[0]["tenant_id"] == TEN
    assert theirs[0]["tenant_id"] == OTHER_TEN
    assert mine[0]["id"] != theirs[0]["id"]
    # the identity key namespace is per tenant, so one tenant's record can
    # never satisfy another tenant's lookup
    c = b4._coll()                                           # noqa: SLF001
    assert c.find_one({"tenant_id": TEN,
                       "retained_identity_key":
                           theirs[0]["retained_identity_key"]}) is None


# ══ G · refusal → retained_raw_id → verbatim record ══════════════
def test_g_a_refusal_points_at_the_evidence_behind_it():
    rows = route_one(envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                              declared="windows_security",
                              event_id="b4-sec-bridge"))[2]
    rid = rows[0]["retained_raw_id"]
    c = b4._coll()                                           # noqa: SLF001
    doc = c.find_one({"tenant_id": TEN, "id": rid})
    assert doc is not None
    full = b4.full_row(doc)
    assert full["raw"]["xml"] == SEC_UNSUPPORTED
    assert full["record_hints"]["event_id"] == "4798"
    assert full["raw_included"] is True
    assert full["provenance"]["trace_id"] == rows[0]["trace_id"]
    assert full["provenance"]["routing"]["mismatch_reason"] == \
        sr.SOURCE_RECORD_NOT_SUPPORTED
    # the list projection stays metadata-only
    meta = b4.metadata_row(doc)
    assert meta["raw_included"] is False
    assert "raw" not in meta
    assert meta["record_hints"]["event_id"] == "4798"
    assert meta["raw_sha256"] == doc["raw_sha256"]


# ══ H · the historical vocabulary is untouched ═══════════════════
def test_h_format_mismatch_code_string_is_unchanged():
    assert sr.SOURCE_FORMAT_MISMATCH == "SOURCE_FORMAT_MISMATCH"
    assert sr.SOURCE_RECORD_NOT_SUPPORTED == "SOURCE_RECORD_NOT_SUPPORTED"
    catalog = sr.catalog()
    assert sr.SOURCE_FORMAT_MISMATCH in catalog["refusal_codes"]
    assert sr.SOURCE_RECORD_NOT_SUPPORTED in catalog["refusal_codes"]
    assert catalog["raw_retention_eligible_codes"] == sorted(
        sr.RAW_RETENTION_ELIGIBLE_CODES)


# ══ the hook itself: fail closed ═════════════════════════════════
def test_a_dsm_without_the_hook_keeps_the_strict_refusal():
    class NoHook:
        id = "no-hook"

        def supports(self, ev):
            return False

    assert DSM_REGISTRY.format_recognized(NoHook(), {"anything": 1}) is False


def test_a_raising_hook_fails_closed_and_is_recorded():
    class Raises:
        id = "raising-hook"

        def supports(self, ev):
            return False

        def recognizes_format(self, ev):
            raise RuntimeError("hook exploded")

    assert DSM_REGISTRY.format_recognized(Raises(), {"x": 1}) is False
    assert any(f.get("status") == "RECOGNIZES_FORMAT_ERROR"
               for f in DSM_REGISTRY.resolve_failures())


def test_format_recognition_requires_provider_or_channel_evidence():
    dsm = DSM_REGISTRY.get("windows-security-evd")
    naked = evtx_xml.decode(_xml(provider="Some-Other-Provider",
                                 event_id=4798, channel="Application"))
    assert dsm.recognizes_format(naked) is False
    real = evtx_xml.decode(SEC_UNSUPPORTED)
    assert dsm.recognizes_format(real) is True
    assert dsm.supports(real) is False


def test_unsupported_event_ids_were_not_widened():
    from detection_content.telemetry import windows_security_dsm as wsd
    assert 4798 not in wsd.SUPPORTED_EVENT_IDS
    assert 4624 in wsd.SUPPORTED_EVENT_IDS


def test_retention_reports_failure_rather_than_pretending():
    class Broken:
        def find_one_and_update(self, *a, **kw):
            from pymongo import errors as pe
            raise pe.PyMongoError("store is down")

    original = b4._coll                                      # noqa: SLF001
    b4._coll = lambda *a, **kw: Broken()                     # noqa: SLF001
    try:
        env = envelope(_delivery(SEC_UNSUPPORTED, "Security"),
                       declared="windows_security", event_id="b4-store-down")
        rows = route_one(env)[2]
        assert rows[0]["raw_retention"]["state"] == "FAILED"
        assert rows[0]["retained_raw_id"] is None
        assert "store is down" in rows[0]["raw_retention"]["reason"]
    finally:
        b4._coll = original                                  # noqa: SLF001
