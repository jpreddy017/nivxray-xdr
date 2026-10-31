"""EVENT ID PROPAGATION + FALLBACK SECURITY INVARIANT.

The defect this pins: the authoritative Windows / Sysmon Event ID was
read from ONE canonical dialect only (`additional_fields.winlog`), so
every record normalised by the XDR DSM plane reached the CES with
`event_id=None`. With no source-stated meaning the classifier fell
through to its catch-all, which used to be `detection` — 3120 Sysmon
registry observations on the real corpus became detections and then drew
compromise markers no evidence supported.

Two invariants are pinned here:

1. PROPAGATION — the authoritative Event ID survives every dialect, in
   every representation the sources actually use (`12` and `"12"`), and
   is REFUSED rather than guessed when malformed.
2. FALLBACK SECURITY — unknown / unclassified / unsupported / missing /
   malformed / unparseable input may NEVER resolve to a positive security
   claim. Absence of classification is evidence for neither
   maliciousness nor benignness.
"""
from __future__ import annotations

import pytest

from v2.ingestion.canonical import (
    SECURITY_CLAIM_KINDS,
    SYSMON_KIND,
    UNCLASSIFIED,
    WINSEC_KIND,
    CanonicalEventRecord,
    ces_to_cem_dict,
    event_id_int,
    resolve_kind,
)
from v2.ingestion.telemetry_bridge import canonical_to_ces, source_event_id

SYSMON_PROVIDER = "Microsoft Sysmon"
ENVELOPE = {"source": "sysmon", "connector_id": "c1", "collector_id": "col1",
            "collection_method": "WINDOWS_EVENTLOG_QUERY",
            "parser_version": "1.0", "source_event_id": "e1",
            "collection_timestamp": "2026-09-22T16:20:09Z"}


def _dsm_canonical(*, source_event_id_value, registry=None, **over):
    """The XDR DSM dialect — `CanonicalTelemetryEvent.to_dict()` shape."""
    doc = {
        "event_id": "sysmon-13-abc",
        "source_vendor": "Microsoft",
        "source_product": "Sysmon",
        "source_event_id": source_event_id_value,
        "event_type": "registry_event",
        "event_time": "2026-09-22T16:20:09.743000+00:00",
        "ingest_time": "2026-09-25T15:35:30.364855+00:00",
        "host": {"hostname": "DESKTOP-A9HGFJJ", "host_id": "DESKTOP-A9HGFJJ"},
        "identity": {"username": "NT AUTHORITY\\SYSTEM"},
        "process": {"name": "svchost.exe", "pid": 2404,
                    "executable_path": "C:\\Windows\\system32\\svchost.exe"},
        "network": {}, "file": {},
        "registry": registry if registry is not None else {
            "hive": "HKLM", "key_path": "HKLM\\Software\\Nivx\\Run",
            "value_name": "Updater", "value_data": "C:\\tmp\\x.exe",
            "action": "set_value",
            "target_object": "HKLM\\Software\\Nivx\\Run\\Updater"},
        "authentication": {}, "cloud": {},
        "raw_ref": {"sysmon_event_id": 13, "channel":
                    "Microsoft-Windows-Sysmon/Operational"},
        "provenance": {"trace_id": "t1", "normalizer_id": "sysmon-normalizer"},
        "additional_fields": {"channel":
                              "Microsoft-Windows-Sysmon/Operational"},
    }
    doc.update(over)
    return doc


def _winlog_canonical(event_id_value):
    """The EDR sensor bridge dialect — `additional_fields.winlog`."""
    return {
        "event_id": "cev_1_0",
        "source_vendor": "NivXForge", "source_product": "WindowsSensor",
        "event_time": "2026-09-22T15:43:31.770000Z",
        "host": {"hostname": "WS-W1", "host_id": "ep_1"},
        "identity": {}, "process": {}, "network": {}, "file": {},
        "registry": {"key": "HKLM\\Software\\Nivx\\Run",
                     "value_data": "C:\\tmp\\x.exe"},
        "dns": {}, "authentication": {},
        "provenance": {"trace_id": "raw_1"},
        "additional_fields": {
            "payload_format": "nivxforge-windows-eventlog",
            "winlog": {"provider": "Microsoft-Windows-Sysmon",
                       "channel": "Microsoft-Windows-Sysmon/Operational",
                       "event_id": event_id_value, "record_id": 918273,
                       "computer": "WS-W1"}},
    }


# ── A · lossless representation handling ─────────────────────────────
@pytest.mark.parametrize("raw,expected", [
    (12, 12), (13, 13), ("12", 12), ("13", 13), (" 12 ", 12), ("012", 12),
    (0, 0),
])
def test_event_id_int_accepts_only_lossless_representations(raw, expected):
    assert event_id_int(raw) == expected


@pytest.mark.parametrize("raw", [
    None, "", "   ", "12abc", "abc", "0x0c", "12.0", 12.0, "-1", True, False,
    [], {}, ("12",),
])
def test_event_id_int_refuses_everything_it_cannot_prove(raw):
    assert event_id_int(raw) is None


# ── B · deterministic mapping from the authoritative Event ID ────────
@pytest.mark.parametrize("raw", [12, "12"])
def test_sysmon_12_maps_to_registry_create(raw):
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=raw))
    assert kind == "registry_create"
    assert basis == "SOURCE_EVENT_ID:sysmon:12"


@pytest.mark.parametrize("raw", [13, "13"])
def test_sysmon_13_maps_to_registry_value_set(raw):
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=raw))
    assert kind == "registry_value_set"
    assert basis == "SOURCE_EVENT_ID:sysmon:13"


@pytest.mark.parametrize("eid,expected", sorted(SYSMON_KIND.items()))
def test_every_known_sysmon_id_is_source_stated(eid, expected):
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=eid))
    assert (kind, basis) == (expected, f"SOURCE_EVENT_ID:sysmon:{eid}")


@pytest.mark.parametrize("eid", sorted(k for k in WINSEC_KIND if isinstance(k, int)))
def test_every_known_winsec_id_is_source_stated(eid):
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider="Microsoft-Windows-Security-Auditing", event_id=eid))
    assert kind == WINSEC_KIND[eid]
    assert basis == f"SOURCE_EVENT_ID:winsec:{eid}"


# ── C · propagation across BOTH canonical dialects ───────────────────
@pytest.mark.parametrize("value", [13, "13"])
def test_dsm_dialect_event_id_reaches_the_ces(value):
    eid, basis = source_event_id(_dsm_canonical(source_event_id_value=value))
    assert eid == 13
    assert basis == "raw_ref.sysmon_event_id"


def test_dsm_dialect_falls_back_to_source_event_id_when_raw_ref_is_absent():
    doc = _dsm_canonical(source_event_id_value="12", raw_ref={})
    eid, basis = source_event_id(doc)
    assert (eid, basis) == (12, "source_event_id")


@pytest.mark.parametrize("value,expected_kind", [
    ("12", "registry_create"), (12, "registry_create"),
    ("13", "registry_value_set"), (13, "registry_value_set"),
])
def test_dsm_sysmon_registry_record_classifies_from_its_event_id(
        value, expected_kind):
    doc = _dsm_canonical(source_event_id_value=value,
                         raw_ref={"sysmon_event_id": value})
    ces = canonical_to_ces(doc, envelope=ENVELOPE)
    assert ces.event_id == int(value)
    assert ces.channel == "Microsoft-Windows-Sysmon/Operational"
    # The DSM dialect names the registry key `key_path`/`target_object`.
    assert ces.registry_key == "HKLM\\Software\\Nivx\\Run"
    cem = ces_to_cem_dict(ces, case_id=None)
    assert cem["kind"] == expected_kind
    assert cem["raw"]["event_id"] == int(value)
    assert cem["provenance"]["kind_basis"] == \
        f"SOURCE_EVENT_ID:sysmon:{int(value)}"


@pytest.mark.parametrize("value", [11, "11"])
def test_sensor_winlog_dialect_still_propagates(value):
    ces = canonical_to_ces(_winlog_canonical(value), envelope=ENVELOPE)
    assert ces.event_id == 11
    cem = ces_to_cem_dict(ces, case_id=None)
    assert cem["kind"] == "file_create"


def test_source_identity_is_preserved_and_traceable():
    ces = canonical_to_ces(_winlog_canonical(13), envelope=ENVELOPE)
    identity = ces.raw_event["source_identity"]
    assert identity["provider"] == "Microsoft-Windows-Sysmon"
    assert identity["channel"] == "Microsoft-Windows-Sysmon/Operational"
    assert identity["event_id"] == 13
    assert identity["record_id"] == 918273
    assert identity["computer"] == "WS-W1"
    assert identity["source_time"] == "2026-09-22T15:43:31.770000Z"
    assert ces.raw_event["canonical_event_id"] == "cev_1_0"


def test_source_identity_invents_nothing_when_the_source_stated_nothing():
    doc = _dsm_canonical(source_event_id_value="", raw_ref={})
    ces = canonical_to_ces(doc, envelope=ENVELOPE)
    identity = ces.raw_event["source_identity"]
    assert "event_id" not in identity
    assert "record_id" not in identity
    assert identity["event_id_basis"] == "NOT_CARRIED_BY_SOURCE"


# ── D · missing Event ID · derived vs unclassified ───────────────────
def test_missing_event_id_with_sufficient_evidence_is_derived_with_a_basis():
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider="Some Unknown Product", event_id=None,
        registry_key="HKLM\\Software\\Nivx\\Run", registry_value="Updater"))
    assert kind == "registry_value_set"
    assert basis == \
        "DERIVED_FROM_OBSERVED_FIELDS:registry_key+registry_value"


def test_missing_event_id_with_insufficient_evidence_is_unclassified():
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider="Some Unknown Product", event_id=None,
        computer="HOST-1", user="SYSTEM"))
    assert kind == UNCLASSIFIED
    assert basis == "UNCLASSIFIED_INSUFFICIENT_EVIDENCE"


def test_the_exact_production_defect_no_longer_reproduces():
    """The real 3120-record shape: Sysmon 13, no winlog block."""
    doc = _dsm_canonical(source_event_id_value="13")
    cem = ces_to_cem_dict(canonical_to_ces(doc, envelope=ENVELOPE),
                          case_id=None)
    assert cem["kind"] == "registry_value_set"
    assert cem["kind"] != "detection"


# ── E · FALLBACK SECURITY INVARIANT ─────────────────────────────────
_NON_CLASSIFYING_INPUTS = [
    ("unknown sysmon event id", CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=99)),
    ("unknown winsec event id", CanonicalEventRecord(
        provider="Microsoft-Windows-Security-Auditing", event_id=9999)),
    ("malformed event id string", CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id="not-a-number")),
    ("malformed event id float", CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=13.5)),
    ("malformed event id bool", CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id=True)),
    ("hex event id", CanonicalEventRecord(
        provider=SYSMON_PROVIDER, event_id="0x0d")),
    ("missing event id", CanonicalEventRecord(provider=SYSMON_PROVIDER)),
    ("missing provider and event id", CanonicalEventRecord()),
    ("unsupported provider", CanonicalEventRecord(
        provider="SomeOtherVendor Widget", event_id=13)),
    ("empty record", CanonicalEventRecord(timestamp="", provider="")),
    ("parse-failure residue", CanonicalEventRecord(
        provider="", event_id=None, raw_event={"parse_error": "malformed"})),
]


@pytest.mark.parametrize("label,ces",
                         _NON_CLASSIFYING_INPUTS,
                         ids=[c[0] for c in _NON_CLASSIFYING_INPUTS])
def test_absent_or_malformed_input_never_becomes_a_security_claim(label, ces):
    kind, basis = resolve_kind(ces)
    assert kind not in SECURITY_CLAIM_KINDS, (
        f"{label} produced the security claim {kind!r}")
    assert kind == UNCLASSIFIED
    assert basis
    cem = ces_to_cem_dict(ces, case_id=None)
    assert cem["kind"] == UNCLASSIFIED
    assert cem["raw"]["action"] == UNCLASSIFIED


def test_unclassified_is_not_a_benign_claim_either():
    assert UNCLASSIFIED not in SECURITY_CLAIM_KINDS
    for claim in ("clean", "benign", "verified", "contained", "blocked"):
        assert claim in SECURITY_CLAIM_KINDS


def test_no_unknown_event_id_resolves_through_the_star_key():
    """`WINSEC_KIND` holds a legacy `"*"` catch-all key. An integer lookup
    can never reach it, and it must never be revived as a default."""
    kind, _ = resolve_kind(CanonicalEventRecord(
        provider="Microsoft-Windows-Security-Auditing", event_id=424242))
    assert kind == UNCLASSIFIED


# ── F · parse failure never manufactures a claim ────────────────────
def test_sysmon_upload_normalizer_parse_failure_yields_no_security_claim():
    from v2.ingestion.canonical import IngestionProvenance
    from v2.ingestion.normalizers import sysmon_xml

    prov = IngestionProvenance(origin="customer-upload", format="sysmon_xml")
    records = list(sysmon_xml.normalize(b"<Events><Event><not closed",
                                        provenance=prov))
    for rec in records:
        assert resolve_kind(rec)[0] not in SECURITY_CLAIM_KINDS


def test_sysmon_upload_normalizer_malformed_event_id_is_unclassified():
    from v2.ingestion.canonical import IngestionProvenance
    from v2.ingestion.normalizers import sysmon_xml

    xml = (b"<Events><Event><System>"
           b"<Provider Name='Microsoft-Windows-Sysmon'/>"
           b"<EventID>not-a-number</EventID>"
           b"<Computer>HOST-1</Computer></System>"
           b"<EventData><Data Name='User'>SYSTEM</Data></EventData>"
           b"</Event></Events>")
    prov = IngestionProvenance(origin="customer-upload", format="sysmon_xml")
    for rec in sysmon_xml.normalize(xml, provenance=prov):
        kind, _ = resolve_kind(rec)
        assert kind not in SECURITY_CLAIM_KINDS
        assert kind == UNCLASSIFIED
