"""WINDOWS SECURITY SEMANTICS · telemetry is not a detection.

`event.kind` states WHAT WAS OBSERVED. A detection is what a detection
engine CONCLUDED; a compromise is what an authoritative correlation / IOC
mechanism concluded; a response state is what response actually did.
`kind` must not be overloaded with all four.

Owner ruling pinned here: Windows 4720 / 4732 / 4738 are account-management
TELEMETRY and must not intrinsically resolve to `kind="detection"` merely
because Windows logged them.

Also pinned: the Windows Security provider gate resolves from SOURCE-STATED
evidence (`System.Provider`, or the privileged channel only one provider can
write) and never from a display/product label.
"""
from __future__ import annotations

import pytest

from v2.cem.v1 import schema as cem_schema
from v2.ingestion.canonical import (
    SECURITY_CLAIM_KINDS,
    SYSMON_KIND,
    WINSEC_KIND,
    CanonicalEventRecord,
    ces_to_cem_dict,
    resolve_kind,
)
from v2.ingestion.telemetry_bridge import (
    canonical_to_ces,
    source_event_id,
    source_provider,
)

WINSEC_PROVIDER = "Microsoft-Windows-Security-Auditing"
ENVELOPE = {"source": "windows-security", "connector_id": "c1",
            "collector_id": "col1", "collection_method": "evtx",
            "parser_version": "1.0", "source_event_id": "e1",
            "collection_timestamp": "2026-09-22T16:45:46Z"}

#: The owner's ruling, expressed as data.
EXPECTED_WINSEC = {
    4624: "logon_success",
    4625: "logon_failure",
    4634: "logoff",
    4672: "special_privileges_assigned",
    4688: "process_create",
    4697: "service_install",
    4698: "scheduled_task_create",
    4700: "scheduled_task_enabled",
    4720: "user_account_created",
    4732: "security_group_member_added",
    4738: "user_account_changed",
    4776: "credential_validation",
    5140: "smb_share_access",
    5145: "smb_share_access",
    5156: "network_connect",
    7045: "service_install",
    1102: "audit_log_cleared",
}


def _winsec_dsm_canonical(eid, *, additional=None, identity=None):
    """The real `windows-security-normalizer` shape, as retained in
    `xdr_canonical_evidence` (verified against live documents)."""
    return {
        "event_id": "wse-1",
        "source_vendor": "Microsoft",
        # A DISPLAY LABEL. Security meaning must not be keyed off it.
        "source_product": "Windows Security Log",
        "source_event_id": str(eid),
        "event_type": "windows_security_event",
        "event_time": "2026-09-22T16:45:46.310178+00:00",
        "ingest_time": "2026-09-25T15:35:33.325970+00:00",
        "host": {"hostname": "DESKTOP-A9HGFJJ", "host_id": "DESKTOP-A9HGFJJ",
                 "os_family": "windows"},
        "identity": identity or {"principal_id": "NT AUTHORITY\\SYSTEM",
                                 "username": "SYSTEM",
                                 "domain": "NT AUTHORITY",
                                 "user_sid": "S-1-5-18",
                                 "logon_id": "0x3e7"},
        "process": {}, "network": {}, "file": {}, "registry": {},
        "authentication": {}, "cloud": {},
        "raw_ref": {"System": {"Provider": WINSEC_PROVIDER,
                               "EventID": eid, "Channel": "Security",
                               "EventRecordID": 239166,
                               "TimeCreated": "2026-09-22T16:45:46.3101789Z",
                               "Computer": "DESKTOP-A9HGFJJ"},
                    "EventData": {}},
        "provenance": {"trace_id": "t1",
                       "normalizer_id": "windows-security-normalizer"},
        "additional_fields": additional or {},
    }


# ── A · the ruling itself ───────────────────────────────────────────
@pytest.mark.parametrize("eid,expected", sorted(EXPECTED_WINSEC.items()))
def test_winsec_kind_matches_the_owner_ruling(eid, expected):
    assert WINSEC_KIND[eid] == expected


def test_winsec_table_holds_exactly_the_reviewed_event_ids():
    assert set(WINSEC_KIND) == set(EXPECTED_WINSEC)


def test_no_windows_security_event_id_intrinsically_makes_a_security_claim():
    offenders = {eid: kind for eid, kind in WINSEC_KIND.items()
                 if kind in SECURITY_CLAIM_KINDS}
    assert offenders == {}, (
        "a Windows Event ID cannot BE a detection; a detection engine "
        f"concludes one. Offenders: {offenders}")


@pytest.mark.parametrize("eid", [4720, 4732, 4738])
def test_account_management_telemetry_is_never_a_detection(eid):
    kind, basis = resolve_kind(CanonicalEventRecord(
        provider=WINSEC_PROVIDER, event_id=eid))
    assert kind == EXPECTED_WINSEC[eid]
    assert kind != "detection"
    assert kind not in SECURITY_CLAIM_KINDS
    assert basis == f"SOURCE_EVENT_ID:winsec:{eid}"


def test_4672_is_an_observation_not_a_privilege_escalation_claim():
    kind, _ = resolve_kind(CanonicalEventRecord(
        provider=WINSEC_PROVIDER, event_id=4672))
    assert kind == "special_privileges_assigned"
    assert kind != "privilege_escalation"


def test_4634_is_a_logoff_not_a_logon_success():
    assert WINSEC_KIND[4634] == "logoff"


def test_4776_outcome_is_not_claimed_from_the_event_id():
    """4776 is logged for SUCCESS and FAILURE alike; the outcome lives in
    `Status`, so the ID alone may not claim a successful logon."""
    assert WINSEC_KIND[4776] == "credential_validation"


def test_1102_is_an_observation_not_an_alert():
    assert WINSEC_KIND[1102] == "audit_log_cleared"
    assert "alert" in SECURITY_CLAIM_KINDS


def test_the_dead_star_catch_all_key_is_gone():
    assert "*" not in WINSEC_KIND


# ── B · vocabulary governance ───────────────────────────────────────
@pytest.mark.parametrize("kind", sorted(set(WINSEC_KIND.values())))
def test_every_winsec_kind_is_in_the_locked_cem_vocabulary(kind):
    assert kind in cem_schema.EVENT_KINDS


@pytest.mark.parametrize("kind", sorted(set(SYSMON_KIND.values())))
def test_every_sysmon_kind_is_in_the_locked_cem_vocabulary(kind):
    assert kind in cem_schema.EVENT_KINDS


def test_unclassified_telemetry_is_part_of_the_vocabulary():
    assert "unclassified_telemetry" in cem_schema.EVENT_KINDS


#: KNOWN, FLAGGED, AWAITING OWNER RULING — outside the approved WinSec
#: scope. Sysmon 255 is Sysmon's own error/self-report event and currently
#: resolves to the security-claim kind `alert`. Pinned so the debt cannot
#: be forgotten, and so the list can only SHRINK.
SYSMON_SECURITY_CLAIM_DEBT = {255: "alert"}


def test_sysmon_security_claim_debt_is_exactly_the_flagged_set():
    offenders = {eid: kind for eid, kind in SYSMON_KIND.items()
                 if kind in SECURITY_CLAIM_KINDS}
    assert offenders == SYSMON_SECURITY_CLAIM_DEBT


# ── C · the Windows Security provider gate ──────────────────────────
def test_provider_comes_from_the_source_not_the_product_label():
    provider, basis = source_provider(_winsec_dsm_canonical(4720))
    assert provider == WINSEC_PROVIDER
    assert basis == "SOURCE_STATED_PROVIDER:raw_ref.System.Provider"
    assert "Windows Security Log" not in provider


def test_privileged_channel_identifies_the_provider_when_none_is_named():
    doc = _winsec_dsm_canonical(4720)
    doc["raw_ref"] = {"System": {"Channel": "Security", "EventID": 4720}}
    provider, basis = source_provider(doc)
    assert provider == WINSEC_PROVIDER
    assert basis == "PRIVILEGED_CHANNEL:raw_ref.System.Channel"


def test_display_label_is_only_the_last_resort_and_is_marked_as_such():
    doc = _winsec_dsm_canonical(4720)
    doc["raw_ref"] = {}
    provider, basis = source_provider(doc)
    assert provider == "Microsoft Windows Security Log"
    assert basis == "VENDOR_PRODUCT_LABEL"


def test_sysmon_privileged_channel_still_resolves():
    doc = {"source_vendor": "Microsoft", "source_product": "Sysmon",
           "raw_ref": {"channel": "Microsoft-Windows-Sysmon/Operational"},
           "additional_fields": {}, "host": {}, "identity": {},
           "process": {}, "network": {}, "file": {}, "registry": {}}
    provider, basis = source_provider(doc)
    assert provider == "Microsoft-Windows-Sysmon"
    assert basis == "PRIVILEGED_CHANNEL:raw_ref.channel"


@pytest.mark.parametrize("eid,expected", sorted(EXPECTED_WINSEC.items()))
def test_source_event_to_canonical_observation_end_to_end(eid, expected):
    """source Windows Security event → authoritative Event ID → canonical
    observation. The proof the owner asked for, per reviewed Event ID."""
    doc = _winsec_dsm_canonical(eid)
    resolved, basis = source_event_id(doc)
    assert (resolved, basis) == (eid, "raw_ref.System.EventID")
    ces = canonical_to_ces(doc, envelope=ENVELOPE)
    assert ces.provider == WINSEC_PROVIDER
    assert ces.channel == "Security"
    assert ces.event_id == eid
    cem = ces_to_cem_dict(ces, case_id=None)
    assert cem["kind"] == expected
    assert cem["kind"] not in SECURITY_CLAIM_KINDS
    assert cem["provenance"]["kind_basis"] == f"SOURCE_EVENT_ID:winsec:{eid}"


# ── D · security value is preserved, not lost ───────────────────────
def test_account_creation_preserves_actor_target_sid_and_source_identity():
    doc = _winsec_dsm_canonical(4720, additional={
        "target_user_name": "svc_backdoor",
        "target_domain_name": "DESKTOP-A9HGFJJ",
        "target_user_sid": "S-1-5-21-1-2-3-1105"})
    cem = ces_to_cem_dict(canonical_to_ces(doc, envelope=ENVELOPE),
                          case_id=None)
    raw = cem["raw"]
    assert cem["kind"] == "user_account_created"
    # the account acted UPON
    ctx = raw["account_context"]
    assert ctx["target_user_name"] == "svc_backdoor"
    assert ctx["target_user_sid"] == "S-1-5-21-1-2-3-1105"
    # the ACTOR, kept apart from its own target
    assert ctx["actor_username"] == "SYSTEM"
    assert ctx["actor_user_sid"] == "S-1-5-18"
    # the source identity
    ident = raw["source_identity"]
    assert ident["provider"] == WINSEC_PROVIDER
    assert ident["channel"] == "Security"
    assert ident["event_id"] == 4720
    assert ident["record_id"] == 239166
    assert ident["computer"] == "DESKTOP-A9HGFJJ"
    assert ident["provider_basis"] == \
        "SOURCE_STATED_PROVIDER:raw_ref.System.Provider"
    # subject SID reached the canonical field too (DSM names it `user_sid`)
    assert raw["sid"] == "S-1-5-18"
    # and the retained source evidence stays referenceable
    assert raw["raw_evidence_ref"]["collection"] == "xdr_canonical_evidence"
    assert raw["raw_evidence_ref"]["record_id"] == 239166


def test_group_member_added_preserves_the_group_and_the_member():
    doc = _winsec_dsm_canonical(4732, additional={
        "group_name": "Administrators",
        "group_sid": "S-1-5-32-544",
        "member_sid": "S-1-5-21-1-2-3-1105",
        "member_name": "-"})
    cem = ces_to_cem_dict(canonical_to_ces(doc, envelope=ENVELOPE),
                          case_id=None)
    assert cem["kind"] == "security_group_member_added"
    ctx = cem["raw"]["account_context"]
    assert ctx["group_name"] == "Administrators"
    assert ctx["group_sid"] == "S-1-5-32-544"
    assert ctx["member_sid"] == "S-1-5-21-1-2-3-1105"
    # "-" is what Windows wrote; it is preserved, not resolved or dropped
    assert ctx["member_name"] == "-"


def test_special_privileges_preserves_the_privilege_list():
    doc = _winsec_dsm_canonical(4672, additional={
        "privilege_list": ["SeDebugPrivilege", "SeTcbPrivilege"]})
    cem = ces_to_cem_dict(canonical_to_ces(doc, envelope=ENVELOPE),
                          case_id=None)
    assert cem["kind"] == "special_privileges_assigned"
    assert cem["raw"]["account_context"]["privilege_list"] == \
        ["SeDebugPrivilege", "SeTcbPrivilege"]


def test_no_account_context_is_manufactured_when_the_source_had_none():
    cem = ces_to_cem_dict(
        canonical_to_ces(_winsec_dsm_canonical(4624), envelope=ENVELOPE),
        case_id=None)
    assert "account_context" not in cem["raw"]


# ── E · the separation of concerns is explicit ──────────────────────
def test_kind_never_carries_a_detection_or_response_conclusion():
    """`resolve_kind` may only ever return an OBSERVATION for real source
    telemetry. `detection` and `alert` stay in the vocabulary because an
    engine may legitimately produce them — never this classifier."""
    produced = set(WINSEC_KIND.values()) | {
        resolve_kind(CanonicalEventRecord(provider=WINSEC_PROVIDER,
                                          event_id=eid))[0]
        for eid in EXPECTED_WINSEC}
    assert produced & SECURITY_CLAIM_KINDS == set()
