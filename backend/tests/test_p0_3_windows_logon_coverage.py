"""P0-3 regression fixtures · Windows Security 4624/4625 logon coverage.

Positive: 4624 success, 4625 failure — must resolve to the Windows-Security
DSM and normalize as authentication evidence.
Negative: previously-supported IDs must keep working; unsupported IDs must
still be refused; the parser must still refuse unsupported EIDs.
"""
from __future__ import annotations

import pytest

from detection_content.telemetry import TELEMETRY_DSM_REGISTRY
from detection_content.telemetry.windows_security_dsm import (
    SUPPORTED_EVENT_IDS,
    WindowsSecurityDSM,
    WindowsSecurityParserError,
)


def _ev(event_id: int, data: dict) -> dict:
    return {
        "EventID": event_id,
        "Channel": "Security",
        "Computer": "WORKSTATION-01.corp.local",
        "TimeCreated": "2026-09-05T10:00:00Z",
        "EventData": data,
    }


_4624 = _ev(4624, {
    "TargetUserName": "alice",
    "TargetDomainName": "CORP",
    "TargetUserSid": "S-1-5-21-1-2-3-1001",
    "TargetLogonId": "0x3E7A1",
    "LogonType": "10",
    "WorkstationName": "JUMPHOST-02",
    "LogonProcessName": "Kerberos",
    "AuthenticationPackageName": "Kerberos",
    "ProcessName": "C:\\Windows\\System32\\svchost.exe",
    "IpAddress": "::ffff:10.20.30.40",
    "IpPort": "51544",
})

_4625 = _ev(4625, {
    "TargetUserName": "svc_backup",
    "TargetDomainName": "CORP",
    "LogonType": "3",
    "WorkstationName": "ATTACKER-PC",
    "AuthenticationPackageName": "NTLM",
    "Status": "0xC000006D",
    "SubStatus": "0xC000006A",
    "IpAddress": "10.99.99.99",
    "IpPort": "445",
})


# ── POSITIVE ────────────────────────────────────────────────────────

def test_supported_event_ids_include_logon():
    assert 4624 in SUPPORTED_EVENT_IDS
    assert 4625 in SUPPORTED_EVENT_IDS


@pytest.mark.parametrize("ev", [_4624, _4625])
def test_dsm_supports_logon_events(ev):
    assert WindowsSecurityDSM().supports(ev) is True


@pytest.mark.parametrize("ev,expected", [(_4624, 4624), (_4625, 4625)])
def test_registry_resolves_logon_to_windows_security(ev, expected):
    dsm = TELEMETRY_DSM_REGISTRY.resolve(ev)
    assert dsm is not None, f"no DSM resolved EventID {expected}"
    assert dsm.id == "windows-security-evd"


def test_4624_normalizes_as_successful_authentication():
    dsm = WindowsSecurityDSM()
    parsed = dsm.select_parser().parse(_4624)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-p0-3",
        tenant_id="tenant-corp")

    assert canonical["event_type"] == "logon_success"
    assert canonical["source_event_id"] == "4624"
    auth = canonical["authentication"]
    assert auth["status"] == "SUCCESS"
    assert auth["logon_type"] == 10
    assert auth["failure_reason"] == ""
    ident = canonical["identity"]
    assert ident["username"] == "alice"
    assert ident["domain"] == "CORP"
    assert ident["principal_id"] == "CORP\\alice"
    assert ident["user_sid"] == "S-1-5-21-1-2-3-1001"
    assert ident["logon_id"] == "0x3E7A1"
    # IPv4-mapped IPv6 prefix must be stripped, matching the 4768 branch.
    assert canonical["network"]["src_ip"] == "10.20.30.40"
    assert canonical["network"]["src_port"] == 51544
    add = canonical["additional_fields"]
    assert add["logon_type"] == 10
    assert add["logon_type_label"] == "remote_interactive"
    assert add["workstation_name"] == "JUMPHOST-02"
    # A successful logon must NOT carry failure metadata.
    assert "status" not in add
    assert "sub_status" not in add


def test_4625_normalizes_as_failed_authentication():
    dsm = WindowsSecurityDSM()
    parsed = dsm.select_parser().parse(_4625)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-p0-3",
        tenant_id="tenant-corp")

    assert canonical["event_type"] == "logon_failure"
    assert canonical["source_event_id"] == "4625"
    auth = canonical["authentication"]
    assert auth["status"] == "FAILURE"
    assert auth["logon_type"] == 3
    assert auth["failure_reason"] == "0xC000006A"
    assert auth["auth_type"] == "ntlm"
    add = canonical["additional_fields"]
    assert add["logon_type_label"] == "network"
    assert add["status"] == "0xC000006D"
    assert add["sub_status"] == "0xC000006A"


def test_logon_events_carry_full_provenance():
    dsm = WindowsSecurityDSM()
    parsed = dsm.select_parser().parse(_4624)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-p0-3",
        tenant_id="tenant-corp")
    prov = canonical["provenance"]
    assert prov["parser_id"]
    assert prov["normalizer_id"]
    assert canonical["event_id"]


# ── NEGATIVE ────────────────────────────────────────────────────────

@pytest.mark.parametrize("eid", [4688, 4768, 4769])
def test_preexisting_event_ids_still_supported(eid):
    assert WindowsSecurityDSM().supports(_ev(eid, {})) is True


@pytest.mark.parametrize("eid", [1, 4634, 4672, 5140, 255, 0])
def test_unsupported_event_ids_still_refused(eid):
    assert WindowsSecurityDSM().supports(_ev(eid, {})) is False


def test_parser_refuses_unsupported_event_id():
    with pytest.raises(WindowsSecurityParserError) as ei:
        WindowsSecurityDSM().select_parser().parse(_ev(4634, {}))
    assert "UNSUPPORTED_EID" in str(ei.value)


def test_non_dict_event_is_refused():
    assert WindowsSecurityDSM().supports(None) is False
    assert WindowsSecurityDSM().supports("4624") is False


def test_missing_logon_type_is_omitted_not_fabricated():
    ev = _ev(4624, {"TargetUserName": "bob"})
    dsm = WindowsSecurityDSM()
    canonical = dsm.select_normalizer().normalize(
        dsm.select_parser().parse(ev), dsm.id, "collector-01", "integ-win",
        "trace-p0-3", tenant_id="tenant-corp")
    assert canonical["authentication"]["logon_type"] is None
    assert "logon_type" not in canonical["additional_fields"]
    assert "logon_type_label" not in canonical["additional_fields"]
    assert "workstation_name" not in canonical["additional_fields"]
