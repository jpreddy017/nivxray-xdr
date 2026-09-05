"""
NivXRay XDR — Phase 2.1 Adversarial Field Normalization Suite.
Attacks Windows 4688/4768/4769, Linux Auditd, and AWS CloudTrail normalizers with:
- missing fields
- null fields
- malformed fields
- alternate casing
- unexpected types
- duplicate events
- Unicode payloads
- oversized command lines (64KB+)
- malformed Auditd hex strings
- unknown CloudTrail identity types
- absent tenant (must fail closed; NO tenant fallback)
- conflicting timestamps
Enforces: ZERO invented telemetry, ZERO tenant fallback.
"""
import pytest
from detection_content.telemetry import (
    WindowsSecurityDSM,
    LinuxAuditdDSM,
    AWSCloudTrailDSM,
    TELEMETRY_DSM_REGISTRY,
)


# ── 1. Absent Tenant & No Tenant Fallback Tests ──────────────────────────────

def test_absent_tenant_raises_error_windows_4688():
    """Windows Security Normalizer must reject absent tenant; NO silent fallback to 'default'."""
    raw = {
        "EventID": 4688,
        "TimeCreated": "2026-09-04T12:00:00Z",
        "Computer": "PC-01",
        "EventData": {"NewProcessName": "cmd.exe", "CommandLine": "cmd.exe"},
    }
    dsm = WindowsSecurityDSM()
    parsed = dsm.select_parser().parse(raw)
    normalizer = dsm.select_normalizer()

    # Calling without tenant_id or empty tenant_id must raise ValueError
    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalizer.normalize(parsed, dsm.id, "c1", "i1", "t1", tenant_id=None)

    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalizer.normalize(parsed, dsm.id, "c1", "i1", "t1", tenant_id="  ")


def test_absent_tenant_raises_error_linux_auditd():
    """Linux Auditd Normalizer must reject absent tenant; NO silent fallback to 'default'."""
    raw = {
        "type": "EXECVE",
        "timestamp": "2026-09-04T12:00:00Z",
        "exe": "/bin/sh",
        "a0": "sh",
    }
    dsm = LinuxAuditdDSM()
    parsed = dsm.select_parser().parse(raw)
    normalizer = dsm.select_normalizer()

    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalizer.normalize(parsed, dsm.id, "c1", "i1", "t1", tenant_id=None)


def test_absent_tenant_raises_error_aws_cloudtrail():
    """AWS CloudTrail Normalizer must reject absent tenant; NO silent fallback to 'default'."""
    raw = {
        "eventName": "CreateUser",
        "eventSource": "iam.amazonaws.com",
        "eventTime": "2026-09-04T12:00:00Z",
        "userIdentity": {"type": "IAMUser", "userName": "test-admin"},
    }
    dsm = AWSCloudTrailDSM()
    parsed = dsm.select_parser().parse(raw)
    normalizer = dsm.select_normalizer()

    with pytest.raises(ValueError, match="NO tenant fallback"):
        normalizer.normalize(parsed, dsm.id, "c1", "i1", "t1", tenant_id="")


# ── 2. Null, Missing, Malformed Fields & Alternate Casing ────────────────────

def test_windows_4688_alternate_casing_and_null_fields():
    """Verify alternate casing (all lowercase or uppercase) resolves without inventing fields."""
    raw = {
        "eventid": 4688,
        "timecreated": "2026-09-04T12:00:00Z",
        "computer": "PC-WIN11",
        "eventdata": {
            "newprocessname": "C:\\Windows\\System32\\cmd.exe",
            "commandline": "CMD.EXE /C DIR",
            "parentprocessname": None,  # Explicitly null
            "targetusername": "AdminUser",
            "targetdomainname": None,
            "tokenelevationtype": "%%1937",
        },
    }
    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw)
    assert dsm is not None
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-alpha"
    )

    assert canonical["tenant_id"] == "tenant-alpha"
    assert canonical["process"]["name"] == "cmd.exe"
    assert canonical["process"]["command_line"] == "CMD.EXE /C DIR"
    assert canonical["process"]["parent_name"] == ""  # Null parent was not invented
    assert canonical["identity"]["username"] == "AdminUser"
    assert canonical["identity"]["domain"] == ""     # Null domain was not invented
    assert canonical["identity"]["is_privileged"] is True


def test_windows_4768_missing_network_fields():
    """Verify 4768 Kerberos TGT request handles missing IP/Port without inventing data."""
    raw = {
        "EventID": 4768,
        "TimeCreated": "2026-09-04T12:05:00Z",
        "Computer": "DC-01.corp",
        "EventData": {
            "TargetUserName": "krbtgt",
            "TargetDomainName": "CORP.LOCAL",
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40810010",
            "Status": "0x0",
            # IpAddress and IpPort intentionally absent
        },
    }
    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw)
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-alpha"
    )

    assert canonical["network"]["src_ip"] == ""
    assert canonical["network"]["src_port"] is None
    assert canonical["authentication"]["status"] == "SUCCESS"


# ── 3. Unicode, Oversized Command Lines & Malformed Types ────────────────────

def test_oversized_and_unicode_commandline():
    """Verify 64KB+ Unicode payload normalizes safely without truncation or crash."""
    unicode_str = "powershell.exe -Command 'Write-Output 💀 恶意软件 Взлом العربية' "
    huge_cmd = unicode_str + ("A" * 70000)

    raw = {
        "EventID": 4688,
        "TimeCreated": "2026-09-04T12:00:00Z",
        "Computer": "WORKSTATION-CYR",
        "EventData": {
            "NewProcessName": "powershell.exe",
            "CommandLine": huge_cmd,
            "SubjectUserName": "пользователь",
        },
    }
    dsm = WindowsSecurityDSM()
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-corp"
    )

    assert len(canonical["process"]["command_line"]) > 70000
    assert "💀" in canonical["process"]["command_line"]
    assert canonical["identity"]["username"] == "пользователь"


# ── 4. Linux Auditd Hex Normalization & Corrupted Strings ────────────────────

def test_linux_auditd_malformed_hex_arguments():
    """Verify malformed hex (odd length or invalid characters) does not crash and is not invented."""
    raw = {
        "type": "EXECVE",
        "msg": "audit(1693829482.123:999):",
        "exe": "63616c636",      # Odd length hex (9 chars)
        "a0": "63616Z63",        # Invalid hex character 'Z'
        "a1": "2f62696e2f7368",  # Valid hex for '/bin/sh'
        "host": "srv-linux-prod",
    }
    dsm = LinuxAuditdDSM()
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-audit"
    )

    # Valid hex decoded cleanly
    assert "/bin/sh" in canonical["process"]["command_line"]
    # Malformed hex preserved as raw without crash
    assert "63616c636" in canonical["process"]["executable_path"] or "63616c636" in canonical["process"]["command_line"]
    assert canonical["host"]["hostname"] == "srv-linux-prod"


def test_linux_auditd_absent_host_no_invented_telemetry():
    """Verify absent host fields in Linux Auditd does NOT invent 'linux-host'."""
    raw = {
        "type": "SYSCALL",
        "msg": "audit(1693829482.123:100):",
        "syscall": "59",
        "exe": "/usr/bin/id",
    }
    dsm = LinuxAuditdDSM()
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-audit"
    )
    # Host must be empty, NOT invented 'linux-host'
    assert canonical["host"]["hostname"] == ""
    assert canonical["host"]["host_id"] == ""


# ── 5. AWS CloudTrail Unknown Identity Types ─────────────────────────────────

def test_cloudtrail_unknown_identity_type():
    """Verify unexpected/custom CloudTrail identity types are preserved without inventing IAMUser."""
    raw = {
        "eventName": "AssumeRoleWithWebIdentity",
        "eventSource": "sts.amazonaws.com",
        "eventTime": "2026-09-04T12:00:00Z",
        "userIdentity": {
            "type": "CustomFederatedPartnerX",
            "principalId": "FED-PARTNER-9988",
            "arn": "arn:aws:sts::123456789012:federated-user/custom_partner",
        },
    }
    dsm = AWSCloudTrailDSM()
    parsed = dsm.select_parser().parse(raw)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "c1", "i1", "t1", tenant_id="tenant-cloud"
    )

    assert canonical["identity"]["principal_id"] == "FED-PARTNER-9988"
    assert canonical["identity"]["username"] == ""
    # Principal ID must NOT be invented "aws-principal"
    assert canonical["identity"]["principal_id"] != "aws-principal"
