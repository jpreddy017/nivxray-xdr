# NIVXFORGE EDR: CANONICAL EVIDENCE SCHEMA CONTRACT
**Authoritative Schemas, Common Envelope Specification, and Event Definitions for EDR & Native Sandbox Telemetry**  
**Document ID:** `NIVXFORGE-EVIDENCE-SCHEMA-2026-09-05`  
**Classification:** Governing Engineering Handoff Pack  
**Handoff Status:** 🟢 APPROVED & READY FOR EMERGENT INTEGRATION REVIEW  

---

## 1. Executive Statement

To guarantee seamless interoperability and prevent fragmented siloed data stores, all telemetry emitted by **NivXForge EDR Sensors** and the **Native Dynamic Sandbox** must conform to this **Canonical Evidence Schema Contract**. Every event is wrapped in an authoritative **Common Envelope** that enforces provenance, tenant isolation, and cryptographic integrity.

---

## 2. The Universal Common Envelope Specification

Every telemetry artifact stored in the Canonical Evidence Vault or processed by NivXRay reasoning engines inherits this structure:

```json
{
  "$schema": "https://schema.nivxray.io/v2/canonical-evidence-envelope.json",
  "envelope_version": "2.0.0",
  
  "tenant_id": "string (UUID v4 - extracted server-side from auth token)",
  "evidence_id": "string (UUID v4 - globally unique immutable evidence ID)",
  "event_id": "string (deterministic hash: sha256(device_id + timestamp + event_type + seq))",
  "timestamp": "string (ISO-8601 UTC with microsecond precision: YYYY-MM-DDTHH:mm:ss.ffffffZ)",
  "source": "string (enum: EDR_SENSOR_WIN, EDR_SENSOR_LINUX, EDR_SENSOR_DARWIN, SANDBOX_HYPERVISOR)",
  
  "device_id": "string (UUID v4 - hardware machine GUID)",
  "user_id": "string (Active Directory SID or Linux UID)",
  "process_id": "string (Process GUID: {device_id}:{pid}:{epoch})",
  "parent_process_id": "string (Parent Process GUID: {device_id}:{ppid}:{epoch})",
  
  "file_hash": "string (SHA-256 hex string or null)",
  "network_endpoint": "string (format: 'IP:Port' or null)",
  "artifact_id": "string (UUID v4 pointing to raw stored payload in Vault or null)",
  
  "provenance": {
    "collector_version": "2.4.0",
    "kernel_driver_hook": "string (e.g. PsSetCreateProcessNotifyRoutineEx, eBPF/sys_enter_execve)",
    "ingestion_gateway_timestamp": "string (ISO-8601 UTC)"
  },
  
  "confidence": "number (float: 0.0 to 1.0 - authoritative sensor telemetry defaults to 1.0)",
  
  "event_type": "string (enum: process, file, network, dns, registry, service, user_session, persistence, memory, system, security_event, sandbox_syscall, sandbox_pcap, sandbox_config)",
  
  "raw_event": "object (exact verbatim ETW, eBPF, or hypervisor JSON payload)",
  "canonical_event": "object (strongly-typed event payload conforming to schemas in Section 3/4)"
}
```

---

## 3. EDR Telemetry Schemas (11 Event Classes)

### 3.1 `process` Event Schema
```json
{
  "action": "enum: CREATE, TERMINATE, INJECT, HOLLOW",
  "pid": 4912,
  "ppid": 4110,
  "image_path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand WwBTAHk...",
  "current_working_directory": "C:\\Users\\jdoe\\AppData\\Local\\Temp",
  "integrity_level": "enum: UNTRUSTED, LOW, MEDIUM, HIGH, SYSTEM",
  "hashes": {
    "sha256": "419c225566d6054d38fe5ee5c01bd9d2bdfedf79a312dd15ae71646e322255ae",
    "md5": "d41d8cd98f00b204e9800998ecf8427e"
  },
  "signature": {
    "is_signed": true,
    "signer_name": "Microsoft Corporation",
    "status": "VALID"
  }
}
```

### 3.2 `file` Event Schema
```json
{
  "action": "enum: CREATE, WRITE, DELETE, RENAME, ACL_CHANGE",
  "file_path": "C:\\ProgramData\\svchost_update.exe",
  "previous_file_path": null,
  "file_size_bytes": 142336,
  "file_extension": ".exe",
  "is_executable": true,
  "hashes": {
    "sha256": "8a7f1e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f"
  }
}
```

### 3.3 `network` Event Schema
```json
{
  "action": "enum: CONNECT, ACCEPT, LISTEN, CLOSE",
  "protocol": "TCP",
  "direction": "OUTBOUND",
  "local_address": "192.168.10.45",
  "local_port": 49812,
  "remote_address": "198.51.100.45",
  "remote_port": 8080,
  "bytes_sent": 34200,
  "bytes_received": 1280,
  "tcp_state": "ESTABLISHED",
  "tls_sni": null
}
```

### 3.4 `dns` Event Schema
```json
{
  "query_name": "update.microsoft-check.net",
  "query_type": "A",
  "response_code": "NOERROR",
  "resolved_ips": ["198.51.100.45"],
  "dns_server": "192.168.1.1",
  "ttl": 300
}
```

### 3.5 `registry` Event Schema
```json
{
  "action": "enum: SET_VALUE, CREATE_KEY, DELETE_KEY, DELETE_VALUE",
  "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "value_name": "WindowsUpdateAssistant",
  "value_type": "REG_SZ",
  "value_data": "C:\\ProgramData\\svchost_update.exe"
}
```

### 3.6 `service` Event Schema
```json
{
  "action": "enum: INSTALL, START, STOP, MODIFY, DELETE",
  "service_name": "WinUpdateSvc",
  "display_name": "Windows Telemetry Updater",
  "binary_path": "C:\\ProgramData\\svchost_update.exe",
  "start_type": "AUTO_START",
  "service_account": "LocalSystem"
}
```

### 3.7 `user_session` Event Schema
```json
{
  "action": "enum: LOGON, LOGOFF, LOCK, UNLOCK, FAILED_LOGON",
  "logon_type": 2,
  "logon_type_desc": "INTERACTIVE",
  "username": "jdoe",
  "domain": "CORP",
  "user_sid": "S-1-5-21-39482910-2918239-1002",
  "client_ip": "127.0.0.1",
  "session_id": 1
}
```

### 3.8 `persistence` Event Schema
```json
{
  "persistence_type": "enum: REGISTRY_RUN, SCHEDULED_TASK, WMI_EVENT, STARTUP_FOLDER, CRON",
  "asep_path": "TaskScheduler:\\Microsoft\\Windows\\Maintenance\\CleanUpTask",
  "target_binary": "C:\\Windows\\System32\\rundll32.exe",
  "arguments": "C:\\ProgramData\\svchost_update.exe,DllRegisterServer",
  "trigger": "ON_IDLE_OR_BOOT"
}
```

### 3.9 `memory` Event Schema
```json
{
  "anomaly_type": "enum: RWX_ALLOCATION, HOLLOWED_PE_HEADER, UNBACKED_THREAD, HOOK_DETECTED",
  "target_pid": 1420,
  "target_process_name": "explorer.exe",
  "base_address": "0x04F10000",
  "region_size_bytes": 4096,
  "protection": "PAGE_EXECUTE_READWRITE",
  "is_mapped_to_disk": false,
  "yara_scan_matches": ["COBALT_STRIKE_BEACON_SHELLCODE"]
}
```

### 3.10 `system` Event Schema
```json
{
  "event_name": "enum: DRIVER_LOAD, TAMPER_ATTEMPT, TIME_JUMP, AUDIT_LOG_CLEARED",
  "driver_path": "C:\\Windows\\System32\\drivers\\suspicious_kernel.sys",
  "is_whitelisted": false,
  "signature_status": "UNSIGNED"
}
```

### 3.11 `security_event` Event Schema
```json
{
  "provider": "Microsoft-Windows-Security-Auditing",
  "event_id": 4688,
  "event_description": "A new process has been created.",
  "subject_user_sid": "S-1-5-21-39482910-2918239-1002",
  "mandatory_label": "High Mandatory Level"
}
```

---

## 4. Sandbox Telemetry Schemas (15 Event Classes)

The Sandbox emits events structured to integrate directly into the Canonical Evidence Vault:

1. **`sandbox_syscall`**: Captures low-level NT API calls (`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `CreateRemoteThread`, `InternetConnectA`).
2. **`sandbox_process`**: Hierarchical child process execution inside the isolated guest VM.
3. **`sandbox_file_drop`**: Secondary payloads written to guest disk with 1-click **"Forward to 59 Decoders"** metadata.
4. **`sandbox_registry`**: Guest registry modifications and autostart key installations.
5. **`sandbox_net_flow`**: Outbound TCP/UDP sockets observed by hypervisor virtual TAP interface.
6. **`sandbox_dns`**: Synthetic INETSim or live DNS resolutions requested by the sample.
7. **`sandbox_http`**: Decrypted HTTP/HTTPS requests including Method, URI, User-Agent, and Response Payload.
8. **`sandbox_tls`**: Extracted TLS Client Hello SNI, JA3/JA4 fingerprints, and cipher suites.
9. **`sandbox_memory`**: Hypervisor-level inspection of guest physical memory frames containing shellcode.
10. **`sandbox_pcap`**: Full packet capture storage pointer (`pcap_sha256`, size, capture duration).
11. **`sandbox_screenshot`**: Periodic desktop display frame capture (PNG format) demonstrating user prompts.
12. **`sandbox_config`**: Extracted malware configuration block (Cobalt Strike C2, RSA public key, DarkGate salt).
13. **`sandbox_ioc`**: Curated list of high-confidence indicators extracted from dynamic execution.
14. **`sandbox_mitre`**: Dynamically mapped ATT&CK techniques based on verified guest behaviors.
15. **`sandbox_anti_evasion`**: Evasion techniques detected during execution (e.g., `IsDebuggerPresent`, `RDTSC_TIMING_CHECK`).
