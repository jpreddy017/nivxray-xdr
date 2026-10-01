# NivXRay XDR — Enterprise Content Gap Matrix
**Document Version:** 1.0.0  
**Audit Date:** 2026-09-04  
**Classification:** Enterprise Threat Coverage & Gap Analysis  
**Governing Principle:** `NO EVIDENCE → NO CLAIM`  
**Phase Status:** Phase 1 Read-Only Architecture & Truth Discovery  

---

## 1. Executive Summary

This document establishes the comprehensive threat coverage and gap matrix for **NivXRay XDR** across all **28 Enterprise Operational Domains (A through AB)**. 

While NivXRay XDR possesses a high-fidelity core library of 22 enterprise detection rules, 5 multi-stage correlation scenarios, and 22 response playbooks, enterprise-grade parity requires mapping current coverage against the complete attack surface, identifying exact telemetry prerequisites, analyzing industry source availability, and establishing risk-prioritized gap closures.

---

## 2. 28-Domain Enterprise Threat Coverage & Gap Analysis

The table below audits each of the 28 domains, detailing telemetry requirements, existing NivXRay content, missing coverage, industry source availability, translation difficulty, and implementation priority:

| Domain | Telemetry Required | Existing NivXRay Content | Genuine Gap | Industry Source Availability | Translation Difficulty | Priority |
| :--- | :--- | :--- | :--- | :--- | :---: | :---: |
| **A. Windows / Endpoint** | Sysmon (EIDs 1, 3, 7, 8, 10, 11, 13, 22), Windows Security (4688, 4624, 7045), PowerShell (4104) | `DET-EX-001` (Encoded PS), `DET-EX-002` (Certutil), `DET-EX-003` (Bitsadmin), `DET-EX-004` (WMI), `DET-EX-005` (Regsvr32), `DET-PS-001` (RunKey), `DET-PS-002` (SchTasks), `DET-PS-003` (SC.exe), `DET-DE-001` (Defender Kill), `DET-DE-002` (Wevtutil), `DET-DE-003` (AMSI Patch), `DET-CR-001` (LSASS), `DET-CR-002` (NTDS), `DET-LM-001` (PsExec), `DET-LM-002` (WinRM) | Driver loading (BYOVD), Process hollowing/injection primitives, Named pipe impersonation, Token manipulation. | Extremely High (SigmaHQ, Elastic, Splunk, Sentinel) | EXACT / STRONG | **P0** |
| **B. Linux** | Auditd (syscalls execve, connect, openat), eBPF / Tracepoints, Syslog, Auth.log | `DET-EX-006` (Pipe to Bash) | Cron persistence, systemd unit manipulation, LD_PRELOAD hijacking, rootkit / kernel module insertion, SUID abuse. | High (SigmaHQ, Elastic Detection Rules) | STRONG | **P1** |
| **C. macOS** | Apple Endpoint Security (ESF), Unified Logging System (ULS) | None | TCC bypass, LaunchAgent/LaunchDaemon persistence, dylib hijacking, osascript execution. | Moderate (SigmaHQ, Elastic, Red Canary) | STRONG | **P2** |
| **D. Active Directory** | Windows Security (4720, 4728, 4738, 5136, 5145), Directory Service Replication | `DET-DS-001` (SharpHound / AdFind) | DCSync (GetNCChanges via replication API), DCShadow, Golden Ticket, SID History injection, AdminSDHolder tampering. | High (SigmaHQ, Splunk Security Content, Sentinel) | STRONG | **P0** |
| **E. Entra ID (Azure AD)** | Microsoft Graph AuditLogs, Sign-in Logs (Interactive & Non-Interactive), Risk Detections | `DET-EM-001` (Service Principal Abuse) | Tenant-wide consent grant abuse, conditional access policy bypass, impossible travel velocity, PIM role activation anomalies. | High (Microsoft Sentinel, Panther Labs) | STRONG | **P0** |
| **F. Kerberos** | Windows Security Event Logs (4768, 4769, 4771), KDC Network Traffic | `DET-CR-004` (Kerberoasting), `DET-CR-005` (AS-REP Roasting) | Silver Ticket, Overpass-the-Hash, Unconstrained Delegation abuse, Resource-Based Constrained Delegation (RBCD). | High (SigmaHQ, Splunk, Elastic) | STRONG | **P0** |
| **G. AD CS** | Windows Security Event Logs (4886, 4887), CA Audit, Certificate Template Changes | `DET-PE-002` (AD CS Template ESC1 Abuse) | ESC2 through ESC14 abuse (vulnerable certificate authorities, NTLM relay to AD CS web enrollment, ESC8 HTTP endpoints). | Moderate (Public DFIR, SpecterOps research) | STRONG | **P0** |
| **H. M365 / Office 365** | Unified Audit Log (UAL), Exchange MailItemsAccessed, SharePoint / OneDrive Audit | `DET-PS-004` (Malicious Inbox Rule Creation) | Mass file download from OneDrive, tenant external sharing changes, eDiscovery abuse, mailbox delegate permission abuse. | High (Microsoft Sentinel, Splunk Content) | STRONG | **P1** |
| **I. Email / Messaging** | SMTP Gateway Logs, M365 Graph Message Trace, Phishing Detections, Header Analysis | `DET-IA-002` (Office Spawning Script Host) | BEC spoofing, display-name deception, OAuth consent phishing links, malicious QR codes (Quishing). | Moderate (SigmaHQ, Vendor Research) | PARTIAL | **P1** |
| **J. DNS** | Passive DNS logs, CoreDNS, Windows DNS Analytical Logs (EID 277), BIND query logs | `DET-CC-002` (DNS Tunneling Query Pattern) | Fast flux domains, DGA algorithmic domains, newly registered domain (NRD) resolution spikes, DNS rebinding. | High (SigmaHQ, Suricata, Splunk) | STRONG | **P1** |
| **K. VPN / Perimeter** | RADIUS / TACACS+ auth logs, IPsec / SSL-VPN session logs (GlobalProtect, AnyConnect, FortiGate) | None | Geo-velocity concurrent sessions, brute-force against portal, split-tunneling anomalies, credential stuffing. | High (Sigma, Splunk, Sentinel) | STRONG | **P1** |
| **L. Firewall** | NetFlow / IPFIX, Next-Gen Firewall (Palo Alto, Fortinet, Check Point) Threat Logs | Golden Snort Alert (Signature 2027865) | Long-lived low-bandwidth beaconing, outbound SSH/RDP on non-standard ports, port knocking, egress volume anomaly. | High (Snort, Suricata, Sigma) | EXACT | **P1** |
| **M. Proxy / SWG** | Squid, Zscaler, BlueCoat, Cloudflare Gateway access logs (URL, user-agent, MIME, bytes) | None | Direct IP access without Host header, rare user-agent strings, executable downloads from unclassified domains. | High (Sigma, Elastic, Splunk) | STRONG | **P1** |
| **N. AWS** | CloudTrail Management & Data Events, VPC Flow Logs, GuardDuty Findings | `DET-CR-006` (IMDS Credential Theft), `DET-PE-003` (IAM Policy Escalation) | KMS key destruction, S3 bucket public exposure, CloudTrail disablement/deletion, Lambda backdoor injection. | High (Elastic, Splunk, Panther, Sentinel) | STRONG | **P0** |
| **O. Azure** | Azure Activity Logs, Diagnostic Settings, Network Security Group (NSG) Flow Logs | None | Azure RunCommand VM execution, Storage Account SAS token generation, Managed Identity enumeration. | High (Microsoft Sentinel, Elastic) | STRONG | **P1** |
| **P. GCP** | Google Cloud Audit Logs (Admin Activity, Data Access), VPC Service Controls | None | Service account key export, Compute Engine startup script modification, BigQuery mass export. | Moderate (Elastic, Panther, Google SEC) | STRONG | **P1** |
| **Q. Kubernetes** | K8s API Audit Logs, Kubelet events, Admission Controller Webhooks | None | Privileged pod creation, hostPath mount abuse, anonymous API binding, ServiceAccount token exfiltration. | High (Elastic, Sigma, CNCF Research) | STRONG | **P1** |
| **R. Containers** | Containerd / Docker daemon events, cgroup modifications, seccomp violations | None | Container escape via CAP_SYS_ADMIN, namespace breakout, malicious container image ingress. | High (Sigma, Falco public rules, Elastic) | STRONG | **P1** |
| **S. VMware / ESXi** | ESXi Shell commands, syslog (/var/log/shell.log), hostd.log, vCenter Audit | `DET-IM-003` (ESXi Mass VM Destruction) | Hypervisor backdoor VIB package installation, VM snapshot tampering, vCenter CVE exploitation. | Moderate (Public DFIR, Vendor Threat Intel) | STRONG | **P1** |
| **T. Backup Infrastructure**| Veeam, Commvault, Rubrik audit logs, Windows VSS, storage snapshot APIs | `DET-IM-001` (Volume Shadow Copy Deletion) | Immutable backup retention tampering, backup encryption key deletion, mass repository wiping. | Moderate (Vendor research, CISA alerts) | STRONG | **P0** |
| **U. RMM (Remote Monitoring)**| Endpoint process execution, network sockets, service installations, command lines | `DET-CC-001` (Dual-Use RMM Execution) | Living-off-the-land RMM deployment (AnyDesk, ScreenConnect, Atera, RustDesk) without management authorization. | High (SigmaHQ, Elastic, Red Canary) | EXACT | **P0** |
| **V. SaaS Platforms** | Salesforce, ServiceNow, GitHub, Workday, Slack audit streams | None | Mass data export via API, OAuth third-party app authorization, admin privilege elevation. | Moderate (Panther, Splunk Security Content) | PARTIAL | **P2** |
| **W. DevOps / CI-CD** | GitHub Actions, GitLab CI, Jenkins audit logs, runner process events | None | Pipeline poison execution (PPE), runner credential exfiltration, malicious pull request workflow trigger. | Moderate (CISA, OpenSSF, StepSecurity) | STRONG | **P1** |
| **X. Non-Human Identities (NHI)**| Cloud IAM, Entra Service Principals, API Gateway auth tokens, Vault logs | `DET-EM-001` (Non-Human Identity Key Abuse) | Dormant SPN activation, certificate rotation evasion, high-privilege workload token theft. | Emerging (Public research, Wiz, Microsoft) | STRONG | **P0** |
| **Y. AI Agents** | AI Agent runtime traces, LLM proxy logs, tool execution call logs | `DET-EM-002` (Autonomous AI-Agent Subprocess Shell Exec) | Indirect prompt injection triggering unauthorized shell/network execution, agentic credential delegation abuse. | Emerging (OWASP GenAI, Public Research) | STRONG | **P1** |
| **Z. Data Exfiltration** | Network flow volume, DLP logs, cloud egress transfer metrics, USB storage events | None | Encrypted archive staging (7z/rar), cloud storage sync (Rclone), large upload to unsanctioned domain. | High (SigmaHQ, Elastic, Splunk) | STRONG | **P0** |
| **AA. Ransomware** | File modification velocity, file entropy, canary file alterations, VSS state | `DET-IM-004` (High-Velocity Encryption), `CORR-ENT-001` (Kill Chain Scenario) | Intermittent encryption, file renaming patterns, ransomware note dropping, network share encryption sweeps. | High (SigmaHQ, Elastic, DFIR research) | STRONG | **P0** |
| **AB. Supply Chain** | Package manager install logs (npm, pip, pypi, nuget), binary signature validation | None | Dependency confusion, typosquatting packages, trojanized binary updates, code signature tampering. | Moderate (CISA alerts, OpenSSF, ReversingLabs) | PARTIAL | **P1** |

---

## 3. Correlation Operator Gap Analysis (ICE 13-Operator Audit)

NivXRay XDR utilizes the **13 stateful correlation operators** implemented in [`backend/routers/xdr_correlation.py`](file:///d:/Projects/backend/routers/xdr_correlation.py):
1. `EVENT_MATCH`: Atomic attribute matching against canonical evidence fields.
2. `TEMPORAL`: Matches $N$ events occurring within a sliding time window $\Delta t$.
3. `TEMPORAL_ORDERED`: Matches events occurring in strict chronological order ($A \prec B \prec C$) within $\Delta t$.
4. `SEQUENCE`: Strict state-machine progression requiring exact transition ordering.
5. `COUNT`: Aggregates matches of a given pattern within a time window.
6. `THRESHOLD`: Triggers when an aggregated metric or count exceeds a defined cutoff.
7. `VALUE_COUNT`: Tracks count of distinct values for a field (e.g., distinct dest IPs).
8. `GROUP_BY`: Scopes correlation state per entity (`host_id`, `user_id`, `tenant_id`).
9. `ENTITY_CORRELATION`: Correlates evidence sharing common entity graph identifiers.
10. `CROSS_SOURCE`: Requires evidence from at least two distinct data source types (e.g., EDR + Firewall).
11. `CROSS_HOST`: Requires lateral progression across distinct host endpoints.
12. `CROSS_USER`: Tracks multi-account pivoting or credential hopping.
13. `NEGATIVE_EVIDENCE`: Evaluates the absence of an expected follow-up event (e.g. Auth without MFA challenge).

### Mapping 24 Critical Enterprise Scenarios to ICE Operators

| Scenario | Primary Required Operators | Can Existing ICE Express It? | Architectural Gap |
| :--- | :--- | :---: | :--- |
| **1. Ransomware Kill Chain** | `TEMPORAL_ORDERED`, `GROUP_BY(host_id)` | **YES** (Covered in `CORR-ENT-001`) | None. |
| **2. Phishing-to-C2 Transfer** | `TEMPORAL_ORDERED`, `CROSS_SOURCE`, `GROUP_BY(host_id)` | **YES** (Covered in `CORR-ENT-002`) | None. |
| **3. RMM Dual-Use Lateral Movement**| `SEQUENCE`, `CROSS_HOST`, `GROUP_BY(user_id)` | **YES** (Covered in `CORR-ENT-003`) | None. |
| **4. Cloud IMDS to IAM Escalation** | `TEMPORAL_ORDERED`, `GROUP_BY(user_id)` | **YES** (Covered in `CORR-ENT-004`) | None. |
| **5. AD Recon to AD CS Template Abuse**| `TEMPORAL_ORDERED`, `GROUP_BY(host_id)` | **YES** (Covered in `CORR-ENT-005`) | None. |
| **6. Kerberoasting + Lateral Pivot**| `EVENT_MATCH(4769)`, `TEMPORAL`, `CROSS_HOST` | **YES** | Rule content definition needed. |
| **7. AS-REP Roasting + Account Crack**| `EVENT_MATCH(4768)`, `TEMPORAL`, `CROSS_SOURCE` | **YES** | Rule content definition needed. |
| **8. DCSync Domain Replication Abuse**| `EVENT_MATCH(Directory Replication)`, `CROSS_SOURCE` | **YES** | Requires Directory Service event decoder. |
| **9. OAuth Consent Grant Hijacking** | `EVENT_MATCH`, `TEMPORAL_ORDERED`, `GROUP_BY(user_id)` | **YES** | Graph audit ingestion required. |
| **10. Cloud Session Token Theft** | `VALUE_COUNT(ip_address)`, `THRESHOLD(>1)`, `TEMPORAL` | **YES** | Token IP geolocation anomaly tracking. |
| **11. MFA Fatigue / Push Spamming** | `COUNT`, `THRESHOLD(>5)`, `TEMPORAL`, `NEGATIVE_EVIDENCE` | **YES** | Detects repeated denials followed by approval. |
| **12. VPN Compromise + Anomaly Velocity**| `TEMPORAL`, `CROSS_HOST`, `CROSS_SOURCE` | **YES** | Geolocation distance delta calculation. |
| **13. Credential Theft to Lateral Movement**| `TEMPORAL_ORDERED`, `CROSS_HOST`, `ENTITY_CORRELATION`| **YES** | Standard progression pattern. |
| **14. Multi-Stage C2 Beaconing** | `COUNT`, `THRESHOLD`, `TEMPORAL`, `VALUE_COUNT` | **YES** | Periodic jitter calculation. |
| **15. Exfiltration via Cloud Storage**| `THRESHOLD(bytes_out)`, `CROSS_SOURCE`, `GROUP_BY` | **YES** | Network egress baseline tracking. |
| **16. Backup Destruction + Ransomware**| `TEMPORAL_ORDERED`, `CROSS_SOURCE`, `ENTITY_CORRELATION`| **YES** | Backup API event ingestion needed. |
| **17. VMware ESXi VM Wiping** | `EVENT_MATCH`, `COUNT`, `GROUP_BY(host_id)` | **YES** | Covered by `DET-IM-003`. |
| **18. Kubernetes Cluster Takeover** | `SEQUENCE`, `CROSS_SOURCE`, `GROUP_BY(namespace)` | **YES** | K8s API audit log ingestion needed. |
| **19. Container Escape to Host Root**| `TEMPORAL_ORDERED`, `ENTITY_CORRELATION` | **YES** | Container ID to host PID namespace bridge. |
| **20. Supply Chain Build Tampering** | `TEMPORAL_ORDERED`, `CROSS_SOURCE`, `NEGATIVE_EVIDENCE` | **YES** | Missing code review check + modified binary. |
| **21. CI/CD Runner Token Exfiltration**| `TEMPORAL_ORDERED`, `GROUP_BY(runner_id)` | **YES** | Pipeline step log parsing required. |
| **22. Non-Human Identity Key Rotation Abuse**| `SEQUENCE`, `TEMPORAL`, `GROUP_BY(spn_id)` | **YES** | Covered by `DET-EM-001`. |
| **23. Autonomous AI Agent Unauthorized Shell**| `EVENT_MATCH`, `GROUP_BY(principal_id)` | **YES** | Covered by `DET-EM-002`. |
| **24. Living-off-the-Land Binary Chain**| `SEQUENCE`, `GROUP_BY(process_lineage)` | **YES** | Parent-child lineage tracing in IKG. |

### Summary of Correlation Engine Gaps
The 13 correlation operators in `routers/xdr_correlation.py` possess complete mathematical and structural expressiveness to model all 24 industry scenarios. **No second correlation engine is required.** The primary operational gap is the ingestion and normalization of specific upstream telemetry feeds (K8s audit, M365 UAL, cloud flow logs) so that canonical evidence feeds these operators.

---

## 4. Telemetry Ingestion Gaps

NivXRay currently provides native DSM and parser implementations for:
- Snort / Suricata EVE JSON (`snort-eve`)
- Syslog RFC 5424 / 3164
- Windows Event Logs (Process Creation, PowerShell 4104)
- Palo Alto Cortex XDR alert ingestion

### Upstream Telemetry Ingest Needs for Full Enterprise Parity
To feed the canonical evidence store for domains A through AB, the following DSMs and parsers represent the highest priority ingestion gaps:
1. **Windows Security EVD DSM**: Ingesting Event IDs 4688, 4624, 4768, 4769, 4720, 7045.
2. **Linux Auditd / eBPF DSM**: Parsing structured syscall audit records (`SYSCALL`, `EXECVE`, `PROCTITLE`, `SOCKADDR`).
3. **AWS CloudTrail DSM**: Parsing multi-region JSON audit event envelopes.
4. **M365 Unified Audit Log (UAL) DSM**: Parsing Azure AD, Exchange, and SharePoint operations.
5. **DNS Analytical DSM**: Parsing high-volume DNS queries and responses.

---

## 5. Prioritized Gap Closure Roadmap

```
╔════════════════════════════════════════════════════════════════════════════╗
║                   NIVXRAY XDR CONTENT GAP CLOSURE ROADMAP                  ║
╠════════════════════════════════════════════════════════════════════════════╣
║ PHASE 1 (CURRENT): Read-Only Architecture & Truth Discovery Audit           ║
║   • Complete current truth reconciliation (COMPLETED)                      ║
║   • Establish source acquisition and license models (COMPLETED)            ║
║   • Define canonical content schema and translation grammar (COMPLETED)    ║
║                                                                            ║
║ PHASE 2 (PLANNED): Ingestion DSM & Parser Expansion (P0 Telemetry)          ║
║   • Implement Windows Security Event Log DSM (4688, 4768, 4769, 7045)      ║
║   • Implement Linux Auditd DSM & Syslog CEF/LEEF parser                    ║
║   • Implement AWS CloudTrail & M365 UAL JSON parsers                       ║
║                                                                            ║
║ PHASE 3 (PLANNED): Source Ingestion & Deduplication Pipeline Execution     ║
║   • Ingest public SigmaHQ rules (Process Creation, Network, Identity)      ║
║   • Ingest public Splunk Security Content and Elastic detection analytics  ║
║   • Apply deterministic AST deduplication and generate canonical models    ║
║                                                                            ║
║ PHASE 4 (PLANNED): Quality Gate Validation & Engine Binding                ║
║   • Execute Tier 1 (1 pos + 1 neg fixture) on all candidates               ║
║   • Execute Tier 2 (regression + false positive profiles)                  ║
║   • Promote passing rules to ENGINE_BOUND and SHADOW mode                   ║
║                                                                            ║
║ PHASE 5 (PLANNED): Correlation & Security State Causal Enrichment          ║
║   • Bind multi-stage correlation scenarios to streaming event bus          ║
║   • Contextualize dual-use detections against Causal Security State        ║
║   • Measure residual risk reduction and attack reachability severance      ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---
*End of Enterprise Content Gap Matrix.*
