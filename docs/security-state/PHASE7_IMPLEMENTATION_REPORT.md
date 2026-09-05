# NivXRay Security State — Phase 7 Implementation Report
## Enterprise Security Intelligence & Temporal Attack Progression Engine

**Phase**: Phase 7  
**Subsystem**: NivXRay Security State + Causal Intelligence Core  
**Mode**: `NIVX_FLAG_SECURITY_STATE = SHADOW`  
**Execution Safety**: `AUTO_RESPONSE = FALSE`, `EXECUTE = LOCKED`  
**Graph of Record**: Authoritative Investigation Knowledge Graph (IKG) — Zero Duplication  
**Status**: 🟢 **IMPLEMENTED & VERIFIED**

---

### Executive Overview

Phase 7 elevates the NivXRay Security State subsystem from static snapshot analysis to a continuous, **evidence-grounded temporal attack-progression reasoning engine**. Rather than merely asking *“Did an alert fire?”* or computing a black-box probability, Phase 7 answers the seven fundamental questions of enterprise security intelligence:

1. **“What happened?”** — Verified causal mechanisms with kernel and protocol evidence.
2. **“What is happening right now?”** — Continuous progression state across `PRE_ATTACK` $\rightarrow$ `ACTIVE_ATTACK` $\rightarrow$ `CONTAINED` $\rightarrow$ `POST_ATTACK`.
3. **“How likely is this attack trajectory?”** — Deterministic Likelihood/Risk Score grounded in completed stages, observed evidence, refutations, and missing telemetry (never claimed as uncalibrated statistical probability).
4. **“What is the attacker expected to do next?”** — Explicitly segregated projections badged `PROJECTED`.
5. **“What can the attacker reach?”** — Multi-host and cloud reachability dynamically traversing the authoritative Investigation Knowledge Graph (IKG) without duplicate graph databases.
6. **“If we do nothing, what happens?”** — Decoupled impact projections across Tier-0 and Tier-1 enterprise assets.
7. **“After containment, can they still continue or re-enter?”** — Decoupled post-attack residual risk evaluating dormant persistence, unrevoked Kerberos tickets, open lateral paths, and backup accessibility.

---

### 1. Architectural Guardrails & Locks

| Architectural Lock | Contract Definition | Enforcement Mechanism |
| :--- | :--- | :--- |
| **Likelihood $\neq$ Probability** | Risk scores must never be claimed as statistical probabilities unless calibrated against a labeled corpus. | Grounded composite score exposing `completed_stages`, `progression_ratio`, `supporting_evidence_ids`, `contradictory_evidence_ids`, `missing_telemetry_indicators`, and `explicit_assumptions`. |
| **Prediction $\neq$ Evidence** | Projections must never be collapsed into observed telemetry. | Strict epistemic separation: `OBSERVED` (sensor frame) $\rightarrow$ `SUPPORTED` (causal fact) $\rightarrow$ `DERIVED` (state) $\rightarrow$ `PROJECTED` (future actions) $\rightarrow$ `ASSUMED` (contextual priors). |
| **Continuous Lifecycle Model** | One continuous state model across all attack phases. | `PRE_ATTACK` $\rightarrow$ `POSSIBLE` $\rightarrow$ `LIKELY` $\rightarrow$ `SUPPORTED` $\rightarrow$ `CONFIRMED_ATTACK` $\rightarrow$ `CONTAINED` $\rightarrow$ `POST_ATTACK` $\rightarrow$ `RESIDUAL_RISK` $\rightarrow$ `RE_ENTRY_EXPOSURE`. |
| **Post-Attack Residual Risk Separation** | Disentangles active execution from environmental vulnerability. | Evaluates two distinct questions: A) `attack_is_active: bool`, and B) `environment_is_vulnerable: bool`. |
| **Zero IKG Duplication** | Never instantiate a parallel graph, secondary tables, or duplicate nodes. | Multi-host lateral reachability queries existing IKG entities (`device::{id}`, `cloud_resource::{id}`) directly. |
| **Authoritative Invariance** | Zero modification to existing NivXRay pipeline. | Authoritative Case Verdict, Attack Story, and IKG remain byte-identical before and after evaluation. |
| **Response Safety Gate** | Automated response execution is hard-locked. | `AUTO_RESPONSE = FALSE`, `is_locked = True`. |

---

### 2. Temporal Attack Progression Engine (`progression/engine.py`)

The `TemporalProgressionEngine` evaluates the continuous temporal continuum across five multi-stage enterprise attack blueprints:
1. **Kerberoasting Credential Harvesting**
   - Stage 1: `SPN_ENUMERATION` (e.g. `Get-NetUser -SPN`, `dsquery`)
   - Stage 2: `ANOMALOUS_ACCOUNT_DISCOVERY` (querying privileged accounts with `serviceprincipalname`)
   - Stage 3: `TGS_TICKET_EXTRACTION` (high-frequency Kerberos Event 4769 with RC4 ciphers)
   - Stage 4: `OFFLINE_TICKET_CRACKING` (ticket export or hashcat/john cracking)
   - Stage 5: `PRIVILEGED_SERVICE_PIVOT` (lateral authentication using cracked credential)
2. **Remote Monitoring & Management (RMM) Takeover**
   - Stage 1: `RMM_BINARY_STAGING` (silent download/staging of AnyDesk, RustDesk, ScreenConnect, NinjaOne)
   - Stage 2: `SERVICE_INSTALLATION` (silent service creation under SYSTEM)
   - Stage 3: `TUNNEL_EGRESS_ESTABLISHED` (outbound persistent reverse tunnel to relay infrastructure)
   - Stage 4: `INTERACTIVE_COMMAND_CONTROL` (command shell invocation under RMM worker)
   - Stage 5: `CREDENTIAL_HARVEST_AND_PIVOT` (credential dumping and lateral subnet traversal)
3. **Ransomware Destruction Precursor**
   - Stage 1: `DEFENSE_EVASION_STAGING` (scriptlet/proxy loader disabling defenses)
   - Stage 2: `VSS_SNAPSHOT_PURGE` (`vssadmin delete shadows /all /quiet`)
   - Stage 3: `BACKUP_CATALOG_DELETION` (`wbadmin delete catalog -quiet`)
   - Stage 4: `HYPERVISOR_VM_TERMINATION` (`esxcli vm process kill` in bulk)
   - Stage 5: `BULK_ENCRYPTION_AND_IMPACT` (file encryption and ransom note staging)
4. **Cloud Instance Metadata Service (IMDS) Pivot**
   - Stage 1: `HOST_COMPROMISE` (workload/container foothold)
   - Stage 2: `IMDS_METADATA_SCRAPE` (querying link-local `169.254.169.254`)
   - Stage 3: `TEMPORARY_TOKEN_ACQUISITION` (extracting IAM role security credentials)
   - Stage 4: `CLOUD_API_PIVOT` (calling cloud control plane APIs using stolen session token)
   - Stage 5: `CLOUD_DATA_EXFILTRATION` (bulk exfiltration of S3/blob storage)
5. **Active Directory Certificate Services (AD CS) Abuse**
   - Stage 1: `PKI_TEMPLATE_ENUMERATION` (`certify find /vulnerable`)
   - Stage 2: `MISCONFIGURED_TEMPLATE_REQUEST` (enrollee supplies privileged SAN)
   - Stage 3: `FORGED_CERTIFICATE_ISSUANCE` (valid certificate issued for Domain Admin)
   - Stage 4: `PKINIT_AUTHENTICATION` (requesting TGT using forged certificate)
   - Stage 5: `DOMAIN_ADMIN_TAKEOVER` (Active Directory forest compromise)

#### 2.1 Pre-Attack Grounded Assessment Example
```json
{
  "phase": "PRE_ATTACK",
  "epistemic_status": "LIKELY",
  "risk_score": 64.0,
  "chain_name": "Kerberoasting Credential Harvesting",
  "completed_stages": ["SPN_ENUMERATION", "ANOMALOUS_ACCOUNT_DISCOVERY"],
  "total_expected_stages": 5,
  "progression_ratio": 0.400,
  "supporting_evidence_ids": ["ev-p7-01a", "ev-p7-01b"],
  "contradictory_evidence_ids": [],
  "missing_telemetry_indicators": [
    "Kerberos TGS request security log (Event 4769) from Domain Controller"
  ],
  "next_expected_behaviors": [
    "PROJECTED: Attacker will request service tickets (TGS-REQ) for enumerated SPNs with RC4 cipher"
  ],
  "potential_impact_projection": "PROJECTED: Lateral privilege escalation to Database and Domain Controller infrastructure via cracked service tickets",
  "explicit_assumptions": [
    "ASSUMED: Service accounts hold unconstrained delegation or local admin rights on tier-1 servers"
  ]
}
```

---

### 3. Post-Attack Residual Risk & Re-entry Exposure

When an attacker process is terminated or an endpoint is isolated, traditional detection systems close the alert. NivXRay Security State explicitly evaluates **Post-Attack Residual Risk**:

```
[Containment Action Executed: endpoint.terminate_process]
                   │
                   ▼
       Is Attacker Active?
             NO: attack_is_active = FALSE
                   │
                   ▼
       Is Environment Still Vulnerable?
             YES: environment_is_vulnerable = TRUE
             ├── Active Directory Kerberos Service Tickets not yet revoked
             ├── Adjacent reachable enterprise endpoints open in IKG (SMB/RPC ports)
             └── Local Volume Shadow Copies purged (disaster recovery unverified)
                   │
                   ▼
       Re-entry Risk Level: LIKELY
       Recommended Remediation Locks:
             ├── identity.revoke_kerberos_tickets
             ├── identity.rotate_krbtgt_keys
             └── network.enforce_segmentation_isolation
```

---

### 4. Enterprise Causal Mechanisms (`causal/engine.py`)

Deterministic causal transitions with explicit competing administrative hypotheses:
1. `REMOTE_ADMINISTRATION_TUNNEL`: RMM session egress vs. `hyp-authorized-it-support`.
2. `VSS_NTDS_EXTRACTION`: `ntds.dit` volume shadow copy dump vs. `hyp-scheduled-system-state-backup`.
3. `KERBEROS_ASREP_ROAST`: Pre-auth disabled AS-REQ vs. `hyp-legacy-kerberos-app-auth`.
4. `CERTIFICATE_SERVICES_ENROLLMENT_RPC`: AD CS ESC1 template enrollment vs. `hyp-authorized-pki-certificate-issuance`.
5. `METADATA_SERVICE_TOKEN_EXTRACTION`: IMDS link-local query vs. `hyp-legit-cloud-agent-imds`.
6. `VSS_SNAPSHOT_DELETION` & `BACKUP_CATALOG_DELETION`: Recovery destruction vs. `hyp-automated-storage-reclaim`.
7. `ESXI_VIRTUAL_MACHINE_KILL`: Hypervisor process termination vs. `hyp-hypervisor-cluster-patching`.

---

### 5. Multi-Host Reachability & IKG Graph of Record (`reachability/engine.py`)

The reachability engine traverses enterprise targets directly from authoritative IKG topology:
- **Domain Controllers (Tier 0)**: Reachable via `CAP_DCSYNC`, `CAP_NTDS_EXTRACTION`, or `CAP_ADCS_ABUSE`.
- **Immutable Backup Storage (Tier 0)**: Reachable via `CAP_SHADOW_COPY_DELETION` or `CAP_BACKUP_TAMPERING`.
- **Core Database Servers (Tier 1)**: Reachable via `CAP_KERBEROASTING`.
- **Cloud Enterprise Data Vaults (Tier 0)**: Reachable via `CAP_CLOUD_METADATA_ACCESS` or `CAP_CLOUD_TOKEN_THEFT`.
- **Adjacent Endpoints & Hosts (Tier 2)**: Dynamically ingested from authoritative IKG nodes (`device::{id}`). Zero duplicate graph tables or secondary databases created.
