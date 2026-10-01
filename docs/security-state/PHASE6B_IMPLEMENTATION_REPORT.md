# NivXRay Security State — Phase 6B Implementation Report
## Extended Causal Rule Engine & Dual-Use Behavioral Library

**Phase**: Phase 6B  
**Mode**: `NIVX_FLAG_SECURITY_STATE = SHADOW`  
**Execution Safety**: `AUTO_RESPONSE = FALSE`, `EXECUTE = LOCKED`  
**Enterprise Graph SSOT**: Authoritative Investigation Knowledge Graph (IKG) — Zero Duplication  
**Status**: 🟢 **VERIFIED / IMPLEMENTED**

---

### Executive Summary

Phase 6B expands the NivXRay Security State subsystem with an advanced, deterministic causal intelligence layer. It directly addresses the challenge of advanced attacker tradecraft by distinguishing dual-use administrative tooling (LOLBAS, Active Directory administrative utilities, remote administration tools) from weaponized exploitation without hardcoded, brittle signature rules.

Rather than treating attacker techniques as isolated point-in-time detections, Phase 6B models behaviors as **reusable deterministic capability primitives** operating along the formal progression:
$$\text{Capability} \longrightarrow \text{Context} \longrightarrow \text{Causality} \longrightarrow \text{Attack State} \longrightarrow \text{Attacker Capability} \longrightarrow \text{Reachability} \longrightarrow \text{Impact}$$

Every causal deduction preserves unbroken provenance back to underlying raw telemetry frames, maintains strict epistemic separation across 10 formal terms, and evaluates reachability across multi-host environments by referencing existing IKG nodes rather than instantiating a duplicate graph.

---

### 1. Architectural Guardrails & Invariants

| Boundary / Invariant | Enforcement Mechanism | Verification Status |
| :--- | :--- | :--- |
| **Authoritative Pipeline Purity** | Read-only observation of authoritative Case, Verdict, Attack Story, and IKG. Zero mutation to existing pipeline records. | 🟢 **PASS** (P6B-08) |
| **Zero IKG Duplication** | Lateral traversal and reachability engines query `ikg_nodes` (`device::{host}`) directly as enterprise graph of record. | 🟢 **PASS** (P6B-04) |
| **Unbroken Provenance DAG** | Every Causal Fact, Attack State, and Reachability Path references its underlying `evidence_ids`. | 🟢 **PASS** (P6B-07) |
| **10-Term Epistemic Discipline** | Discrete vocabulary distinguishing facts (`OBSERVED`, `SUPPORTED`), derivations (`DERIVED`), projections (`PROJECTED`), and competing hypotheses (`POSSIBLE`, `UNSUPPORTED`). | 🟢 **PASS** (P6B-06) |
| **Response Safety Gate** | Reversal actions are proposed for human staging only; `auto_execute=False` and `is_locked=True` are strictly enforced. | 🟢 **PASS** (P6B-09) |

---

### 2. Dual-Use Behavioral Library (`capability/engine.py`)

The Dual-Use Behavioral Library resolves the ambiguity inherent in dual-use administrative software (LOLBAS, RMM, AD administrative tools) by evaluating actions across 11 contextual dimensions rather than simple process-name matching.

#### 2.1 Capability Categories
Administrative and system binaries are classified into behavioral categories:
- `REMOTE_ADMINISTRATION`: Tools like `psexec`, `anydesk`, `teamviewer`, `screenconnect`, `logmein`.
- `SHELL_AND_SCRIPTING`: `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `bash`.
- `BINARY_PROXY_EXECUTION`: LOLBins such as `certutil.exe`, `bitsadmin.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`, `wmic.exe`, `installutil.exe`, `msbuild.exe`, `csc.exe`.
- `DIRECTORY_AND_IDENTITY_SERVICE`: `dsquery.exe`, `ntdsutil.exe`, `adfind.exe`, `nltest.exe`, `klist.exe`, `csvde.exe`, `ldifde.exe`.
- `REMOTE_PROCESS_INVOCATION`: `wmic process call create`, `winrs`, `sc.exe`, `schtasks.exe`.
- `GENERAL_UTILITY`: General operating system utilities.

#### 2.2 11-Dimensional Contextual Evaluation Matrix
Every capability evaluation evaluates:
1. **Identity & Authorization Context**: Is the identity authorized for administrative operations?
2. **Parent Process Lineage**: Was the process spawned by office apps (`word.exe`), web servers (`w3wp.exe`), or suspicious parents?
3. **Temporal Maintenance Context**: Did execution occur within approved maintenance/business windows?
4. **Inbound Tunneling / Reverse Proxy**: Did execution originate over reverse proxies or suspicious tunnels?
5. **Command-Line Weaponization**: Evidence of `-enc`, `downloadstring`, `-urlcache`, `scrobj.dll`, or obfuscation?
6. **Credential Store Interaction**: Direct referencing of `lsass`, `sam`, `minidump`, `secretsdump`?
7. **AD Replication Abuse Primitives**: Direct DRSUAPI RPC (`drsgetncchanges`, `lsadump::dcsync`)?
8. **Kerberos TGS Request Primitives**: Bulk SPN harvesting and ticket extraction (`getuserspns`, `kerberoast`)?
9. **Process Token Privilege Mismatch**: High-integrity/SYSTEM execution from unprivileged lineage?
10. **Corroborating Telemetry Footprint**: Dual network and file-drop events corroborating proxy execution?
11. **Competing Benign Hypothesis Corroboration**: Routine administrative maintenance reduces score when all parameters are nominal.

```
+-------------------------------------------------------------------------------+
|                      Dual-Use Evaluation Pipeline                             |
|                                                                               |
|  [Raw Event] ---> [Categorize Tool] ---> [11-Dimensional Scoring Matrix]      |
|                                                    |                          |
|         +------------------------------------------+                          |
|         |                                                                     |
|         v                                                                     |
|  Score >= 80: CONFIRMED_ATTACK   (e.g., certutil -urlcache payload download)  |
|  Score >= 55: ABUSED_CAPABILITY  (e.g., unauthorized RMM session)             |
|  Score >= 35: SUSPICIOUS_USE     (e.g., off-hours ad-hoc admin script)        |
|  Score >= 15: ANOMALOUS_USE      (e.g., new script parameter)                 |
|  Score <  15: AUTHORIZED_USE     (e.g., approved certutil verify)             |
+-------------------------------------------------------------------------------+
```

---

### 3. Extended Deterministic Causal Engine (`causal/engine.py`)

The causal engine deduces deterministic cause-effect links between canonical evidence events. Rather than relying on generic temporal clustering, the engine prioritizes specialized domain attack transitions:

#### 3.1 Active Directory DCSync Replication Chain
- **Mechanism**: `CausalMechanismType.DIRECTORY_REPLICATION_RPC`
- **Pattern**: An endpoint executes an AD replication primitive (`ntdsutil`, `secretsdump`, `drsgetncchanges`) targeting domain controller replication endpoints.
- **Hypothesis Validation**:
  - If source is an authorized Domain Controller $\rightarrow$ Classify as legitimate replication (`hyp-legit-dc-replication`).
  - If source is a workstation or unauthorized server $\rightarrow$ Classify as weaponized DCSync credential extraction (`hyp-dcsync-credential-theft`).
- **Epistemic Status**: `SUPPORTED` (Causal Fact) $\rightarrow$ `DERIVED` (Attack State: `CREDENTIAL_ACCESS`).

#### 3.2 Kerberoasting Causal Chain
- **Mechanism**: `CausalMechanismType.KERBEROS_TGS_REQUEST`
- **Pattern**: SPN enumeration (`dsquery`, `getuserspns`, `rubeus`) followed immediately by high-volume Kerberos Ticket Granting Service (`TGS-REQ`) requests for service accounts.
- **Competing Hypothesis**: Routine single-ticket Kerberos authentication (`hyp-legit-spn-auth`).
- **Epistemic Status**: `SUPPORTED` (Causal Fact) $\rightarrow$ `DERIVED` (Attack State: `CREDENTIAL_ACCESS`).

#### 3.3 LOLBAS Proxy Execution Chain
- **Mechanism**: `CausalMechanismType.LOLBAS_PROXY_EXECUTION`
- **Pattern**: Dual-use binary (`certutil`, `bitsadmin`, `mshta`) performing network outbound retrieval (`HTTP_GET`) coupled with disk persistence / script execution.
- **Competing Hypothesis**: Legitimate certificate CRL validation / software update (`hyp-admin-cert-validation`).
- **Epistemic Status**: `SUPPORTED` (Causal Fact) $\rightarrow$ `DERIVED` (Attack State: `DEFENSE_EVASION`).

#### 3.4 Multi-Host Lateral Traversal Chain
- **Mechanism**: `CausalMechanismType.REMOTE_WMI_PROCESS_CALL` / `SMB_NAMED_PIPE_EXECUTION`
- **Pattern**: Source host authenticates over SMB/WMI to remote target host followed immediately by process creation on target (`10.0.0.51` $\rightarrow$ `10.0.0.52`).
- **Competing Hypothesis**: Centralized SCCM/IT deployment (`hyp-sccm-admin-push`).
- **Enterprise Graph Integration**: Operates directly over existing IKG device entities (`device::{host-id}`) without duplicating the graph.
- **Epistemic Status**: `SUPPORTED` (Causal Fact) $\rightarrow$ `DERIVED` (Attack State: `LATERAL_MOVEMENT`).

---

### 4. Attack State Machine & Reachability Integration

#### 4.1 Attack State Escalation Rules (`state_engine/engine.py`)
Deterministic deduction rules map validated causal mechanisms into formalized attack states:
1. `RULE_LOLBAS_PROXY_EXECUTION`: LOLBAS proxy execution maps directly to `AttackState.DEFENSE_EVASION` with `CAP_LOLBAS_EXECUTION`.
2. `RULE_KERBEROASTING_ACTIVITY`: Kerberoasting causal chain maps directly to `AttackState.CREDENTIAL_ACCESS` with `CAP_KERBEROASTING`.
3. `RULE_DCSYNC_REPLICATION_ABUSE`: DCSync replication abuse maps to `AttackState.CREDENTIAL_ACCESS` with `CAP_DCSYNC` and `CAP_AD_REPLICATION_ABUSE`.
4. `RULE_MULTI_HOST_TRAVERSAL`: Remote WMI/SMB process execution across hosts advances state to `AttackState.LATERAL_MOVEMENT` with `CAP_MULTI_HOST_TRAVERSAL`.

#### 4.2 Multi-Host Reachability Engine (`reachability/engine.py`)
The reachability engine projects potential attacker traversal paths based on acquired attacker capabilities:
- **`CAP_DCSYNC`**: Direct path to Enterprise Domain Controllers (`asset-dc-01`) via `DIRECTORY_REPLICATION_RPC`.
- **`CAP_KERBEROASTING`**: Direct path to Database Service Principal Names (`asset-db-spn-01`) via offline TGS cracking.
- **`CAP_MULTI_HOST_TRAVERSAL`**: Direct traversal to adjacent endpoints extracted dynamically from authoritative IKG nodes (`device::host-02`).
- **Impact Decoupling**: Target impact values are decoupled from reachability probabilities: reachability probability is projected (`PROJECTED`) based on attacker capability, while target asset valuation remains fixed.

---

### 5. Architectural Verification & Zero-Regression Summary

All existing phases and gates were validated through the master test runner:
- **Core Security State Suite**: 8/8 tests passed
- **Phase 2C Real Investigation Replay**: 6/6 tests passed
- **Phase 3 Persistent Ledger & SQLite Concurrency**: 10/10 tests passed
- **Phase 3B Multi-Process Distributed Lock & Ledger Integrity**: 7/7 challenges passed
- **Phase 4C Streaming Adapter & Replay Equivalence**: 10/10 tests passed
- **Phase 4C.1 Independent Adversarial Audit**: 8/8 audits passed
- **Phase 5 Platform Shadow Integration & Cockpit API**: 12/12 gates passed
- **Phase 6B Extended Causal Rule Engine Suite**: 10/10 acceptance gates passed

Total Suite: **71/71 tests PASS** (100% deterministic green).
