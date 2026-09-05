# NivXRay Security State — Phase 6B Handoff Document

**Phase**: Phase 6B — Extended Causal Rule Engine & Dual-Use Behavioral Library  
**Date**: 2026-09-04  
**Status**: 🟢 **PHASE 6B CLOSED AND VERIFIED**  
**Previous Milestones**: Phase 1–3, Phase 3B, Phase 4C, Phase 4C.1, Phase 5 (All CLOSED and IMMUTABLE)  
**Next Recommended Milestone**: **Phase 6C — Browser E2E Cockpit Validation**

---

### 1. Milestone Summary

Phase 6B successfully implements the Extended Causal Rule Engine and Dual-Use Behavioral Library for the NivXRay Security State subsystem. 

Key technical achievements:
1. **Dual-Use Behavioral Library**: Evaluates administrative and LOLBAS tools across 11 contextual dimensions to reliably distinguish legitimate system administration from weaponized proxy execution.
2. **Deterministic Causal Transitions**: Implemented domain-specific causal chains for Active Directory DCSync (`DIRECTORY_REPLICATION_RPC`), Kerberoasting (`KERBEROS_TGS_REQUEST`), LOLBAS proxy staging (`LOLBAS_PROXY_EXECUTION`), and remote lateral movement (`REMOTE_WMI_PROCESS_CALL` / `SMB_NAMED_PIPE_EXECUTION`).
3. **Competing Hypotheses Discipline**: Explicitly evaluates benign administrative hypotheses alongside threat hypotheses before assigning causal attribution.
4. **Zero IKG Duplication**: Multi-host reachability directly utilizes the authoritative Investigation Knowledge Graph (IKG) nodes (`device::{id}`) without creating a parallel graph.
5. **Epistemic & Provenance Integrity**: Preserved 10 formal epistemic statuses and unbroken provenance traces from raw telemetry frames through causal facts to derived attack states.
6. **Platform Invariance**: Authoritative Case Verdict, Attack Story, and IKG are unmodified; response execution remains strictly locked.

---

### 2. Public Contracts & Interfaces Added / Extended

#### 2.1 Contracts (`backend/security_state/contracts.py`)
- **`EpistemicStatus` (Enum)**:
  - Facts: `OBSERVED`, `SUPPORTED`
  - Derivations & Inferences: `DERIVED`, `LIKELY`, `POSSIBLE`
  - Projections & Assumptions: `PROJECTED`, `ASSUMED`
  - Contradictions & Rejections: `UNSUPPORTED`, `CONTRADICTED`, `DISPROVEN`
- **`CausalMechanismType` (Enum)**:
  - Extended with: `LOLBAS_PROXY_EXECUTION`, `KERBEROS_TGS_REQUEST`, `DIRECTORY_REPLICATION_RPC`, `REMOTE_WMI_PROCESS_CALL`, `SMB_NAMED_PIPE_EXECUTION`.
- **`StandardCapabilities`**:
  - `CAP_LOLBAS_EXECUTION = "cap.lolbas_execution"`
  - `CAP_KERBEROASTING = "cap.kerberoasting"`
  - `CAP_DCSYNC = "cap.dcsync"`
  - `CAP_AD_REPLICATION_ABUSE = "cap.ad_replication_abuse"`
  - `CAP_MULTI_HOST_TRAVERSAL = "cap.multi_host_traversal"`

#### 2.2 Capability Engine (`backend/security_state/capability/engine.py`)
- **`CapabilityCategory` (Enum)**:
  - Categorizes tools into `REMOTE_ADMINISTRATION`, `SHELL_AND_SCRIPTING`, `BINARY_PROXY_EXECUTION`, `DIRECTORY_AND_IDENTITY_SERVICE`, `REMOTE_PROCESS_INVOCATION`, `GENERAL_UTILITY`.
- **`DualUseCapabilityEngine.evaluate_capability()`**:
  - Ingests `CapabilityContext` and evaluates across 11 dimensions. Returns `CapabilityAbuseEvaluation` with calculated score, confidence, reasoning, and optional reversal recommendation.

#### 2.3 Causal Engine (`backend/security_state/causal/engine.py`)
- **`CausalEngine.evaluate_causality()`**:
  - Evaluates specialized attack chains prior to generic process fallback. Produces deterministic `CausalFact` objects with explicit `competing_hypotheses`.

#### 2.4 State Machine & Reachability (`state_engine/engine.py`, `reachability/engine.py`)
- **`AttackStateMachine.evaluate_state()`**:
  - Evaluates `RULE_LOLBAS_PROXY_EXECUTION`, `RULE_KERBEROASTING_ACTIVITY`, `RULE_DCSYNC_REPLICATION_ABUSE`, and `RULE_MULTI_HOST_TRAVERSAL`.
- **`MultiHostReachabilityEngine.evaluate_reachability()`**:
  - Traverses existing IKG topology (`device::{id}`) without graph duplication; projects attack paths based on `CAP_DCSYNC`, `CAP_KERBEROASTING`, and `CAP_MULTI_HOST_TRAVERSAL`.

---

### 3. File Inventory

#### 3.1 Implementation Files Modified
- [`backend/security_state/contracts.py`](file:///d:/Projects/backend/security_state/contracts.py): Added epistemic statuses, causal mechanisms, and capability constants.
- [`backend/security_state/capability/engine.py`](file:///d:/Projects/backend/security_state/capability/engine.py): Added `CapabilityCategory`, LOLBAS/AD registries, and 11-dimensional contextual scoring matrix.
- [`backend/security_state/capability/__init__.py`](file:///d:/Projects/backend/security_state/capability/__init__.py): Exported `CapabilityCategory`.
- [`backend/security_state/causal/engine.py`](file:///d:/Projects/backend/security_state/causal/engine.py): Implemented specialized causal attack chains (DCSync, Kerberoasting, LOLBAS, Remote WMI) and competing hypotheses.
- [`backend/security_state/state_engine/engine.py`](file:///d:/Projects/backend/security_state/state_engine/engine.py): Added deduction rules for Phase 6B attack states and capabilities.
- [`backend/security_state/hydration/case_hydrator.py`](file:///d:/Projects/backend/security_state/hydration/case_hydrator.py): Extracted Phase 6B capabilities and forwarded IKG nodes to reachability.
- [`backend/security_state/reachability/engine.py`](file:///d:/Projects/backend/security_state/reachability/engine.py): Multi-host reachability integration referencing existing IKG nodes directly.

#### 3.2 Verification & Test Files
- [`backend/security_state/tests/phase6b_causal_rules_tests.py`](file:///d:/Projects/backend/security_state/tests/phase6b_causal_rules_tests.py): Acceptance test cases P6B-01 through P6B-10.
- [`backend/security_state/tests/phase6b_causal_rules_runner.py`](file:///d:/Projects/backend/security_state/tests/phase6b_causal_rules_runner.py): Standalone Phase 6B runner.
- [`backend/security_state/tests/run_tests.py`](file:///d:/Projects/backend/security_state/tests/run_tests.py): Master test runner (invoking all phases, 71 tests).

#### 3.3 Documentation Files
- [`docs/security-state/PHASE6B_IMPLEMENTATION_REPORT.md`](file:///d:/Projects/docs/security-state/PHASE6B_IMPLEMENTATION_REPORT.md)
- [`docs/security-state/PHASE6B_VALIDATION_REPORT.md`](file:///d:/Projects/docs/security-state/PHASE6B_VALIDATION_REPORT.md)
- [`docs/security-state/PHASE6B_HANDOFF.md`](file:///d:/Projects/docs/security-state/PHASE6B_HANDOFF.md)

---

### 4. Operational Invariants & Safety Locks

- **Current Feature Flag**: `NIVX_FLAG_SECURITY_STATE = SHADOW`
- **Response Execution**: Hard-locked (`AUTO_RESPONSE = FALSE`, `is_locked = True`).
- **Phase 5 Status**: **CLOSED and IMMUTABLE**. No modifications made to Phase 5 test files or report.
- **Phase 6B Status**: **CLOSED and VERIFIED**. All 10 gates passed deterministically.

---

### 5. Next Steps

Per the authorized sequence:
1. **Phase 6B**: 🟢 **COMPLETE**
2. **Phase 6C**: Analyst Cockpit Browser E2E validation (playwright / browser subagent testing interactive UI components, causality graphs, counterfactual exploration, and intervention staging).
3. **Phase 6A**: Distributed Streaming / Kafka cluster integration.
4. **Production Deployment**: Pending multi-host broker testing and live telemetry stress tests.
