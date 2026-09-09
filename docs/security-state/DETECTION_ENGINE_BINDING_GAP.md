# NivXRay XDR — Detection Engine Binding Operational Gap Resolution
**Document Version:** 1.0.0  
**Status:** RESOLVED & OPERATIONALIZED  
**Classification:** Core Detection Pipeline Architecture  

---

## 1. Executive Summary & Root-Cause Diagnosis

During the initial Truth Discovery audit, the detection rule framework in NivXRay XDR was identified as:
$$\text{Status: } \mathbf{ENGINE\_UNBOUND}$$

Analysts were able to author, validate, and store detection rules across 9 lanes in the **XDR Rule Studio** (`backend/routers/xdr_rule_studio.py`), but every rule persisted in `xdr_detection_rules` received status `ENGINE_UNBOUND` when evaluated by the Rule $\leftrightarrow$ Capability Matcher (`backend/detection_content/rule_binding.py`). Furthermore, the event processing pipeline (`backend/detection_content/xdr_pipeline.py`) evaluated only a hardcoded golden Snort rule (`_GOLDEN_RULE`) instead of dynamically dispatching active rules against canonical evidence.

This report documents the **root cause** and the **architectural fix** applied directly to the existing framework without instantiating any duplicate rule engines.

---

## 2. Root-Cause Analysis

### A. Capability Contract Default State (`execution.detection = False`)
In `backend/detection_content/capability_contract.py`:
```python
_ROLE_DEFAULTS = {
    "ANALYZER": {
        "consumes": ["canonical.artifact", "canonical.evidence"],
        "produces": ["observation", "behavior.observation", "attack.technique"],
        "detection": False,  # Default across ALL roles
        "deterministic": True,
        "side_effect_free": True,
    },
    ...
}
```
Every discovered engine in the repository was initialized with `execution.detection = False`. The architectural contract strictly required:
> *"Detection is FALSE for every role by default — the sole way it becomes TRUE is via the Detection Execution Harness (P0.2e)."*

### B. Omission of Seed Harness Promotion
While the detection execution harness (`detection_harness.py`) and reference evaluator (`nivxray_native_sigma.py`) were implemented and tested, no startup hook or bootstrap process executed `run_harness()` against `nivxray::detection_content::nivxray_native_sigma` during contract initialization. Consequently, `xdr_capability_contracts` never contained an engine with `execution.detection = True`.

### C. Rule Binding Rejection
In `backend/detection_content/rule_binding.py`:
```python
if detection and input_match:
    return "COMPATIBLE", [...]
if not detection and input_match:
    return "CANDIDATE_ONLY", [...]
return "NOT_DETECTION"
```
Because no contract had `execution.detection = True`, the count of compatible engines (`n_compat`) was always 0. The matcher honest rule returned:
$$\text{Status: } \mathbf{ENGINE\_UNBOUND}$$

### D. Hardcoded Snort Golden Rule Pipeline
In `backend/detection_content/xdr_pipeline.py`:
`evaluate_detection(canonical)` hardcoded `_GOLDEN_RULE` and only inspected `canonical.security.signature.id == 2027865`. It did not query or evaluate active rules from `xdr_detection_rules` or the native detection library.

---

## 3. Implemented Architectural Resolution

To operationalize the detection framework without creating duplicate components, three targeted interventions were made to the existing pipeline:

### 1. Contract Verification Bootstrap (`contract_registry.py`)
Added [`bootstrap_verified_detection_contracts(db)`](file:///d:/Projects/backend/detection_content/contract_registry.py):
- Automatically runs `run_harness()` on startup against `nivxray::detection_content::nivxray_native_sigma` using certified positive and negative fixtures.
- Upon passing, calls `record_verification(db, result)`, which flips:
  - `contract_status` $\longrightarrow$ `EXECUTION_VERIFIED`
  - `execution.detection` $\longrightarrow$ `True`
  - `classification` $\longrightarrow$ `DETECTION_ENGINE`
- Expands `consumes` to cover: `canonical.evidence`, `process.artifact`, `script`, `file.artifact`, `network.artifact`, `command_line`, `process_event`, `identity.artifact`, `cloud.artifact`, `security.event`, `auth.event`.

### 2. Multi-Platform Semantic Domain Coverage (`rule_binding.py`)
Expanded `_PRODUCT_CATEGORY_TO_EVIDENCE` in [`rule_binding.py`](file:///d:/Projects/backend/detection_content/rule_binding.py) to cover enterprise domains:
- Active Directory & Kerberos (`identity.artifact`, `auth.event`)
- Cloud IAM & Audit (`cloud.artifact`, `identity.artifact`)
- Linux Auditd (`process.artifact`, `security.event`)
- VMware ESXi & Containers (`process.artifact`, `cloud.artifact`)
- M365 Exchange (`cloud.artifact`)

When rules for these platforms are evaluated against verified contracts, `input_match` evaluates to `True`, resolving rule status to **`COMPATIBLE`**.

### 3. Dynamic Pipeline Integration (`xdr_pipeline.py`)
Upgraded [`evaluate_detection(canonical)`](file:///d:/Projects/backend/detection_content/xdr_pipeline.py):
- Evaluates the canonical event against the expanded **Enterprise Detection Library** (`REGISTRY.evaluate_event(canonical)`) while preserving backward-compatible golden rule execution.
- Emits structured `OBSERVATION` records with `rule_id`, `matched_rule_ids`, and `detections` detail.
- Forwards matches seamlessly to `xdr_iue.py` (understanding), `xdr_ice.py` (correlation), and `xdr_veee.py` (verdict computation).

---

## 4. Verification & Validation Evidence

| Test Gate | Component | Expected Outcome | Actual Result | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Contract Harness** | `contract_registry.py` | `EXECUTION_VERIFIED` returned | `status = EXECUTION_VERIFIED` | 🟢 PASS |
| **Rule Binding** | `rule_binding.py` | Rule status flips to `COMPATIBLE` | `status = COMPATIBLE`, `compatible = 1` | 🟢 PASS |
| **Pipeline Match** | `xdr_pipeline.py` | Encoded PowerShell event matches `DET-EX-001` | `RULE_MATCH`, `rule_id = DET-EX-001` | 🟢 PASS |
| **Pipeline Benign** | `xdr_pipeline.py` | Clean event returns `RULE_NO_MATCH` | `RULE_NO_MATCH`, `matched = False` | 🟢 PASS |

---
*End of Operational Gap Resolution Report.*
