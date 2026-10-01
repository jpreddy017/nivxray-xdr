# NivXRay XDR — Enterprise Content Acquisition & Lifecycle Architecture
**Document Version:** 1.0.0  
**Audit Date:** 2026-09-04  
**Classification:** Detection Content Engineering Architecture  
**Governing Principle:** `NO EVIDENCE → NO CLAIM` · `ZERO DUMP ARCHITECTURE`  
**Phase Status:** Phase 1 Read-Only Architecture & Truth Discovery  

---

## 1. Executive Summary & Architectural Philosophy

NivXRay XDR rejects the anti-pattern of operating as a raw, uncurated repository of thousands of blindly copied detection strings. The goal of this architecture is **not** to "download 3,000 rules and dump them into NivXRay."

Instead, NivXRay XDR establishes an industrial-grade, deterministic pipeline:
$$\mathbf{Industry\ Source} \longrightarrow \mathbf{Acquisition} \longrightarrow \mathbf{License/Provenance} \longrightarrow \mathbf{Normalize} \longrightarrow \mathbf{Translate} \longrightarrow \mathbf{Deduplicate} \longrightarrow \mathbf{Validate} \longrightarrow \mathbf{Engine\ Bind} \longrightarrow \mathbf{Correlate} \longrightarrow \mathbf{Security\ State} \longrightarrow \mathbf{Shadow} \longrightarrow \mathbf{Active}$$

This architecture ensures:
1. **Zero Piracy**: Only legally verified, permissively licensed public defensive content is ingested.
2. **Deterministic Semantic Deduplication**: Content is deduplicated by behavioral AST fingerprint, not superficial rule titles.
3. **Continuous Provenance**: Full lineage back to upstream authors, commits, and licenses is retained indefinitely.
4. **Governed Lifecycle & Auditability**: Rules move through formal quality gates; every state transition is recorded in an append-only audit trail.
5. **No Silent Production Drift**: Upstream version bumps trigger regression gates and shadow observation prior to activation.

---

## 2. End-to-End Content Acquisition Pipeline

The diagram below details the end-to-end data flow from upstream open-source repositories to active runtime evaluation:

```mermaid
flowchart TD
    subgraph S1["1. Source Discovery & Fetch"]
        A1["Upstream Repositories\n(SigmaHQ, Elastic, Splunk, Sentinel, Panther, MITRE)"] --> A2["Git Webhook / Scheduled Poller"]
        A2 --> A3["Tarball / Commit Diff Fetch"]
    end

    subgraph S2["2. Legal & Provenance Gate"]
        A3 --> B1{"License Verification\n(Apache 2.0, MIT, BSD, DRL 1.1?)"}
        B1 -->|"Rejected / Proprietary"| B2["QUARANTINE / DISCARD"]
        B1 -->|"Approved"| B3["Extract Metadata & Upstream Commit SHA\n(canonical.provenance)"]
    end

    subgraph S3["3. Syntax Parsing & AST Generation"]
        B3 --> C1{"Source Format"}
        C1 -->|"Sigma YAML"| C2["Strict pySigma Parser"]
        C1 -->|"EQL / ES|QL"| C3["EQL AST Transpiler"]
        C1 -->|"Splunk SPL"| C4["SPL Search Parser"]
        C1 -->|"KQL"| C5["KQL Syntax Parser"]
        C1 -->|"Snort / Suricata"| C6["Snort EVE Parser"]
    end

    subgraph S4["4. Normalization & Intermediate Representation"]
        C2 & C3 & C4 & C5 & C6 --> D1["Map Fields to NivXRay Canonical Evidence Schema"]
        D1 --> D2["Generate NivXRay Intermediate Representation (NIR-AST)"]
    end

    subgraph S5["5. Semantic Deduplication Engine"]
        D2 --> E1["Compute Behavioral Fingerprint & AST Hash"]
        E1 --> E2{"Compare with Canonical Store"}
        E2 -->|"DUPLICATE"| E3["Merge Provenance / Keep Best Variant"]
        E2 -->|"CONFLICTING"| E4["Flag for Detection Engineer Review"]
        E2 -->|"UNIQUE / COMPLEMENTARY"| E5["Assign Canonical Content ID (DET-xxx)"]
    end

    subgraph S6["6. Quality & Verification Gate"]
        E5 --> F1["Attach Positive & Negative Fixtures\n(Atomic Red Team / Synthetic)"]
        F1 --> F2{"Execute Engine Validation Harness\n(1 pos + 1 neg pass?)"}
        F2 -->|"Failed"| F3["State: VALIDATION_FAILED"]
        F2 -->|"Passed"| F4["State: VALIDATED"]
    end

    subgraph S7["7. Engine Binding & Contextualization"]
        F4 --> G1["Rule Binding Matcher (rule_binding.py)\n(Match against verified engines)"]
        G1 --> G2["Security State Bridge (detection_bridge.py)\n(Tag dual-use profiles, reachability factors)"]
    end

    subgraph S8["8. Safe Staged Rollout"]
        G2 --> H1["State: SHADOW MODE\n(Live/Replay telemetry evaluation without alerts)"]
        H1 --> H2{"Analyst Approval Gate"}
        H2 -->|"Promoted"| H3["State: ACTIVE\n(Full production evaluation in xdr_pipeline.py)"]
    end
```

---

## 3. Semantic Deduplication Architecture

When acquiring hundreds of rules across Sigma, Splunk, and Elastic, multiple rules inevitably detect the identical underlying technique (e.g. `whoami /all`, `vssadmin delete shadows`, `mimikatz sekurlsa::logonpasswords`). Superficial string matching or name comparison fails because vendors name identical behavior differently.

### 3.1 Multi-Dimensional Deduplication Vector
The deduplication engine computes a 7-dimensional behavioral signature:
$$\mathbf{S}_{rule} = \langle \text{Platform},\ \text{Tactic},\ \text{Technique\_ID},\ \text{Primary\_Image},\ \text{Normalized\_Arg\_Pattern},\ \text{Required\_Field\_Set},\ \text{AST\_Structure\_Hash} \rangle$$

```mermaid
flowchart LR
    A["Incoming Rule Candidate"] --> B["Extract Dimension Vector"]
    
    subgraph Dimensions["Vector Dimensions"]
        B --> D1["ATT&CK Tactic & Technique"]
        B --> D2["Platform (Windows/Linux/Cloud)"]
        B --> D3["Target Process / Binary Family"]
        B --> D4["Normalized Predicate Logic AST"]
        B --> D5["Telemetry Field Requirements"]
    end
    
    Dimensions --> C["Compute Canonical Semantic Hash"]
    C --> E{"Query Deduplication Registry"}
    
    E -->|"Semantic Hash Match (100% Logic Equivalence)"| F["Classify: DUPLICATE\n• Append source to existing detector's provenance\n• Do NOT create redundant rule"]
    E -->|"Technique & Target Match, Different Coverage"| G["Classify: COMPLEMENTARY\n• Link rules in same Duplicate Group\n• Keep both; designate primary detector"]
    E -->|"Opposing Logic / Negation Conflict"| H["Classify: CONFLICTING\n• Alert Detection Engineering"]
    E -->|"No Match"| I["Classify: UNIQUE\n• Allocate new NivXRay Canonical ID"]
```

### 3.2 Canonical Detector Selection Policy
When multiple public rules exist for the exact same semantic fingerprint:
1. **Attribution Preservation**: All originating sources (e.g. `sigma:rule-uuid-1`, `elastic:rule-uuid-2`) are appended to `metadata.cross_references` and `metadata.provenance`.
2. **Canonical Selection Hierarchy**:
   - Priority 1: The variant with the strictest (lowest false-positive) argument filtering.
   - Priority 2: The variant with certified automated test fixtures (`fixtures.count >= 2`).
   - Priority 3: The variant requiring the most universal canonical evidence fields.
3. **Zero Loss of Specificity**: If Rule A covers Windows 10 and Rule B covers Windows Server 2022 specific command flags, they are marked `COMPLEMENTARY` rather than collapsed into a single diluted rule.

---

## 4. Formal Content Lifecycle State Machine

Every piece of detection and correlation content in NivXRay XDR is governed by a deterministic finite state machine. Transitions occur only when programmatic verification criteria are satisfied.

```mermaid
stateDiagram-v2
    [*] --> ACQUIRED: Raw import from upstream source
    
    ACQUIRED --> NORMALIZED: Field names mapped to NivXRay schema
    ACQUIRED --> REJECTED: License invalid / Proprietary / Unparseable
    
    NORMALIZED --> TRANSLATED: Syntax parsed to NivXRay IR AST
    NORMALIZED --> UNSUPPORTED: Required syntax not expressible in AST
    
    TRANSLATED --> DEDUPLICATED: Semantic fingerprint checked
    
    DEDUPLICATED --> VALIDATING: Attached to test fixtures
    
    VALIDATING --> VALIDATED: Passed 1 pos + 1 neg harness test
    VALIDATING --> VALIDATION_FAILED: Harness assertion failure
    
    VALIDATION_FAILED --> TRANSLATED: Engineer tweaks predicate
    
    VALIDATED --> ENGINE_BOUND: Matched to EXECUTION_VERIFIED engine contract
    VALIDATED --> ENGINE_UNBOUND: No compatible engine declared
    
    ENGINE_BOUND --> CONTEXTUALIZED: Dual-use profile & Security State factors attached
    
    CONTEXTUALIZED --> SHADOW: Evaluating production stream with zero alert noise
    
    SHADOW --> ACTIVE: Promoted by analyst approval after 0% FP burn-in
    
    ACTIVE --> TUNING: False positive reported in production
    TUNING --> SHADOW: Adjusted predicate re-evaluated
    
    ACTIVE --> SUPERSEDED: Replaced by higher-fidelity detector
    ACTIVE --> DEPRECATED: Technique obsolete / Telemetry retired
    
    ACTIVE --> ROLLED_BACK: Emergency rollback due to unexpected disruption
    
    REJECTED --> [*]
    DEPRECATED --> [*]
    SUPERSEDED --> [*]
```

### State Definitions & Transition Criteria:
1. **`ACQUIRED`**: Upstream YAML/TOML/JSON stored in staging database. Provenance hash recorded.
2. **`NORMALIZED`**: Telemetry fields translated to NivXRay canonical evidence fields (`process.name`, `network.src.ip`).
3. **`TRANSLATED`**: Query logic compiled into deterministic Python predicate or engine AST.
4. **`DEDUPLICATED`**: Fingerprinted against existing library. Duplicates merged; unique rules indexed.
5. **`VALIDATING`**: Executed against local positive and negative test fixtures in `detection_harness.py`.
6. **`VALIDATED`**: Fixtures verified with 100% accuracy.
7. **`ENGINE_BOUND`**: Attached to an active engine contract where `execution.detection = True`.
8. **`CONTEXTUALIZED`**: Enriched with Security State dual-use rules (`detection_bridge.py`).
9. **`SHADOW`**: Active in stream, emitting shadow telemetry to `xdr_shadow_matches` for burn-in.
10. **`ACTIVE`**: Full production evaluation in `xdr_pipeline.py`. Emits live observations to IUE/ICE.

---

## 5. Source Update, Diff & Versioning Model

Public detection repositories release continuous updates, bug fixes, and deprecations. NivXRay XDR must absorb updates safely without overwriting tuned production rules.

```mermaid
flowchart TD
    A["Scheduled Update Poller"] --> B["Fetch Upstream Git Remote"]
    B --> C["Compute Commit Diff against Last Synced SHA"]
    
    C --> D{"Classify Diff per Rule"}
    
    D -->|"New Rule File"| E["Route to Acquisition Pipeline (ACQUIRED)"]
    D -->|"Modified Existing Rule"| F["Perform Semantic AST Diff"]
    D -->|"Deleted / Deprecated Upstream"| G["Flag for Deprecation Review (Never silent delete)"]
    
    F --> H{"Is AST Logic Modified?"}
    H -->|"Metadata Only (Tags, Docs)"| I["Auto-Update Metadata (Version bump: patch)"]
    H -->|"Logic Changed (Filter added/removed)"| J["Create Staged Fork: rule_id:v2"]
    
    J --> K["Execute Regression Gate on v2"]
    K --> L{"Regression Gate Pass?"}
    L -->|"Failed"| M["Quarantine v2 · Retain v1 in Production"]
    L -->|"Passed"| N["Deploy v2 in SHADOW MODE alongside v1"]
    
    N --> O["Analyst Promotion Gate"]
    O -->|"Approved"| P["Mark v1 SUPERSEDED · Promote v2 to ACTIVE"]
    O -->|"Rejected"| Q["Retain v1 · Archive v2"]
```

### Versioning Contract:
- **`source_version`**: The exact Git tag or commit hash of the originating upstream repository (e.g., `SigmaHQ:r2026-08-15:abc1234`).
- **`translation_version`**: The version of the NivXRay AST transpiler used (e.g., `nx-transpiler-v1.2`).
- **`canonical_version`**: SemVer format (`major.minor.patch`) assigned by NivXRay Rule Studio:
  - `patch`: Metadata, documentation, or ATT&CK tag updates.
  - `minor`: Non-breaking filter refinement or additional positive test fixtures.
  - `major`: Structural logic changes, field requirement changes, or engine re-binding.
- **Rollback Guarantee**: Every active rule stores its immediate previous version. If a newly promoted rule produces unexpected volume in production, an analyst can trigger an instantaneous rollback (`POST /api/xdr/rule-studio/rollback/{rule_id}`), transitioning the active detector back to the previous validated SHA.

---
*End of Enterprise Content Acquisition & Lifecycle Architecture.*
