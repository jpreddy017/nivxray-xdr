# NivXRay XDR · Differentiator Acceptance Criteria (Owner-Locked · Addendum ADD-01)

> **Status:** ADDENDUM to the OWNER AUTHORIZATION — FULL AG BUILD → NIVXRAY XDR END-TO-END IMPLEMENTATION.
> **Immutability:** These acceptance criteria are locked. Implementation is not marked COMPLETE unless every criterion below is met by SOURCE + RUNTIME + EVIDENCE + TEST + UI.
> **Product name:** NivXRay XDR (used consistently).

---

## 1 · IN-SITU SANDBOX DETONATION

### 1.1 · Required flow
From an endpoint or process investigation, the analyst must be able to select a suspicious artifact / process and invoke **Detonate in Sandbox** *without losing the current investigation context*.

```
Incident → Investigation → Device → Process Tree → Suspicious Process/File
                                                                 │
                                                          [Detonate]
                                                                 │
                                                              Sandbox
                                                                 │
                                                       Dynamic Evidence
                                                                 │
                                                       Canonical Evidence
                                                                 │
                                                              IUE / ICE
                                                                 │
                                                          Security State
                                                                 │
                                                             Verdict
                                                                 │
                                                              IKG
                                                                 │
                                                      Attack Story pivot
```

### 1.2 · Analyst pivot invariants
Without losing case context the analyst MUST be able to pivot between: `process` · `file` · `hash` · `command_line` · `sandbox_execution` · `network` · `dns` · `dropped_files` · `registry` · `memory` · `ioc` · `attck` · `evidence`.

### 1.3 · Infrastructure honesty
Live VM infrastructure is **not** deployable in the preview environment. The implementation MUST land:
- Production interfaces (API contracts, request/response schemas)
- Orchestration (submission → queue → executor → result)
- Evidence contracts (Canonical-Evidence emitters)
- Deployment architecture (Docker/K8s + hypervisor + snapshot/revert)
- Clearly demarcated infrastructure-blocked runtime portion via capability status `NOT_AVAILABLE_INFRASTRUCTURE`.

**Forbidden:** simple external link, placeholder button, or fake progress bar.

## 2 · CAUSAL SECURITY STATE

### 2.1 · Required loop
```
Evidence → State → Causality → Attack State → Capability → Reachability
        → Impact → Counterfactual → Intervention → Verification → New State
```

### 2.2 · Provenance classes (never collapsed, never fabricated)
Every conclusion in the UI MUST carry one of:
`OBSERVED · SUPPORTED · DERIVED · LIKELY · POSSIBLE · UNSUPPORTED · CONTRADICTED · DISPROVEN`.

### 2.3 · Evidence-backed transitions
UI MUST expose the evidence supporting each state transition. **NO EVIDENCE → NO CLAIM.** Traditional risk score may remain as supplementary context but MUST NOT be presented as causal proof. Card / badge / tooltip must show provenance class + linked evidence IDs.

### 2.4 · Runtime endpoints (delivered in Stage 1+2)
Backend surface for these live at `/api/v2/security-state/*` (14 endpoints — `evaluate`, `transitions`, `causality`, `capabilities`, `reachability`, `counterfactual`, `interventions/plan`, `interventions/stage`, `response/verify`, `ledger`, `provenance`, `history`, `streaming/status`).

## 3 · MULTI-STAGE DEOBFUSCATION LINEAGE

### 3.1 · Required display
The UI MUST show the **complete lineage** — never only the final decoded command. Example:

```
Raw Command → Hex → Base64 → GZIP → PowerShell → Caret/Token normalization → Final Payload
```

### 3.2 · Per-stage fields
For every decoder stage the UI MUST expose:
| Field | Definition |
|---|---|
| `input` | The exact bytes/text going into this stage |
| `transformation` | Codec identity (e.g. `base64_decode`, `gzip_inflate`) |
| `output` | The exact bytes/text produced |
| `status` | `OK` / `FAILED` / `SKIPPED` / `STOPPED` |
| `confidence` | Numeric or class label |
| `provenance` | Where the stage decision came from |
| `evidence_ref` | Backlink to Canonical Evidence |
| `semantic_interpretation` | What the stage means analytically |
| `attck_mapping` | MITRE technique(s), when applicable |
| `extracted_ioc` | IOCs surfaced at this stage |
| `stop_reason` | Present iff the pipeline halted here |

### 3.3 · No silent loss
The final payload MUST remain traceable back to its originating evidence. **ZERO silent decoding loss** — any stage that would drop bytes MUST emit a `dropped_bytes` provenance record.

## 4 · SHARED EVIDENCE FABRIC

Independent UI-only implementations of §1, §2, §3 are forbidden.
All three MUST converge through:
```
Canonical Evidence → IUE → ICE → IKG → Security State → Verdict → Investigation
```
i.e. **EDR evidence + Sandbox evidence + Decoder evidence + External telemetry = one investigation evidence model.**

## 5 · ACCEPTANCE TESTS (automated)

### 5.1 · Sandbox E2E
```
Process Tree → Detonate → Sandbox → Dynamic Evidence → Investigation
```

### 5.2 · Security State E2E
```
Evidence → Causal State → Reachability → Counterfactual → Intervention → Verification → New State
```

### 5.3 · Decoder E2E
```
Raw command → Stage 1 → Stage 2 → Stage 3 → Final payload
```

Every acceptance test MUST prove that each stage remains linked to its originating evidence.

## 6 · COMPETITIVE BENCHMARK

Continue benchmarking against: CrowdStrike Falcon · Microsoft Defender · SentinelOne · Trellix · Cortex XDR · leading enterprise sandbox platforms.
Do **not** copy proprietary UI. Benchmark capability, workflow, analyst efficiency, operational outcome.
NivXRay XDR differentiation comes from deterministic evidence + causal architecture, not cosmetic UI.

## 7 · FINAL COMPLETION RULE

An implementation is COMPLETE for a differentiator only when all five layers are proven end-to-end:

`SOURCE → RUNTIME → EVIDENCE → TEST → UI`

Existence of React components, API endpoints, or documentation alone does **not** meet acceptance.

---

## 8 · Current honest state (Stage 1+2 + UI honest-state repair)

| Differentiator | SOURCE | RUNTIME | EVIDENCE | TEST | UI | Overall |
|---|:---:|:---:|:---:|:---:|:---:|---|
| §1 In-Situ Sandbox Detonation | ⚠ blueprint (AG spec docs imported) | ❌ VM plane not deployable | ❌ | ❌ | ❌ | **NOT_AVAILABLE** — infrastructure-gated |
| §2 Causal Security State | ✅ 81-file AG package imported | ✅ 14 endpoints live | ⚠ end-to-end replay pending | ⚠ 3 P0-D isolation vectors only | ❌ UI wiring queued | **PARTIAL** |
| §3 Multi-Stage Deobfuscation Lineage | ✅ Universal Decoder (Emergent authoritative 45+14+7+14) | ✅ decoder engine + DDO | ✅ produces per-stage trace | ⚠ decoder harness only | ❌ lineage UI card queued | **PARTIAL — backend ready, UI missing** |
| Investigation List UI honest-state | — | ✅ | ✅ | — | ✅ **FIXED THIS SESSION** — no more `[object Object]`, no more `Dev: 75`, no more `18 nodes`, honest `NO EVIDENCE` badge | **HONEST** |

## END · Differentiator Acceptance Criteria delivered · to be re-verified after Stage 3 replay + UI operationalization slices.
