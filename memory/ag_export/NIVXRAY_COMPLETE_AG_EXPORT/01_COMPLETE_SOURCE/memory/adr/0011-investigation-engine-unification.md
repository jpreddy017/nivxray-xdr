# ADR-0011 — Investigation Engine Unification

- **Status:** **Proposed · planning-only** (2026-02-28). Implementation authorization pending operator sign-off on the plan below.
- **Deciders:** Operator (product owner) · Emergent (proposer)
- **Threshold met:** Corpus v1 Parity Sweep results (2026-02-28) — 0/20 verdict parity, 3/20 evidence-type parity, 1/20 stages parity, 19/20 CIM_STRUCTURE, 20/20 DECODE.
- **Supersedes:** the narrower "Verdict-Unification" candidate. Root cause is architectural, not verdict-specific.

## 1 · Problem

The parity sweep proved one root cause behind four symptoms:

- ✅ Decode pipeline is unified.
- ✅ CIM foundation is shared.
- ❌ Investigation / reasoning engines diverge.
- ❌ Verdicts diverge (`build_verdict_card` vs LLM `executive_card`).
- ❌ Evidence classification diverges.
- ❌ Analysis stages diverge.

The last four are a single architectural fork viewed from four angles.
Fix it at the engine layer once → all four parity dimensions come
green together.

## 2 · Decision

Introduce **one Investigation Engine** that sits between the unified
`FactSubstrate` and the unified CIM. Both endpoints — `/api/decode/smart`
and `/api/v2/auto-investigate` — become **presentation-layer serializers**
of the same `Investigation` object; they no longer own their reasoning
paths.

### 2.1 Single Investigation Engine

**Inputs (frozen):**
- `FactSubstrate` (already unified; see ADR-0009 §2.6)
- Optional `AnalystContext` (user-supplied focus / hints)

**Outputs (frozen):**
- One `Investigation` (ADR-0009 CIM v1.0) with:
  - Deterministic Assessments (verdict + family + category + risk)
  - Evidence with `evidence_class ∈ {behavioral, semantic, structural}`
  - AnalysisStages reflecting only stages that actually ran
  - Recommendations (all evidence-backed, ADR-0009 §2.1.d)
  - Unknowns (deterministic, ADR-0009 §2.2)
  - Explainability payload (ADR-0007 §7 contributors + not_counted)

**Invariants (composer-enforced, must all hold at output):**
1. Exactly one verdict Assessment per Investigation.
2. Every Assessment carries ≥1 Evidence.id (ADR-0009 §2.1.b).
3. Every Recommendation carries ≥1 Evidence.id (ADR-0009 §2.1.d).
4. No orphan Evidence (ADR-0009 §2.8 #5).
5. Verdict severity ≥ Suspicious requires ≥1 behavioral/semantic Evidence (ADR-0007 §2.3 gate).
6. Explainability.contributors non-empty for every Suspicious+ verdict (ADR-0007 §7).
7. Deterministic — same `FactSubstrate` → identical `Investigation` (modulo `id`/`created_at`).
8. Transport-independent — engine never imports from `routers/*` or FastAPI.

### 2.2 Single FactSubstrate

- Every endpoint MUST populate the same `FactSubstrate` shape (ADR-0009 §2.6).
- `fact_substrate.from_analysis_result()` remains the ONLY adapter — extended, not forked.
- Endpoint-specific field-name mapping is allowed INSIDE the adapter; the composer sees only canonical `FactSubstrate` fields.
- **No adapters outside** `nivxforge/cim/fact_substrate.py`.

### 2.3 Single Evidence Pipeline

One extractor, one classifier, one model:
- **Extractor:** existing `operations.extract_iocs` (ADR-0008-gated) + composer's decoder-layer / MITRE / TI evidence emission.
- **Classifier:** the `evidence_class` tagging currently in `evidence_extractor._collect_indicators` (ADR-0007) becomes a standalone module `nivxforge/cim/classifiers.py`.
- **Model:** ADR-0009 §2.1.a `Evidence` object. Immutable shape.

### 2.4 Single Assessment Pipeline

- All Assessment emission moves into `compose.py`.
- No endpoint-specific Assessment construction anywhere else.
- Assessment kinds fixed: `verdict | family | category | behavior | attribution | risk | capability | impact` (ADR-0009 §2.1.b).

### 2.5 Single Verdict Engine

- One deterministic verdict implementation: `evidence_extractor.build_verdict_card` (already ADR-0007-gated).
- LLM `executive_card` is DEMOTED to a **narrative source** only — its verdict / confidence outputs are NOT surfaced. Its prose is retained as `Investigation.report.narrative` (for later ADR-narrative-composer consumption).
- Explainability payload (ADR-0007 §7) is shared across all consumers.
- Confidence model unified: single 0-100 integer, mapped to Confidence enum via `_verdict_to_confidence()` (ADR-0009 §2.1.a helper).

### 2.6 Single CIM Composer

- `nivxforge/cim/compose.py` is the ONLY producer of `Investigation` objects.
- Every consumer (Workspace, Lab, Reports, API, future CLI) reads the same `Investigation`.
- No consumer re-derives verdict / evidence / stages / assessments.

### 2.7 Presentation Layer

The API endpoints become thin serializers:

```
routers/ops.py            → serialize(Investigation).as_decode_view()
routers/auto_investigate  → serialize(Investigation).as_investigation_view()
Workspace pages           → render(Investigation)  [Track B migration]
Lab pages                 → render(Investigation)  ✅ already
Reports                   → compose_report(Investigation)  [future ADR]
Future CLI                → format(Investigation)  [future]
```

- Legacy response envelopes (`verdict_card`, `iocs`, `mitre`, `ti_shield`) become **derived views** on the Investigation — same information, endpoint-familiar shape.
- No new HTTP routes.

## 3 · Scope

**In scope:**
- Consolidating verdict / evidence / stages / assessments into the composer.
- Extending `fact_substrate.from_analysis_result` to make BOTH endpoint inputs produce equivalent substrates.
- Retiring divergent code paths (LLM executive_card verdict output demoted to narrative).
- Ensuring both endpoints emit CIMs that are field-identical for the same input (modulo id/timestamps).

**Out of scope (explicit non-goals):**
- ❌ Navigation redesign (ADR-0010).
- ❌ Narrative Composer / Report layer.
- ❌ History / Recent Cases UI.
- ❌ Any Workspace page migration.
- ❌ Any visual improvements.
- ❌ Any new capabilities not already present in one of the two engines.

## 4 · Sequencing (proposed)

Phase 0 · **Planning gate** ← this ADR. Operator sign-off required.
Phase 1 · **Substrate parity** — extend `from_analysis_result` so both endpoints populate identical FactSubstrate for identical input.
Phase 2 · **Composer takes ownership** — move all verdict/evidence/stage/assessment emission into `compose.py`; retire divergent paths.
Phase 3 · **Endpoint serializers** — `routers/ops.py` and `routers/auto_investigate.py` become CIM serializers; legacy fields become derived views.
Phase 4 · **Parity sweep re-run** — must achieve the 8-dimension target below.
Phase 5 · **Governance close** — update ADR status, CAPABILITY_REGISTRY, PRD.

## 5 · Exit Criteria — 8-dimension parity target

Re-run `tests/test_corpus_v1_parity_sweep.py`. Target:

| Dimension       | Current | Target |
|-----------------|--------:|-------:|
| Decode          |   20/20 |  20/20 |
| CIM Structure   |   19/20 |  20/20 |
| Verdict         |    0/20 |  20/20 |
| Evidence Types  |    3/20 |  20/20 |
| Analysis Stages |    1/20 |  20/20 |
| Explainability  |     n/a |  20/20 |
| Recommendations |     n/a |  20/20 |
| ATT&CK Mapping  |     n/a |  20/20 |

Plus:
- All 114 existing ADR pins remain green.
- Full Workspace regression: net zero new failures vs baseline.
- Perf: `/api/decode/smart` and `/api/v2/auto-investigate` end-to-end
  latency ≤ 105% of current baseline (Corpus v1 mean).

Partial success is NOT "success" for this ADR.

## 6 · Related patterns

- **P-VERDICT-DUAL-SURFACE** — resolved fully by §2.5.
- **PARITY_GAP-002** (2026-02-28) — resolved fully by §2 (all sub-sections).
- **PARITY_GAP-001** (Case 0015 error-envelope) — resolved as a side-effect of §2.3 (composer emits a valid empty CIM even on decoder error).

## 7 · Risks & mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Retiring LLM verdict path breaks analyst confidence in Auto Investigate | Med | Med | Retain LLM prose as narrative; verdict is deterministic but the story is preserved. Explainability makes the deterministic verdict inspectable. |
| Regression on Workspace pages that read `verdict_card` directly | High | High | Derived-view layer keeps `verdict_card` shape stable. Migration is behind-the-scenes. |
| Corpus v1 exit criteria over-fit; new artifact types diverge again | Low | Med | Rules-based classifier + composer keeps divergence surface small; new artifact types go through the SAME engine. |
| Perf regression from consolidating multiple analysis paths | Low | Low | Composer is O(n); benchmark before merge. |

## 8 · Registry impact

Once implemented, `CAPABILITY_REGISTRY.md` gains:

| Capability | ADR | Status | Evidence | Corpus | Regression | Component |
|---|---|---|---|---|---|---|
| Investigation Engine Unification | ADR-0011 | **Proposed** (2026-02-28) | CORPUS_V1_PARITY.md matrix | v1 | see §5 · 8-dimension parity | `nivxforge/cim/` composer + `classifiers.py` |
