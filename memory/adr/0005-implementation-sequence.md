# ADR-005 · Phase-by-Phase Implementation Sequence (DESIGN-ONLY, READ-ONLY)

- **Status**: Proposed · awaiting owner review · **no implementation authorised**
- **Date**: 2026-08-10
- **Prerequisite artefacts (all approved)**:
  - `/app/memory/adr/0005-canonical-investigation-architecture.md` (ADR-005 design)
  - `/app/memory/adr/0005-owner-decision-matrix.md` (owner decisions recorded 2026-08-10)
  - `/app/memory/adr/0005-migration-map.md` (migration map approved 2026-08-10 as architectural direction)
  - `/app/memory/GOLDEN_CASE_SAMPLE1.md` (golden acceptance canary, rules R-G1..R-G6)
- **Explicit non-goals**: no code changes, no route changes, no DB modifications, no Wave 1 modifications, no ADR-004 modifications, no Engine A modifications, no verdict modifications, no Workspace UI modifications.

---

## 0. Foundation-beside-existing principle (owner-mandated 2026-08-10)

> *"The first implementation should not try to fix Workspace. It should build the new canonical foundation BESIDE the existing system. Only after that foundation proves itself do we begin moving entry points."*

Consequences enforced throughout this sequence:

- **Phases 1–4 do not touch any existing route.** They add new modules alongside existing ones. Existing entry points continue to serve existing pipelines with zero behavioural change.
- **Phase 5 is the first phase where an existing route's behaviour changes** — and only after Phases 1–4 have proven determinism.
- **No phase moves a bypass.** A route is either untouched or converged to the canonical lifecycle — never redirected to a different existing pipeline as an interim step. This rules out any "L1b"-shaped fix at every phase.
- **Sample1 (case ID `3db79c4a-088b-4df7-b65a-f68b367b7677`) is never modified.** Every acceptance criterion below that references "Sample1" means: re-ingest `Sample.docx` as a **NEW** case. The original record stays as the pre-canonical baseline (R-G1..R-G6).

---

## 1. The universal per-phase gate

Every phase must pass this gate before the next phase may begin:

```
     Design (this document, phase spec)
        │
        ▼
     Implement (only after phase spec approved)
        │
        ▼
     Tests (unit + integration + regression)
        │
        ▼
     Sample1-equivalent acceptance
        │   (re-ingest Sample.docx as a NEW case;
        │    Sample1 original stays untouched)
        ▼
     Projection acceptance (byte-identical output
        │   vs. legacy on a golden corpus, OR
        │   owner-approved diff)
        ▼
     Determinism (same-input replay produces
        │   byte-identical SSOT / projection)
        ▼
     Owner sign-off
        │
        ▼
     [Only then] next phase
```

**No phase may run any of the following in parallel:**
- Skipping the Sample1-equivalent acceptance step.
- Merging determinism checks into the next phase.
- Deferring projection acceptance to a later phase.
- Modifying the golden Sample1 record.
- Adding an implementation step that this document did not authorise.

---

## 2. Phases at a glance

| # | Phase | Touches routes? | Touches Workspace UI? | Touches Wave 1? | Touches Engine A? | Reversibility |
|---|---|:-:|:-:|:-:|:-:|:-:|
| 1 | Canonical IUE Composer | No | No | No | No | Full (new module) |
| 2 | Canonical SSOT authoritative tier | No | No | No | No | Full (new schema alongside) |
| 3 | Canonical Executor | No | No | No | No | Full (new orchestrator alongside) |
| 4 | Projections | No | No | No | No | Full (pure functions, no persistence) |
| 5 | Entry-point convergence | **Yes** (per route, gated) | No | No | No | Per-route rollback via shim |
| 6 | Wave 1 relabelling + fresh segment | No | No | **Yes** (additive labelling only) | No | Full (new segment; pre-segment locked) |
| 7 | Sample1 acceptance regression | No | No | No | No | N/A (verification) |
| 8 | Workspace UI verification & template removal | No | **Yes** | No | No | Full (UI-only, feature-flagged) |
| 9 | ADR-004 Step 2 (Verdict consumer switch) | No | No | Read only | **Yes** (retirement) | Full (Engine A retained until authorised) |
| 10 | DEPRECATE (consumer-count = 0 removals) | Cleanup | Cleanup | Cleanup | Cleanup | Irreversible (deletion) |

---

# PHASE 1 · Canonical IUE Composer

### Objective
Build the new Canonical IUE Composer (D1-D) as a new module. It aggregates existing sub-classifiers into `IUEDecision`. No existing route calls it yet. Behaviour of the current system is unchanged.

### Files / modules affected
- **NEW** module (name TBD in implementation-sequence review — this document proposes `backend/canonical/iue/composer.py` as a placeholder location; owner may relocate).
- **NEW** models: `IUEDecision`, `InputProfile`, `IUEEvidence`, `PlanStep`, `ConfidenceMatrix`, `DispatchPolicy` — as declarative Pydantic/dataclass schemas alongside the composer.
- **Existing sub-classifiers (READ-ONLY reuse — no modifications in Phase 1):**
  - `services/die/input_understanding.py` (IUE-2 — classification + plan-emission portion reused; executor portion NOT touched in Phase 1)
  - `v2/investigation/iu/engine.py` + `v2/investigation/iu/detectors/*` (IUE-3)
  - `services/uil/classifier.py` + `services/uil/mixed.py` + `services/uil/preprocess.py` (IUE-4)
  - `services/die/input_health.py` (pre-IUE health, wired into the composer)
- **Existing IUE-1 (`nivxforge/investigation/input_understanding.py`)** — NOT called by the composer. Marked for Phase 10 deprecation. Left untouched in Phase 1.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 1 disposition |
|---|---|
| IUE-2 classification + plan-emission | KEEP (imported by composer read-only) |
| IUE-2 `_execute_plan()` executor | KEEP (untouched — will move in Phase 3) |
| IUE-3 detectors + `classify()` | KEEP (imported by composer) |
| IUE-4 `classifier.py::classify` + mixed splitter | KEEP (imported by composer) |
| IUE-5 (`services/ida/*`) | KEEP untouched (Analyzer role — moves in Phase 3) |
| InputHealth | KEEP (wired into composer as pre-classification step) |
| IUE-1 (`nivxforge/investigation/input_understanding`) | KEEP untouched (still called by existing `decode_smart`) |
| Canonical IUE Composer | **NEW** (INV-6-compliant: composition only, no classification, no execution) |

### Dependencies
- **Upstream**: Phase 0 owner decisions recorded (✅ done).
- **Downstream blocks**: Phase 2 (SSOT authoritative tier consumes `IUEDecision` as a first-class field), Phase 3 (Executor consumes `plan[]` + `dispatch[]`).

### Tests / gates
- **T1.1** Unit tests per sub-classifier composition (Health → Bytes → TextStructure → Language → MultiArtefact → Intent → Plan).
- **T1.2** Determinism test: 20-input golden corpus, `composer.classify(input).determinism_hash` byte-stable across 100 replays.
- **T1.3** Contract tests: `IUEDecision` schema is complete against ADR-005 §3.2 field table.
- **T1.4** Provenance test: every `IUEEvidence` entry carries `(engine, version, at, upstream_evidence_ids)` (D3-z envelope).
- **T1.5** Tie-breaking test: when two sub-classifiers emit conflicting primary types, the composer's deterministic tie-breaker rule (specified in the Phase 1 spec, TBD) applies identically across replays.
- **T1.6** No-network test: composer runs with all outbound sockets blocked (INV-2 determinism).

### Sample1-equivalent acceptance
- **A1.1** Re-ingest `Sample.docx` bytes through the composer (in isolation — NOT through any route). The composer must emit:
  - `input_profile.primary_type = DOCX` (or the composer's canonical DOCX taxonomy value)
  - `input_health` populated
  - `intent` populated with a non-generic value
  - `plan[]` non-empty
  - `dispatch[]` non-empty and non-trivial (at least `ARCHIVE_EXTRACT`, `ARTIFACT_SPLIT`, `IOC_EXTRACTOR`, `MITRE_MAP`)
  - `confidence_matrix` populated on all 6 axes
  - `determinism_hash` reproducible
- **A1.2** Sample1 original record MUST remain unchanged (verify fingerprint `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`).

### Projection acceptance
Not applicable in Phase 1 (no projections yet). The composer's output shape is validated against the ADR-005 §3.2 contract, nothing more.

### Rollback boundary
- **Full rollback**: delete the new composer module. No existing route depends on it. No consumer contract changed.
- **Time budget for rollback**: seconds (module removal). No data migration.

### What remains frozen during Phase 1
- All routes (no route imports the composer).
- All SSOT shapes (no SSOT emits or consumes `IUEDecision` yet).
- Engine A, canonical v2 verdict, Wave 1 store, Workspace UI, ADR-004.

### Exact STOP condition
Phase 1 STOPS when:
1. T1.1..T1.6 all green in CI.
2. A1.1 verified against Sample.docx (as a NEW ingestion — NOT against the persisted Sample1 case).
3. A1.2 verified (Sample1 fingerprint unchanged).
4. Owner sign-off recorded in `/app/memory/adr/0005-phase1-signoff.md`.

Only then may Phase 2 begin.

---

# PHASE 2 · Canonical SSOT Authoritative Tier

### Objective
Author the canonical SSOT authoritative tier (D2-d) as a new schema alongside all existing SSOTs. It uses ADR-0014 CIO's `EvidenceGraph + ReasoningStep + Truth Model` as the structural base, extended with `iue_decision`, `execution_trace`, mandatory `Provenance` envelope (D3-z), and `artifacts[].investigation_ref → ssot_ref` (D6-r). No existing consumer reads it yet. No existing SSOT is modified.

### Files / modules affected
- **NEW** authoritative-tier schema module (placeholder location TBD; propose `backend/canonical/ssot/authoritative.py`).
- **NEW** immutable-store extension (placeholder: reuse `investigation_ssot` collection with a new `schema_version` value; content-addressed via canonical-JSON sha256 fingerprint).
- **NEW** `ssot_ref` type and dereferencing helper.
- **Existing**:
  - `nivxforge/investigation/models.py::CIO` — READ-ONLY reference (schema donor, not modified in Phase 2)
  - `nivxforge/investigation/graph.py::EvidenceGraph` — READ-ONLY reference
  - `v2/investigation/model.py::InvestigationModel` — untouched
  - `services/die/canonical.py::Canonical` — untouched
  - `l2_investigation/schemas.py::EvidenceBundle` — untouched
  - `nivxforge/core/cio.py` (North Star) — untouched (its `Provenance` shape absorbed as reference)

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 2 disposition |
|---|---|
| ADR-0014 CIO (`nivxforge/investigation/models.py`) | KEEP untouched — schema donor only |
| North Star CIO Provenance shape | KEEP as reference — absorbed into new envelope |
| EvidenceGraph nodes/edges | KEEP (reused as the graph substructure of the authoritative tier) |
| ReasoningStep stream | KEEP (reused; extended with `output_evidence_ids[]`) |
| Canonical SSOT authoritative tier | **NEW** |
| Immutable SSOT store | ADAPT (schema-version-aware; content-addressed key) |
| `ssot_ref` | **NEW** type |

### Dependencies
- Upstream: Phase 1 complete (composer emits `IUEDecision` which is a first-class field on the authoritative tier).
- Downstream blocks: Phase 3 (Executor writes to the tier), Phase 4 (projectors read from it).

### Tests / gates
- **T2.1** Contract tests: authoritative tier schema is complete against ADR-005 §4.1 minimum-information table (25+ buckets).
- **T2.2** Provenance envelope test: no entry can be appended without `Provenance{engine, version, at, upstream_evidence_ids[]}` (D3-z).
- **T2.3** Append-only invariant test: mutation of an existing entry raises; only appends succeed.
- **T2.4** Determinism-hash test: two independently constructed SSOTs with identical content produce byte-identical canonical JSON and identical sha256.
- **T2.5** `ssot_ref` roundtrip test: write child SSOT → get fingerprint → dereference → byte-identical child SSOT (D6-r).
- **T2.6** Projection-vs-authoritative separation test: a hand-crafted authoritative SSOT can be constructed with `activity.*`, `iocs.*`, `attck.*`, `attack_chain`, `attack_story`, `analyst_summary`, `executive_summary`, `recommendations`, `reports.*`, `timeline` fields all **empty**; the tier is still valid (projections are populated by Phase 4, not by the tier itself).
- **T2.7** Isolation test: no existing route, consumer, or test imports the new tier — Phase 2 is truly beside-the-system.

### Sample1-equivalent acceptance
- **A2.1** Given the composer's `IUEDecision` for `Sample.docx` (from A1.1), hand-construct a minimal authoritative-tier SSOT with `iue_decision` populated, `input_raw` = docx bytes, `input_profile` populated, `input_health` populated, everything else empty. It MUST validate and serialise deterministically.
- **A2.2** Store that SSOT in the immutable store, dereference by `ssot_ref`, verify byte-identical readback.
- **A2.3** Sample1 original record unchanged (fingerprint re-verified).

### Projection acceptance
Not applicable in Phase 2 (projections arrive in Phase 4).

### Rollback boundary
- **Full rollback**: delete the new schema module + immutable-store rows tagged with the new schema-version. No existing SSOT is touched; no existing consumer depends on the new tier.
- **Time budget**: minutes.

### What remains frozen during Phase 2
- All routes, all consumers, all existing SSOTs, all projections (do not exist yet), Engine A, canonical v2 verdict, Wave 1 store shape, Workspace UI, ADR-004.

### Exact STOP condition
1. T2.1..T2.7 green.
2. A2.1..A2.3 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase2-signoff.md`.

---

# PHASE 3 · Canonical Executor

### Objective
Author the canonical Executor (D4-3). It consumes `IUEDecision.plan[]` + `dispatch[]` + `dispatch_policy`, invokes Analyzers/Enrichers as capability plug-ins, and writes to the authoritative tier with mandatory Provenance. The Executor exists as a library — no route invokes it in Phase 3.

### Files / modules affected
- **NEW** Executor module (placeholder `backend/canonical/executor/`).
- **NEW** capability registry mapping `Capability` enum → plug-in.
- **NEW / ADAPT** capability plug-in adapters wrapping existing Analyzers as read-only invocations that write to the authoritative tier:
  - DIE analyze → `SEMANTIC_AST` capability
  - DIE DKP → `DKP_MATCH` capability
  - DIE preprocessor stages → executor plug-ins
  - DIE archive_recovery → `ARCHIVE_EXTRACT` capability
  - DIE intent (moved upstream — called by composer in Phase 1 already)
  - IDA acquisition → `IDA_ACQUIRE` capability
  - IDA artifact_splitter / router → `ARTIFACT_SPLIT` capability
  - MDR `_extract_entities` → `IOC_EXTRACTOR` capability
  - MDR `_detect_commands` → `COMMAND_DETECT` capability
  - MDR `_flatten_mitre` → `MITRE_MAP` capability
  - MDR `_merge_iocs` → `IOC_MERGE` capability
  - MDR `_investigation_quality` → `QUALITY_SCORE` capability
  - OSINT enricher → `THREAT_INTEL_ENRICH` capability (D8-s Enricher role — isolated)
  - Nivxforge recursive → `RECURSIVE_DISCOVERY` capability
- **Existing consumers of the above Analyzers** — NOT modified. Existing routes continue calling them the way they do today. The Phase 3 adapters are additive plug-ins that also happen to expose the same underlying logic through the canonical Executor.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 3 disposition |
|---|---|
| All Analyzers listed above | KEEP + WRAP (existing invocation path preserved; new capability-adapter added) |
| OSINT enricher | KEEP + WRAP as isolated Enricher |
| Nivxforge recursive | ADAPT (its iteration loop is now the `RECURSIVE_DISCOVERY` capability; existing direct invocations continue) |
| Executor | **NEW** |
| Capability registry | **NEW** |

### Dependencies
- Upstream: Phase 2 complete (Executor writes to the authoritative tier).
- Downstream blocks: Phase 4 (projections read what the Executor writes), Phase 5 (entry-point adapters invoke the Executor).

### Tests / gates
- **T3.1** Per-capability unit tests: each plug-in invoked in isolation produces the same output as the underlying Analyzer AND appends correctly-provenanced entries to the authoritative tier.
- **T3.2** Plan-driven execution test: given a plan `[Health, IUE (already run), DECODER, IOC_EXTRACTOR, MITRE_MAP, RECOMMENDATION_STUB (populated in Phase 4)]`, executor runs strict-ordered without error.
- **T3.3** Dispatch-driven execution test: given a dispatch `[DECODER, IOC_EXTRACTOR, MITRE_MAP]` with policy=`parallel_where_safe`, executor runs concurrently and produces the same SSOT byte-identical to strict-ordered.
- **T3.4** Recursive-discovery test (D6-r): given a synthetic input with an embedded base64 blob, executor produces a child SSOT stored by `ssot_ref`, parent's `artifacts[].investigation_ref` set, parent's projections (in Phase 4) roll up child's contributions.
- **T3.5** Budget enforcement test: recursive discovery with `max_depth=2` stops at depth 2; unvisited children recorded as `budget_exhausted` in `execution_trace`.
- **T3.6** Enricher isolation test (INV-2): disabling the Enricher role produces a lower-confidence but still-valid SSOT; the deterministic conclusion is unchanged.
- **T3.7** Determinism-under-parallelism test: `parallel_where_safe` produces byte-identical SSOT across 50 replays (proving no order-dependent side effects).
- **T3.8** Isolation test: no existing route invokes the Executor in Phase 3.

### Sample1-equivalent acceptance
- **A3.1** Given `Sample.docx` bytes → composer → IUEDecision → Executor. Result: an authoritative-tier SSOT with **populated** `evidence_graph` (nodes for the docx artefacts + decoded fragments), populated `activity.processes/files/network/registry/auth` where applicable, populated `execution_trace`, populated `reasoning_steps`, populated `threat_intel` (if OSINT ran).
- **A3.2** SSOT's authoritative tier passes all Phase 2 invariants (append-only, provenance envelope, deterministic).
- **A3.3** Sample1 original record unchanged.

### Projection acceptance
Not applicable in Phase 3 (projections arrive in Phase 4). What the Executor writes MUST be reviewed against the ADR-005 §4 authoritative field list — no field is populated that Phase 4 would classify as "projection".

### Rollback boundary
- **Full rollback**: delete the Executor module + capability plug-in adapters. Underlying Analyzers untouched. No route depends on the Executor in Phase 3.
- **Time budget**: minutes.

### What remains frozen during Phase 3
- Routes, existing consumers, existing SSOTs, projections (Phase 4), Wave 1, Engine A, canonical v2 verdict, Workspace UI, ADR-004.

### Exact STOP condition
1. T3.1..T3.8 green.
2. A3.1..A3.3 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase3-signoff.md`.

---

# PHASE 4 · Projections

### Objective
Author every projection function as a **pure function of the authoritative tier**. Projections exist as libraries — no route calls them in Phase 4. Legacy consumers still call their existing sources. Byte-level determinism vs. legacy output on a golden corpus MUST be proven.

### Files / modules affected
- **NEW** projection modules (one per projection):
  - `project_verdict(SSOT) → Verdict`
  - `project_attck(SSOT) → List[Technique]`
  - `project_attack_chain(SSOT) → List[Stage]`
  - `project_attack_story(SSOT) → AttackStory`
  - `project_evidence_graph_view(SSOT) → GraphView` (thin passthrough)
  - `project_analyst_summary(SSOT) → AnalystSummary`
  - `project_executive_summary(SSOT) → ExecutiveSummary`
  - `project_recommendations(SSOT) → List[Recommendation]` (evidence-tied per technique; **no generic template fallback**)
  - `project_timeline(SSOT) → Timeline`
  - `project_lolbas(SSOT) → List[LolbasHit]`
  - `project_iocs(SSOT) → IOCBundle`
  - `project_activity(SSOT) → InvestigationModel` (SSOT-A projection)
  - `project_canonical(SSOT) → Canonical` (SSOT-B projection)
  - `project_evidence_bundle(SSOT) → EvidenceBundle` (SSOT-E projection)
  - `project_reports(SSOT) → Reports{stix, sigma, yara, navigator, mdr}`
- **NEW** golden-corpus fixture: N inputs (Sample.docx included as a re-ingested new case + a diverse set to stress the projections).
- **Existing consumers** — NOT modified.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 4 disposition |
|---|---|
| Legacy composers (`mdr_executive_card`, `investigation_narrative`, `investigation_report`, `render()`, `refresh_verdict`, DIE analyst_narrative) | KEEP untouched in Phase 4 — used as ORACLES for byte-identity comparison |
| Projection modules | **NEW** |
| Generic recommendation template in `services/die/analyst_narrative.py` | **KEEP untouched in Phase 4** — will be removed in Phase 8 |

### Dependencies
- Upstream: Phase 3 complete (projections require populated authoritative SSOTs).
- Downstream blocks: Phase 5 (entry adapters must be able to emit projections).

### Tests / gates
- **T4.1** Per-projection determinism test: `project_X(SSOT)` byte-identical across 100 replays.
- **T4.2** Per-projection golden-corpus test: for a fixed corpus of N inputs, `project_X(SSOT(input)) == legacy_X(input)` byte-for-byte, OR an owner-approved allowed diff documented in `/app/memory/adr/0005-phase4-allowed-diffs.md`. **Allowed diffs must be enumerated per input per projection; no blanket allowance.**
- **T4.3** INV-1 test: no projection reads from any source other than the authoritative tier. Static analysis test on the projection modules.
- **T4.4** No-fallback test: `project_recommendations` with an SSOT that has no MITRE returns an EMPTY list plus a `reasoning_step` recording "no MITRE evidence available". It does NOT emit the generic template.
- **T4.5** Rebuild-idempotence test: `project_X(SSOT) == project_X(project_reverse_if_possible(project_X(SSOT)))` — for projections that have an inverse; for lossy projections, documented as lossy.
- **T4.6** Isolation test: no existing route invokes any projection in Phase 4.

### Sample1-equivalent acceptance
- **A4.1** Re-ingest `Sample.docx` as a NEW case through composer → executor → authoritative SSOT. Then invoke every projection. Verify against the Sample1 acceptance table (`GOLDEN_CASE_SAMPLE1.md` §10 row-by-row):
  - `iocs.urls / ips / domains / emails` populated where present in DOCX text
  - `mitre` non-empty with evidence pointers
  - `lolbas` populated per detected binary
  - `attack_chain` = ordered `Stage[]` with per-stage evidence
  - `attack_story` structured (not a generic template)
  - `executive_summary` = 5-question card with evidence pointers
  - `analyst_summary` structured with evidence pointers
  - `recommendations` per-technique, evidence-tied; no generic block
  - `timeline` populated
  - Determinism: identical byte hash across replays
- **A4.2** Sample1 original record unchanged (fingerprint).

### Projection acceptance (this is the gate that unlocks Phase 5)
- **P4.G1** Every projection passes T4.2 golden-corpus byte-identity or has documented owner-approved diffs.
- **P4.G2** A4.1 passes on the Sample1-equivalent case.
- **P4.G3** A cross-checked report — `/app/memory/adr/0005-phase4-projection-acceptance.md` — enumerates every projection, its status, and its allowed diffs.

### Rollback boundary
- **Full rollback**: delete projection modules. Legacy composers untouched. No route depends on projections in Phase 4.
- **Time budget**: minutes.

### What remains frozen during Phase 4
- Routes, existing composers (used as oracles), Wave 1, Engine A, canonical v2 verdict, Workspace UI, ADR-004.

### Exact STOP condition
1. T4.1..T4.6 green.
2. A4.1, A4.2 verified.
3. P4.G1, P4.G2, P4.G3 signed off.
4. Owner sign-off recorded in `/app/memory/adr/0005-phase4-signoff.md`.

**This is the largest gate in the sequence.** Nothing in Phase 5 begins until Phase 4's projection acceptance is proven.

---

# PHASE 5 · Entry-Point Convergence (per route, gated)

### Objective
Migrate entry points ONE AT A TIME to the canonical lifecycle. Each route migration is an independent sub-phase with its own gate. Under D5-β, a shim on `cases.py::save_case` accepts both legacy raw input and canonical SSOTs during migration.

### Route migration order (proposed — owner may reorder)
Order chosen to migrate low-risk / low-traffic routes first, so the canonical lifecycle is proven under real traffic before touching the primary Workspace surface.

1. **5.1** `POST /api/uil/investigate` (UIL — lowest current traffic; already partly IUE-driven via IUE-2 delegation)
2. **5.2** `POST /api/sessions/investigate` (Sessions — same shape, second lowest traffic)
3. **5.3** `POST /api/die/investigation-results` (DIE — Workspace already tolerates the `Canonical` projection contract)
4. **5.4** `POST /api/documents/{id}/re-investigate` (Docs Re-Investigate — removes the L1 direct-MDR-jump; input is bytes-friendly)
5. **5.5** `POST /api/v2/auto-investigate` (Auto-Investigate — IUE runs first instead of post-hoc stamp)
6. **5.6** `POST /api/decode/smart` (Workspace paste — largest active traffic; migrated after all downstream sub-phases proven)
7. **5.7** `POST /api/cases/save` (Save Case — the very route Sample1 exposed; shim accepts either legacy or SSOT during 5.7)
8. **5.8** `POST /api/cases/{id}/reinvestigate` (Reinvestigate — analog to 5.7)

Each of 5.1–5.8 has its own full gate (design → implement → tests → Sample1-equivalent → projection acceptance → determinism → sign-off) before the next sub-phase begins.

### Per-sub-phase files affected
- Only the specific route file + its EntryAdapter.
- **Never** the underlying Analyzers, projections, composer, executor, or authoritative tier — those are frozen after Phase 4.
- No other routes touched in the same sub-phase.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes (per sub-phase)
| Component | 5.x disposition |
|---|---|
| Target route handler | ADAPT — becomes a thin EntryAdapter → canonical lifecycle → projection response |
| Legacy pipeline for target route (e.g. `decode_smart`, `render()`, MDR pipeline) | KEEP untouched — used as behavioural oracle during sub-phase; retired in Phase 10 |
| All other routes | FROZEN |

### Dependencies (per sub-phase)
- Upstream: Phase 4 complete + all previous 5.x sub-phases signed off.
- Downstream blocks: none within Phase 5 (sub-phases are strictly sequential).

### Tests / gates (per sub-phase 5.x)
- **T5.x.1** Parallel-response test: for a fixed corpus, canonical response byte-identical (or allowed-diff) vs. legacy pipeline response on the same input.
- **T5.x.2** Traffic-shadowing test (if feasible in the pod): production traffic mirrored to the canonical path; canonical response compared to legacy in read-only mode for M requests; discrepancies triaged.
- **T5.x.3** No-cross-contamination test: sub-phase 5.x's migration does not change the behaviour of any other route.
- **T5.x.4** Persistence-shape test (specifically for 5.7 / 5.8): `workspace_cases.ssot` field continues to project the `Canonical` shape (SSOT-B projection) during migration; NEW cases persist an `ssot_ref` pointer to the authoritative store; historical cases untouched.
- **T5.x.5** Wave 1 label test: canonical route emits Wave-N observations with `source_ssot_shape`, `source_ssot_version`, `source_path`, `segment=canonical_v1` (all Phase 6 fields must be plumbed even if Phase 6 hasn't converted the pre-segment).

### Sample1-equivalent acceptance (per sub-phase)
- **A5.x** Re-ingest `Sample.docx` through the target route (NEW case). Verify §10 acceptance table row-by-row for that route's specific consumers.
- Sample1 original record unchanged (verified after every sub-phase — this is a running invariant).

### Projection acceptance (per sub-phase)
- P5.x.G1: byte-identical or allowed-diff parity against legacy for the target route's projection output.

### Rollback boundary (per sub-phase)
- Feature flag per sub-phase (`ENABLE_CANONICAL_ROUTE_<X>`). Flag off → route reverts to legacy handler immediately. **Data written in canonical form remains valid** (schema-versioned per D9).
- Rollback of a single sub-phase does NOT force rollback of prior sub-phases (they remain converged).

### What remains frozen during each sub-phase
- All other routes.
- Composer / SSOT / Executor / Projections (foundation is now immutable input to Phase 5).
- Sample1 record (permanent).
- ADR-004 Step 2 (waits for Phase 9).
- Workspace UI (waits for Phase 8).

### Exact STOP condition (per sub-phase)
1. T5.x.1..T5.x.5 green.
2. A5.x verified.
3. P5.x.G1 signed off.
4. Owner sign-off recorded in `/app/memory/adr/0005-phase5-{sub-phase}-signoff.md`.
5. Feature flag left ON for a minimum soak window (owner-defined; propose 72 h) before the NEXT sub-phase begins.

---

# PHASE 6 · Wave 1 Relabelling + Fresh Segment

### Objective
Extend the `verdict_shadow_observations` record schema with `source_ssot_shape, source_ssot_version, source_path, input_completeness_by_bucket, segment` fields. Lock the existing 2 records into segment `pre_ssot_reconciliation`. Begin the fresh `canonical_v1` segment fed by the canonical Executor's shadow attach.

### Files / modules affected
- Observation-record schema (additive migration — INV-4).
- One-time backfill script: existing 2 records → `segment=pre_ssot_reconciliation` (label only; content untouched).
- Canonical Executor's shadow attach (already implemented in Phase 3; Phase 6 turns on the labelling).
- Query layer: aggregation queries without `segment` return an error (per W1-A rule 2).

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 6 disposition |
|---|---|
| Existing 2 observations | KEEP untouched (label added as read-time overlay OR one-time backfill; content byte-identical either way) |
| Existing shadow attach in `auto_investigate.py:798-807` | KEEP for as long as its route exists; its observations tagged `source_path="cio.compute_shadow"` if still emitting after Phase 5.5 |
| Existing shadow attach in `v2/jobs/pipeline.py:679-720` | KEEP for as long as MDR pipeline exists; observations tagged `source_path="investigation_model.from_model"` |
| Canonical Executor's shadow attach | **NEW** (turns on in Phase 6); tagged `source_path="canonical_v1"` |
| Aggregation query layer | ADAPT (mandatory segment filter) |

### Dependencies
- Upstream: Phase 5.1–5.8 complete (canonical Executor is now the main investigation orchestrator).
- Downstream blocks: Phase 9 (ADR-004 Step 2 requires `canonical_v1` segment authorised sample size).

### Tests / gates
- **T6.1** Backfill test: existing 2 records get `segment=pre_ssot_reconciliation` label; determinism fingerprints of the underlying observation content unchanged.
- **T6.2** New-record test: canonical Executor's shadow attach emits records with all 5 new fields populated.
- **T6.3** Query-guard test: aggregation queries without `segment` filter raise an error; queries with explicit `segment` succeed.
- **T6.4** Pre-segment lock test: attempts to insert new records into `segment=pre_ssot_reconciliation` are rejected.

### Sample1-equivalent acceptance
- **A6.1** Sample1 original record's absence from `verdict_shadow_observations` is preserved (R-G5). No back-attach occurs.
- **A6.2** A NEW ingestion of `Sample.docx` in the `canonical_v1` segment produces a labelled observation record.

### Projection acceptance
- Wave 1 records are not projections; Phase 6 is a data-schema evolution.

### Rollback boundary
- Fields are additive (INV-4). Rollback = ignore new fields in queries. No destructive change.

### What remains frozen during Phase 6
- Engine A (still authoritative).
- ADR-004 Step 2 (waits until authorised sample size in `canonical_v1`).
- All route decisions made in Phase 5.
- Sample1 record.

### Exact STOP condition
1. T6.1..T6.4 green.
2. A6.1, A6.2 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase6-signoff.md`.

---

# PHASE 7 · Sample1 Acceptance Regression

### Objective
Formally re-ingest `Sample.docx` as a **NEW** case through the fully canonical lifecycle and verify every row of `GOLDEN_CASE_SAMPLE1.md` §10. Produce the acceptance report.

### Files / modules affected
- None (verification phase).
- New acceptance report: `/app/memory/adr/0005-sample1-canonical-acceptance.md`.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
- No changes. Verification only.

### Dependencies
- Upstream: Phases 1–6 complete.

### Tests / gates
- **T7.1** Re-ingest `Sample.docx` bytes through canonical `POST /api/decode/smart` OR `POST /api/documents/{id}/re-investigate` (both should behave identically after Phase 5) as a NEW case.
- **T7.2** Verify §10 acceptance table row-by-row on the NEW case's persisted SSOT + projections.
- **T7.3** Verify Sample1 original record fingerprint unchanged.
- **T7.4** Verify determinism: repeat T7.1 five times; all five NEW cases produce the byte-identical authoritative SSOT (canonical JSON sha256).
- **T7.5** Verify NEW case's `verdict_shadow` record present in `canonical_v1` segment with full labels.

### Sample1-equivalent acceptance
- **A7.1** Every row of `GOLDEN_CASE_SAMPLE1.md` §10 satisfied.
- **A7.2** Sample1 original record unchanged.
- **A7.3** No regression against Phase 4 golden corpus (P4.G1 re-verified).

### Projection acceptance
- Every projection listed in Phase 4 outputs evidence-backed content on the NEW case; no generic template.

### Rollback boundary
- Verification only — no rollback needed.

### What remains frozen during Phase 7
- Everything except the new acceptance report artefact.

### Exact STOP condition
1. T7.1..T7.5 green.
2. A7.1..A7.3 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase7-signoff.md`.
4. `/app/memory/adr/0005-sample1-canonical-acceptance.md` produced.

**This is the acceptance moment for the canonical foundation.** Phase 8 (Workspace UI) is gated on this.

---

# PHASE 8 · Workspace UI Verification & Template Removal

### Objective
Verify the Workspace UI renders correctly against canonical projections. Remove the generic recommendation template fallback in `services/die/analyst_narrative.py` (no longer needed — Phase 4 already established `project_recommendations` returns an empty list with a reasoning step when MITRE evidence is absent, per T4.4).

### Files / modules affected
- `services/die/analyst_narrative.py` — remove the generic recommendation template fallback block.
- `/app/frontend/src/pages/WorkspacePage.jsx` — verified against canonical projection payloads; feature-flag any UI adjustments needed to consume the fully-populated shape.
- No other UI files unless a specific consumer is broken.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 8 disposition |
|---|---|
| Generic recommendation template in `services/die/analyst_narrative.py` | **DEPRECATE + REMOVE** (owner-authorised removal; the projection-based system replaces it) |
| WorkspacePage.jsx | KEEP + verify (feature flag `WORKSPACE_CANONICAL_UI` if any breakage) |
| Other UI files | KEEP |

### Dependencies
- Upstream: Phase 7 signed off.

### Tests / gates
- **T8.1** UI regression corpus: on the Phase 4 golden corpus, WorkspacePage renders each panel (Verdict, IOCs, MITRE, LOLBAS, Attack Chain, Attack Story, Executive Summary, Analyst Summary, Recommendations, Evidence Graph) with evidence-backed content.
- **T8.2** No-generic-template test: `services/die/analyst_narrative.py` no longer contains the "IMMEDIATE / THREAT HUNTING / CONTAINMENT" hard-coded template block.
- **T8.3** Empty-evidence rendering test: for an input with no MITRE evidence, the Recommendations panel renders an explicit "no evidence-derived recommendations for this case" state — NOT the generic template.
- **T8.4** Feature-flag rollback test: with `WORKSPACE_CANONICAL_UI=off`, UI reverts to legacy rendering (final safety net during rollout).

### Sample1-equivalent acceptance
- **A8.1** Re-ingest `Sample.docx` NEW case; WorkspacePage renders every panel with evidence-backed content.
- **A8.2** Screenshot the Recommendations panel — it does NOT contain the "IMMEDIATE / THREAT HUNTING / CONTAINMENT" template.
- **A8.3** Sample1 original record unchanged.

### Projection acceptance
- Every panel consumes a canonical projection; no panel synthesises its own MITRE / attack chain / verdict.

### Rollback boundary
- Feature flag `WORKSPACE_CANONICAL_UI` off → UI reverts.
- Generic-template removal is code-level; reversible by revert commit if needed within the same release window.

### What remains frozen during Phase 8
- Engine A (waits for Phase 9).
- ADR-004 Step 2.

### Exact STOP condition
1. T8.1..T8.4 green.
2. A8.1..A8.3 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase8-signoff.md`.

---

# PHASE 9 · ADR-004 Step 2 (Verdict Consumer Switch)

### Objective
Retire Engine A as the authoritative verdict source. Canonical v2 becomes authoritative, consuming the canonical SSOT authoritative tier directly. Only proceeds if the `canonical_v1` Wave-N segment has accumulated the owner-authorised sample size and divergence stays within owner-authorised thresholds.

### Files / modules affected
- Engine A retirement (marked DEPRECATE; consumers switched to canonical v2 output on the SSOT).
- `v2/verdict/canonical.py::score` becomes the authoritative scorer.
- All consumers that read `cio.verdict` or `refresh_verdict()` output → read `SSOT.verdict` written by the canonical scorer.
- Wave-N segment continues; scorer's output is now the primary verdict, not a shadow.

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
| Component | Phase 9 disposition |
|---|---|
| Engine A | DEPRECATE (code kept for a grace window; consumer count = 0 target) |
| `v2/verdict/canonical.py` | ADAPT (authoritative input = canonical SSOT authoritative tier) |
| `v2/verdict/shadow.py::compute_shadow` | DEPRECATE |
| `v2/verdict/canonical_input.py::from_investigation_model` | DEPRECATE |
| `refresh_verdict()` (`nivxforge/investigation/verdict_engine.py`) | DEPRECATE |

### Dependencies
- Upstream: Phase 8 signed off.
- Additional gate: `canonical_v1` segment sample size ≥ owner-authorised threshold; divergence within owner-authorised bounds.

### Tests / gates
- **T9.1** Sample-size gate: `canonical_v1` observation count meets owner-defined n per class.
- **T9.2** Divergence gate: canonical v2 vs. Engine A divergence within authorised thresholds on the `canonical_v1` segment.
- **T9.3** Consumer-switch test: every consumer that read Engine A's verdict now reads canonical v2's; byte-identical or allowed-diff.
- **T9.4** Sample1-equivalent NEW case: verdict produced by canonical v2 matches the acceptance table row.
- **T9.5** Rollback test: feature flag flips consumer back to Engine A; verdict output reverts.

### Sample1-equivalent acceptance
- **A9.1** NEW `Sample.docx` case's verdict is produced by canonical v2 and passes the acceptance table.
- **A9.2** Sample1 original record unchanged.

### Projection acceptance
- `project_verdict(SSOT)` is now the single authoritative verdict projection.

### Rollback boundary
- Feature flag `AUTHORITATIVE_VERDICT_ENGINE={engine_a|canonical_v2}` — flip to `engine_a` restores the pre-Phase-9 state within seconds.

### What remains frozen during Phase 9
- Engine A CODE (kept for grace window; deletion in Phase 10).
- All other components.

### Exact STOP condition
1. T9.1..T9.5 green.
2. A9.1, A9.2 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase9-signoff.md`.

---

# PHASE 10 · DEPRECATE (Consumer-Count = 0 Removals)

### Objective
Delete components whose consumer count has reached zero. Only after every replacement is proven and stable.

### Files / modules affected (candidates — actual deletion set gated on consumer-count telemetry)
- IUE-1 (`nivxforge/investigation/input_understanding.py`) — after every caller migrated to composer
- `decode_smart` orchestration in `routers/ops.py` — after Phase 5.6 stabilised (route thin adapter survives; orchestration retires)
- `render()` in `services/die/investigation_results.py` — after Phase 5.3 stabilised
- `refresh_verdict()` in `nivxforge/investigation/verdict_engine.py` — after Phase 9 stabilised
- `compute_shadow(cio)` in `v2/verdict/shadow.py` — after Phase 6 stabilised
- `from_investigation_model()` in `v2/verdict/canonical_input.py` — after Phase 9 stabilised
- North Star CIO standalone module in `nivxforge/core/cio.py` — after invariants absorbed into authoritative tier
- Engine A — after Phase 9 grace window
- Legacy pre-IUE routes (`analyze.py`, `chain.py`, subset of `ai.py`, `iedde.py`, `moe_panel.py`, `threat_model.py`) — after each route's consumer count = 0

### KEEP / ADAPT / WRAP / PROJECTION / DEPRECATE changes
- All target components DELETED.

### Dependencies
- Upstream: Phase 9 signed off + owner-defined stability window met (propose ≥ 2 weeks) + per-component consumer-count telemetry = 0.

### Tests / gates
- **T10.1** Consumer-count telemetry: automated scan proves zero imports / zero route hits for each candidate before deletion.
- **T10.2** Deletion regression test: golden corpus continues to pass post-deletion.
- **T10.3** Sample1-equivalent NEW case: all acceptance rows still pass.
- **T10.4** Rollback test: deletion is behind a per-component removal commit; git revert restores.

### Sample1-equivalent acceptance
- **A10.1** NEW `Sample.docx` case still passes every row of `GOLDEN_CASE_SAMPLE1.md` §10 post-deletion.
- **A10.2** Sample1 original record unchanged.

### Projection acceptance
- No new projections; projections continue to work.

### Rollback boundary
- Per-component deletion commit; git revert restores.
- **This is the first phase where irreversibility begins (post grace window).**

### What remains frozen during Phase 10
- Sample1 record (permanent invariant).
- Authoritative SSOT contract.
- Composer contract.
- Executor contract.
- Projection contracts.

### Exact STOP condition
1. T10.1..T10.4 green (per component).
2. A10.1, A10.2 verified.
3. Owner sign-off recorded in `/app/memory/adr/0005-phase10-{component}-signoff.md` PER COMPONENT DELETED.

---

## Cross-phase invariants (must hold across ALL phases)

- **IX-1 Sample1 fingerprint** `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` must be re-verifiable at any point during any phase. Any drift = phase halt.
- **IX-2 No cross-phase merging.** Each phase's tests / acceptance / determinism / sign-off must be complete before the next phase begins. No "we'll validate the projection in Phase 5" shortcut.
- **IX-3 No bypass movement.** No phase redirects a route from one legacy pipeline to another legacy pipeline. Routes either stay legacy or converge to the canonical lifecycle — nothing in between.
- **IX-4 Additive migration.** Every schema change is a superset add (INV-4). Field removals require an ADR (D9-both).
- **IX-5 Feature-flag rollback.** Every user-visible change is behind a per-change feature flag until owner-authorised for permanent status.
- **IX-6 Sign-off is per file.** Each phase produces a dated sign-off document at `/app/memory/adr/0005-phase{N}-signoff.md`. Owner-signed. Not implied.

---

## Explicit non-goals of this sequence (echoed from ADR-005 §12)

This sequence does NOT:
- Modify any code, routes, migrations, scoring, UI, Wave 1, ADR-004, Engine A, Sample1, or any DB collection in Phases 0–4.
- Modify anything in Phases 5+ without prior owner sign-off on the specific phase.
- Prescribe module names, class names, endpoint names — those are settled in the per-phase implementation spec that comes AFTER this sequence is approved.
- Prescribe storage layout beyond the invariants stated (immutable store extension, content-addressed fingerprint).
- Prescribe timelines, resourcing, team assignments.
- Authorise deletion outside the Phase 10 gate.

---

## STOP

Per directive: **no code changes, no route changes, no DB modifications,
no Wave 1 modifications, no ADR-004 modifications, no Engine A
modifications, no verdict modifications, no Workspace UI modifications,
no implementation authorised.**

**Awaiting owner review of this sequence. Only on owner sign-off may
Phase 1 begin — and only Phase 1, with its own gate.**

Sample1 remains the untouched pre-canonical golden baseline (R-G1..R-G6).
