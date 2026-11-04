# ADR-005 · Canonical Architecture Migration Map (DESIGN-ONLY, READ-ONLY)

- **Status**: Proposed · awaiting owner review
- **Date**: 2026-08-10
- **Source of truth**: `/app/memory/adr/0005-canonical-investigation-architecture.md` + `/app/memory/adr/0005-owner-decision-matrix.md` (owner decisions recorded 2026-08-10)
- **Golden acceptance case**: `/app/memory/GOLDEN_CASE_SAMPLE1.md`
- **Explicit non-goals**: no code changes, no route changes, no DB modifications, no Wave 1 modifications, no ADR-004 modifications, no Engine A modifications, no verdict modifications, no Workspace UI modifications, no implementation authorised. This document is a design artefact only.

## Owner decisions carried into this map

| D | Decision |
|---|---|
| D1 | Composer over IUE-2 / IUE-3 / IUE-4 / IUE-5 sub-classifiers |
| D2 | Two-tier canonical SSOT (authoritative graph + canonical projection tier) |
| D3 | Both ReasoningStep + Provenance envelope |
| D4 | plan[] + dispatch[] + `dispatch_policy` |
| D6 | Recursive-store BY REFERENCE into the immutable SSOT store |
| D7 | Wave 1: segment-and-continue with locked pre-segment |
| D10 | ADR-005 is a prerequisite to ADR-004 Step 2 |
| L1b | **REJECTED** — no tactical `cases.py` routing patch |

---

## Legend

Every existing component below is classified into one of five disposition states.
Nothing is deleted before its replacement is proven; nothing is duplicated.

| Disposition | Meaning |
|---|---|
| **KEEP** | Component survives unchanged. Same code, same contract, same consumers. It is already canonical (or trivially so). |
| **ADAPT** | Component survives with a modified contract to fit the canonical architecture. Existing consumers may need a shim. |
| **WRAP** | Component's behaviour survives, but it is fronted by a canonical facade (e.g. the composer IUE fronts IUE-2/3/4/5). Direct callers are gradually retargeted at the facade. |
| **PROJECTION** | Component is redefined as a **pure function of the canonical SSOT** — no longer authoritative, no longer allowed to compute its own truth. Rebuild from the canonical SSOT on demand. |
| **DEPRECATE** | Component is scheduled for removal AFTER its consumers migrate. Deletion happens only when consumer count = 0 and Sample1 acceptance test §10 passes without it. |

Every disposition satisfies the invariants recorded in the decision matrix (INV-1..INV-6), most importantly:
- **INV-1** — no analyser / decoder / verdict engine / report generator / UI component becomes an alternative SSOT.
- **INV-4** — additive migration; field removals require a major schema-version bump.

---

## PART 1 · IUE modules

| Component | Today's role | Disposition | Post-migration role |
|---|---|---|---|
| **IUE-1** · `nivxforge/investigation/input_understanding.py` (17-cat stamp) | Post-hoc metadata stamp on `cio.metadata.input_understanding`; `route` field never consumed | **DEPRECATE** | Removed once every caller (currently `decode_smart`, `auto_investigate`, `die.py`) reads `iue_decision.intent` + `iue_decision.input_profile` from the canonical SSOT. Metadata semantics are covered by the composer's `IntentClassifier` sub-classifier (see D1-D). |
| **IUE-2** · `services/die/input_understanding.py` (761 LOC, plan+executor+ConfidenceMatrix) | Whole-pipeline executor on `/api/die/*`, `/api/sessions/*`, `/api/uil/*` | **ADAPT** (into two roles) | (a) The **classification + plan-emission** portion becomes a sub-classifier under the composer (D1-D) — `TextStructureClassifier` + `LanguageClassifier` + `IntentClassifier` + `PlanBuilder`. (b) The **`_execute_plan()` executor** portion moves to the Executor role (§5 of ADR-005) — no longer bundled with the classifier. |
| **IUE-3** · `v2/investigation/iu/engine.py` + `detectors/*` (multi-artefact + capability dispatch) | Evidence-graph annotator inside `v2/investigation/graph/builder.py` | **ADAPT** | Becomes the composer's `MultiArtefactDetector` + per-language detector fleet. Continues emitting `Evidence` with `source="input_understanding.<name>"`. Its `Capability` dispatch list feeds the canonical `IUEDecision.dispatch[]` (D4-3). |
| **IUE-4** · `services/uil/classifier.py` (33-kind bytes-native `InputKind` enum) | Front door for `/api/uil/*` only | **ADAPT** | Becomes the composer's `BytesMagicClassifier` + `MixedInputSplitter`. The **only** sub-classifier that natively handles bytes/binary — kept precisely for this. `InputKind` enum survives as the `IUEDecision.input_profile.primary_type` taxonomy. |
| **IUE-5** · `services/ida/input_classifier.py` (artefact decomposition + IDA verdict) | Called by IUE-2 executor's IDA step | **ADAPT** | Becomes an **Analyzer** (executor plug-in) invoked by the `ARTIFACT_SPLIT` and `IDA_ACQUIRE` capabilities — not an IUE. Rationale: it operates on already-classified input; per §5 of ADR-005 this is Analyzer, not IUE. |
| `services/die/input_health.py` | Reachable only via `/api/die/health-check` | **KEEP** + **ADAPT** wiring | Code kept; wiring changes so that InputHealth runs **before** IUE on every canonical entry point (ADR-005 §3.1). Output lands in `SSOT.input_health`. |
| **NEW** · Canonical IUE Composer | — | **NEW** | Thin composer (D1-D). Aggregates sub-classifier `Evidence`; emits `IUEDecision{input_health, input_profile, intent, capabilities, plan, confidence_matrix, dispatch_policy, provenance, next_engine_hint}`. Deterministic; determinism hash exposed. Zero investigation logic — composition only (INV-6). |

**Dependency**: nothing outside PART 1 blocks these adaptations. The composer can be authored **before** any consumer switches (it lives alongside existing IUEs).

---

## PART 2 · SSOT-shaped objects

| Component | Today's role | Disposition | Post-migration role |
|---|---|---|---|
| **SSOT-A** · `v2/investigation/model.py::InvestigationModel` (MDR 9-bucket) | Produced by MDR pipeline; consumed by narrative / report / Wave 1 shadow input | **PROJECTION** | Redefined as the **`activity` projection tier** of the two-tier canonical SSOT (D2-d). `processes/files/network/registry/auth` buckets survive verbatim; `raw_events` bucket is removed (data lives on the authoritative graph). Rebuild function: `project_activity(SSOT.evidence_graph) → InvestigationModel`. |
| **SSOT-B** · `services/die/canonical.py::Canonical` (die-Canonical, persisted as `ssot` v1.0) | Persisted on `workspace_cases.ssot`; consumed by `WorkspacePage.jsx` via `/die/investigation-results` | **PROJECTION** | Redefined as the **`Canonical` projection** — its 21 fields become a Workspace-facing view over the authoritative graph. Rebuild function: `project_canonical(SSOT) → Canonical`. Persistence contract on `workspace_cases.ssot` is honoured during the phased migration (D5-β shim). |
| **SSOT-C** · `nivxforge/investigation/models.py::CIO` (ADR-0014, EvidenceGraph + ReasoningStep + Truth Model) | Authoritative for Workspace UI verdict/graph/reasoning; projected to InvestigationModel for Wave 1 shadow | **ADAPT** → becomes the **authoritative tier of the canonical SSOT** (D2-d) | Extended with: (a) `iue_decision`, (b) `execution_trace`, (c) mandatory `Provenance` envelope on every append (D3-z), (d) `artifacts[].investigation_ref → ssot_ref` (D6-r), (e) schema version bump. Slice-B/C/D/F placeholder fields (`timeline`, `verdict`, `summary`, `recommendations`, `reports`) are **filled by projectors** (see PART 6), not by the authoritative tier itself. |
| **SSOT-D** · `nivxforge/core/cio.py::CIO` (North Star, append-only, per-entry Provenance-mandatory) | Not populated by any engine today (Phase 0 placeholder) | **KEEP as reference contract** → **DEPRECATE** the standalone module | Its **append-only invariant + mandatory `Provenance{engine, at}` shape** is absorbed into SSOT-C's contract (D3-z Provenance envelope). Once SSOT-C carries the invariant, the standalone North Star module is retired. |
| **SSOT-E** · `l2_investigation/schemas.py::EvidenceBundle` (L4 Analyst Workspace bundle) | Frozen dataclass; input to L2 services | **PROJECTION** | Redefined as the **L4 Analyst Workspace projection** — a fingerprint-addressable, frozen view over the authoritative graph. Rebuild function: `project_evidence_bundle(SSOT) → EvidenceBundle`. `ConvergenceCertificate` becomes an evidence node in the graph; `SampleMetadata` becomes a projection over authoritative attributes. L2 services (`attack_story, capability_explorer, detection_rules, ...`) continue to accept `EvidenceBundle` unchanged. |
| **NEW** · Canonical Investigation SSOT (two-tier, D2-d) | — | **NEW** | Authoritative tier = extended SSOT-C. Canonical projection tier = registered `Projector`s producing SSOT-A / SSOT-B / SSOT-E / plus new projections (attack_chain, attack_story, executive_summary, analyst_summary, reports.*). Every projection is a **pure function** of the authoritative tier (INV-1). |

**Dependency**: PART 2 cannot land before PART 1 (the composer emits `iue_decision`, which is a first-class field on the authoritative tier).

---

## PART 3 · Investigation pipelines / orchestrators

| Component | Today's role | Disposition | Post-migration role |
|---|---|---|---|
| `routers/ops.py::decode_smart` (`/api/decode/smart`) | Workspace paste decoder; runs ingress_gate → CIM → CIO stamp → verdict → OSINT | **DEPRECATE** (behaviour preserved as executor plug-ins) | Split into Analyzers: (a) `IngressGate` → `VendorNormaliser` capability, (b) `AtomicIocGuard` → `IOC_EXTRACTOR` capability, (c) `DeterministicBestDecode` → `DECODER` capability, (d) CIM/CIO composition → replaced by the canonical SSOT builder, (e) verdict refresh → moves to the Composer/Projector role. **The `decode_smart` route survives as a thin entry adapter that packages request → EntryAdapter → canonical lifecycle → response projection.** Behaviour preserved; orchestration removed. |
| `v2/jobs/pipeline.py::run_investigation_with_progress` (MDR) | Auto-Investigate + Docs Re-Investigate | **ADAPT** → becomes an **Executor implementation** for the canonical lifecycle | Its steps (`_detect_commands`, `_extract_entities`, per-command decode, archetype pre-decode, `_flatten_mitre`, `_merge_iocs`, OSINT, `_investigation_quality`, `_mdr_executive_card`, `_build_investigation_model`, narrative/report composers) become **individually-addressable Analyzers/Composers**. The pipeline itself is retired as a monolithic orchestrator; a canonical Executor invokes the same Analyzers driven by the IUE plan (D4-3). |
| `services/die/investigation_results.py::render` | SSOT renderer for `/api/die/*`, `/api/sessions/*`, `/api/uil/*` | **DEPRECATE** (behaviour preserved as `project_canonical`) | The `Canonical` output shape becomes a **projection** (PART 2 SSOT-B disposition). The `render` function is retired; its steps that produce authoritative data (IUE + IDA + intent) run in the canonical Executor; the shape assembly moves to the projection tier. |
| `routers/workspace_investigation.py` (L1 Analyst Workspace) | Bundle-in / bundle-out CRUD | **KEEP** + **ADAPT** input | Continues to accept `EvidenceBundle`, but the bundle is now emitted as `project_evidence_bundle(SSOT)` (PART 2 SSOT-E disposition). L1 route contract is unchanged. |

**Dependency**: PART 3 requires PART 1 (composer emits the plan) and PART 2 (canonical SSOT exists to write into).

---

## PART 4 · Analyzers, decoders, IDA, recursive discovery

| Component | Disposition | Post-migration role |
|---|---|---|
| DIE semantic AST (`services/die/api.py::analyze`, PowerShell/CMD/Bash/JS/VBS/Python parsers) | **KEEP** | `SEMANTIC_AST` capability — Analyzer role |
| DIE DKP (`services/die/dkp/*`) | **KEEP** | `DKP_MATCH` capability — Analyzer |
| DIE chain analyzer (`services/die/chain.py`) | **KEEP** | `CHAIN_ANALYSIS` capability |
| DIE preprocessor (`services/die/preprocessor/*`) | **KEEP** | Executor plug-in (pre-decode staging) |
| DIE archive recovery (`services/die/archive_recovery.py`) | **KEEP** | `ARCHIVE_EXTRACT` capability |
| DIE intent (`services/die/intent.py`) | **KEEP** but move upstream | Called by the **composer IUE** as part of `IntentClassifier` — no longer a post-classification step |
| IDA acquisition (`services/ida/acquisition.py`) | **KEEP** | `IDA_ACQUIRE` capability (URL fetcher) |
| IDA artifact splitter/router (`services/ida/artifact_splitter.py`, `artifact_router.py`) | **KEEP** | `ARTIFACT_SPLIT` capability |
| MDR `_extract_entities`, `_detect_commands`, `_flatten_mitre`, `_merge_iocs`, `_investigation_quality` (`v2/mdr/*`) | **ADAPT** → per-capability Analyzers | Split out as individual Analyzers each writing to the authoritative graph with mandatory `Provenance`. Not a bundled pipeline. |
| MDR executive card, narrative, report composers | **ADAPT** → per-Projector | Executive card = `project_executive_summary`; narrative = `project_analyst_summary`; report = `project_reports`. Read authoritative SSOT, write projections. |
| Nivxforge OSINT enricher (`nivxforge/investigation/osint_enricher.py`) | **KEEP** as **Enricher** (isolated role, D8-s default) | External-lookup boundary; deterministic conclusion computable without it (INV-2) |
| Nivxforge verdict engine (`nivxforge/investigation/verdict_engine.py::refresh_verdict`) | **DEPRECATE** | Replaced by the canonical verdict engine (see PART 5) |
| Nivxforge recursive investigator (`nivxforge/investigation/recursive.py`) | **ADAPT** → becomes the `RECURSIVE_DISCOVERY` capability | Iteration loop retained; each child artefact enters `[Health → IUE → Executor]` producing a child SSOT stored **by reference** (D6-r); parent's projections roll up children with provenance edges |
| Nivxforge fact substrate (`nivxforge/cim/fact_substrate.py`) | **ADAPT** | Becomes the authoritative-tier writer: analyzer output → EvidenceGraph nodes with mandatory `Provenance` (D3-z) |

**Dependency**: PART 4 adaptations depend on PART 2 (canonical SSOT contract) but not on PART 3.

---

## PART 5 · Verdict engines

| Component | Today's role | Disposition | Post-migration role |
|---|---|---|---|
| Engine A (legacy authoritative verdict) | Authoritative on every consumer today | **KEEP** on the freeze — do NOT touch until D2 lands + labelled Wave 1 authorises the switch | Continues as authoritative during the migration. Retired only after ADR-004 Step 2 authorises the switch — which itself depends on D2 and labelled Wave 1 data. |
| `v2/verdict/canonical.py::score` (canonical v2, shadow) | Shadow-only; produces `verdict_shadow` | **ADAPT** | Its input contract changes: today it accepts a per-path projection (`compute_shadow(cio)` OR `from_investigation_model(model)`) — post-migration it accepts the **canonical SSOT authoritative tier directly** and outputs `SSOT.verdict{label, confidence, reason, contributors[], input_completeness}` |
| `v2/verdict/canonical_input.py::from_investigation_model` (Wave 1 shadow input) | Projects MDR model → verdict input | **DEPRECATE** | Replaced by the canonical SSOT authoritative-tier reader once D2 lands. Kept during the migration only as the input for **pre-canonical** Wave 1 observations (locked into segment W1-A). |
| `v2/verdict/shadow.py::compute_shadow` (CIO → InvestigationModel projection → shadow verdict) | The lossy hop identified in Wave 1 confound | **DEPRECATE** | Replaced. The `_cio_to_investigation_model` bridge is retired once the canonical SSOT is the direct shadow input. |

**Dependency**: PART 5 blocks nothing in PART 1-4 but is blocked BY PART 2. ADR-004 Step 2 (consumer switch) is blocked by PART 5.

---

## PART 6 · Downstream consumers → PROJECTIONS

Every consumer below becomes a **pure function of the canonical SSOT authoritative tier** (INV-1).

| Consumer | Today's source | Disposition | Rebuild function |
|---|---|---|---|
| Verdict card | `cio.verdict` (via `refresh_verdict`) + Wave 1 shadow | **PROJECTION** | `project_verdict(SSOT.evidence_graph, SSOT.activity, SSOT.threat_intel, SSOT.iue_decision.confidence_matrix, SSOT.input_completeness)` — writes back to `SSOT.verdict{contributors[]}` with provenance |
| ATT&CK mapping | Three parallel sources today (`mdr.mitre`, `cio.evidence_graph`, `analyze.mitre`) | **PROJECTION** — single source | `project_attck(SSOT.evidence_graph)` — each technique carries the evidence node(s) that justify it |
| Attack Chain | MDR / DIE / Workspace synthesise independently | **PROJECTION** — single source | `project_attack_chain(SSOT.evidence_graph, SSOT.attck)` — ordered `Stage[]` with per-stage `evidence_ids[]` |
| Attack Story | L2 `attack_story` service | **PROJECTION** | `project_attack_story(SSOT.attack_chain, SSOT.reasoning_steps, SSOT.context.historical)` |
| Evidence Graph view (Workspace) | Direct read from CIO | **KEEP** | Direct read from `SSOT.evidence_graph` (unchanged contract) |
| MITRE Heatmap (UI) | Various | **PROJECTION** | Reads `SSOT.attck` |
| Mitigation / Recommendations | Three parallel sources (`mdr_recommendations`, `cio.metadata.recommendations`, DIE generic template) | **PROJECTION** — single source | `project_recommendations(SSOT.attck, SSOT.iue_decision.intent, SSOT.verdict, SSOT.activity)` — evidence-tied per technique; NO fallback template; if the SSOT has no MITRE, that fact is itself recorded with provenance |
| Analyst Summary | Three parallel sources (`investigation_narrative`, `cio.summary`, `analyst_narrative`) | **PROJECTION** — single source | `project_analyst_summary(SSOT)` — structured, deterministic, evidence-pointered |
| Executive Summary | Two parallel sources (`mdr.executive_card`, `cio.summary`) | **PROJECTION** — single source | `project_executive_summary(SSOT.verdict, SSOT.iue_decision.intent, top-N SSOT.evidence_graph, SSOT.context.historical)` — 5-question card |
| Trajectory / Timeline | `mdr.mdr_investigation.timeline` | **PROJECTION** | `project_timeline(SSOT.evidence_graph, SSOT.execution_trace)` |
| Threat Intel view | Various | **KEEP** contract | Direct read from `SSOT.threat_intel` + per-node `attrs.enrichment` |
| LOLBAS | `cio.metadata.lolbas` | **PROJECTION** | `project_lolbas(SSOT.evidence_graph)` |
| Reports (STIX / Sigma / YARA / Navigator / MDR) | Two/three parallel sources | **PROJECTION** — single source | `project_reports(SSOT)` — one entry point per format |
| Wave-N shadow observation | Two upstream shapes today (CIO / InvestigationModel) | **ADAPT** | Reads canonical SSOT directly; every observation record carries `source_ssot_shape, source_ssot_version, source_path, input_completeness_by_bucket` (ADR-005 §10) |
| Case persistence (`workspace_cases`) | Persists `ssot: {die-Canonical v1.0}` today | **ADAPT** | Persists `ssot_ref → immutable SSOT store` (D6-r write-through); `workspace_cases.ssot` field survives during phased migration as a projection (D5-β shim). Full authoritative tier lives in the immutable store. |
| L4 Analyst Workspace bundle (`/api/investigation`) | `EvidenceBundle` (SSOT-E) | **PROJECTION** | `project_evidence_bundle(SSOT)` (see PART 2 SSOT-E) |

**INV-1 enforcement**: no consumer above is authoritative. Every consumer's output is regenerable from the authoritative tier alone.

---

## PART 7 · Workspace entry points

| Entry point | Today's route + pipeline | Disposition | Post-migration |
|---|---|---|---|
| Workspace paste (`POST /api/decode/smart`) | `decode_smart` monolith + IUE-1 stamp | **ADAPT** as thin **EntryAdapter** | Adapter sets `source_channel="workspace_paste"`, packages `RawInput{bytes/str, filename?, mime_hint?}` → invokes canonical lifecycle → returns projection response |
| Workspace Save Case (`POST /api/cases/save`) | `cases.py::save_case` → delegates to `decode_smart` | **ADAPT** as thin persistence adapter | Two modes: (a) persist an already-computed SSOT (`ssot_ref` provided by caller); (b) invoke canonical lifecycle first, then persist. Under D5-β, the shim accepts both a canonical SSOT and (temporarily) a raw input for legacy callers |
| Workspace Reinvestigate (`POST /api/cases/{id}/reinvestigate`) | `cases.py::reinvestigate_case` → delegates to `decode_smart` | **ADAPT** | Loads raw input from case → enters canonical lifecycle → writes new SSOT version to immutable store → updates `workspace_cases.ssot_ref` |
| Documents Re-Investigate (`POST /api/documents/{id}/re-investigate`) | L1 fix: jumps to MDR pipeline (bypasses IUE) | **ADAPT** | Removes the L1 direct-MDR-jump. Passes bytes + `filename` + `mime_hint` to the canonical lifecycle. Sets `source_channel="document_reinvestigate"` |
| Auto Investigate (`POST /api/v2/auto-investigate`) | MDR pipeline + IUE-1 post-hoc stamp | **ADAPT** | Sets `source_channel="auto_investigate"`, canonical lifecycle. IUE runs first (not stamped after) |
| DIE (`POST /api/die/{understand,investigation,investigation-results}`) | Runs IUE-2 whole-pipeline via `render()` | **ADAPT** | The `/api/die/*` shapes are preserved (they are UI projections) but their **implementation** projects from the canonical SSOT (`project_canonical`). IUE-2 whole-pipeline invocation is retired. |
| UIL (`POST /api/uil/{classify,split,investigate}`) | IUE-4 → delegates to IUE-2 | **ADAPT** | `/api/uil/classify` and `/api/uil/split` continue as thin wrappers around the composer's `BytesMagicClassifier` + `MixedInputSplitter`. `/api/uil/investigate` becomes an entry adapter to the canonical lifecycle. |
| Sessions (`POST /api/sessions/investigate`) | Delegates to `render()` | **ADAPT** | Entry adapter to canonical lifecycle; `source_channel="session"` |
| L4 Analyst Workspace (`POST /api/investigation`) | Bundle in / bundle out | **KEEP** contract | Continues accepting `EvidenceBundle`; the bundle is now emitted by `project_evidence_bundle` |
| Legacy `analyze.py`, `chain.py`, `ai.py`, `iedde.py`, `moe_panel.py`, `threat_model.py` routes | Pre-IUE pipelines | **DEPRECATE** (after consumer count = 0) | Absorbed into canonical-lifecycle capabilities; standalone routes retired once no consumers remain |
| Future EDR / SIEM / OT adapters | Not built | **NEW** | Vendor-normaliser executor runs first (Cisco / CrowdStrike / Defender / QRadar / SentinelOne / Splunk / vendor-JSON); canonical lifecycle downstream |

---

## PART 8 · Wave 1

| Concern | Disposition | Post-migration |
|---|---|---|
| Existing 2 records in `verdict_shadow_observations` | **KEEP untouched** in **locked pre-segment `pre_ssot_reconciliation`** (W1-A) | Read-only; no back-attach; no delete |
| Wave 1 attach in `auto_investigate.py:798-807` (`compute_shadow(cio)`) | **DEPRECATE** | Replaced by canonical-SSOT reader once D2 lands; label `source_path="cio.compute_shadow"` retained for historical records |
| Wave 1 attach in `v2/jobs/pipeline.py:679-720` (`from_investigation_model(model)`) | **DEPRECATE** | Same as above; label `source_path="investigation_model.from_model"` retained |
| Wave 1 attach going forward | **NEW** — attaches from the **canonical Executor** with mandatory record labels | Every record carries `source_ssot_shape`, `source_ssot_version`, `source_path`, `input_completeness_by_bucket`, `segment` (default `canonical_v1`) |
| Aggregation queries | **NEW rule** | Queries without an explicit `segment` filter return an error; cross-segment aggregation forbidden |
| Sample1 in Wave 1 | **STAYS ABSENT** (per R-G5, `GOLDEN_CASE_SAMPLE1.md`) | No retroactive attach; Sample1 remains a pre-canonical baseline forever |

---

## PART 9 · Dependency graph (safe migration order)

```
                     ┌──────────────────────────────────────────────┐
                     │  Phase 0 · Contracts frozen (no code)         │
                     │  D1..D10 owner decisions, migration map       │
                     │  reviewed & approved                          │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 1 · Canonical IUE Composer (D1-D)      │
                     │  New module; sub-classifiers ADAPT'd; no      │
                     │  route changes. Determinism tests locked.     │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 2 · Canonical SSOT authoritative tier  │
                     │  (D2-d + D3-z) — SSOT-C ADAPT'd with iue_     │
                     │  decision, execution_trace, Provenance        │
                     │  envelope, ssot_ref, schema version bump.     │
                     │  Immutable SSOT store (D6-r) extended for     │
                     │  child artefacts.                             │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 3 · Canonical Executor (D4-3)          │
                     │  New executor invokes plan[]/dispatch[]/      │
                     │  policy; retargets MDR/DIE Analyzers as       │
                     │  capability plug-ins. No route changes yet.   │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 4 · Projections (PART 6)                │
                     │  Every consumer becomes a PROJECTION over the │
                     │  canonical SSOT: verdict, attck, attack_chain,│
                     │  attack_story, analyst_summary, executive_    │
                     │  summary, recommendations, timeline, lolbas,  │
                     │  reports, EvidenceBundle, InvestigationModel, │
                     │  Canonical. Rebuild determinism proven.       │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 5 · Entry-point convergence (D5-β)     │
                     │  Each Workspace entry point becomes an        │
                     │  EntryAdapter → canonical lifecycle. Per-     │
                     │  route migration under shim; every route     │
                     │  validated against Sample1 acceptance test    │
                     │  §10 individually.                            │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 6 · Wave 1 relabelling + fresh segment │
                     │  (W1-A) — canonical Executor's shadow attach  │
                     │  produces labelled records; pre-segment       │
                     │  locked; ADR-004 Step 2 gate begins           │
                     │  accumulating authorised sample size.         │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 7 · Sample1 acceptance regression       │
                     │  Re-ingest Sample.docx as a NEW case; verify  │
                     │  §10 table row-by-row. Sample1 original        │
                     │  record stays untouched (R-G1..R-G6).         │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 8 · Workspace verification              │
                     │  UI panels validated against the canonical    │
                     │  SSOT (MITRE, Attack Chain, Attack Story,     │
                     │  Executive Summary, Recommendations,          │
                     │  Analyst Summary, Evidence Graph, Verdict).   │
                     │  Generic recommendation template REMOVED.     │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 9 · ADR-004 Step 2 (Verdict switch)    │
                     │  Only after Phase 8 passes AND labelled       │
                     │  Wave 1 sample size authorised. Engine A →    │
                     │  canonical v2 consumer switch.                │
                     └───────────────────────┬──────────────────────┘
                                             │
                                             ▼
                     ┌──────────────────────────────────────────────┐
                     │  Phase 10 · DEPRECATE                          │
                     │  Retire IUE-1, decode_smart orchestrator,     │
                     │  render(), refresh_verdict, from_invest_model,│
                     │  compute_shadow bridge, standalone            │
                     │  North Star CIO module. Only after            │
                     │  consumer count = 0 per component.            │
                     └──────────────────────────────────────────────┘
```

**Rules governing the order**:
- Phase N+1 cannot start until Phase N's acceptance is proven (Sample1-equivalent unit tests for each phase).
- No phase modifies Sample1 (R-G1..R-G6).
- No phase adds a fourth `verdict_shadow` attach site during migration; Wave 1 records the source_path.
- Phase 4 (projections) MUST prove `project_X(SSOT) == today's_X_output` on a golden corpus BEFORE any consumer switch in Phase 5. This is the anti-regression gate.

---

## PART 10 · Consumer-migration checklist (per component)

Before any component is switched to the canonical source:

1. Projection function exists and is unit-tested.
2. Golden-corpus determinism test passes: for a fixed set of inputs, `project_X(SSOT) == existing_X_output` byte-for-byte OR with a documented, owner-approved allowed diff.
3. Sample1 acceptance test row for X passes (§10 of the golden case document).
4. Wave-N observations for X carry `source_ssot_shape` labels.
5. Consumer count for the DEPRECATED source is verified before deletion.

---

## PART 11 · What this map does NOT decide

The map is deliberately silent on:

- **Naming** (module names, class names, endpoint names, field names) — will be settled in the implementation-sequence design that comes AFTER this map is reviewed.
- **Storage layout** (Mongo vs. Postgres, immutable-store internals, content-addressing vs. id-addressing) — deferred.
- **UI changes** — the map preserves current API shapes as projections; UI convergence is a separate design.
- **Timelines and resourcing** — this is a topology, not a schedule.
- **Testing strategy** — Sample1 is the acceptance canary; broader test-strategy design comes after the map is approved.
- **D5 phasing details** — default is D5-β (phased with shim); the shim's lifetime bound is deferred.
- **D8 clarifications** — default is D8-s (Enricher separate); the local-vs-network Enricher subtlety is deferred.
- **D9 breaking-major criteria** — default is D9-both; the ADR-per-breaking-major discipline is deferred.

## PART 12 · STOP

Per directive: no code changes, no route changes, no DB modifications,
no Wave 1 modifications, no ADR-004 modifications, no Engine A
modifications, no verdict modifications, no Workspace UI modifications,
no implementation authorised.

**Awaiting owner review of this map. On approval, the next artefact
proposed is the phase-by-phase implementation sequence (still design-
only, no code), gated on this map.**

Sample1 remains the untouched pre-canonical golden baseline.
