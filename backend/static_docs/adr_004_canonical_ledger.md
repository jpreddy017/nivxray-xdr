# ADR-004 · NivXRay Canonical Implementation Ledger

- **Status**: PROPOSED — awaiting owner sign-off
- **Date**: 2026-08-09
- **Supersedes**: Original 360° audit `2026-02-09` (rejected — see `CURRENT_STATE_AUDIT_RECONCILIATION.md`)
- **Author**: E1 (evidence-driven, no code changes in this ADR)
- **Applies to**: git HEAD `52007cbd`

---

## Context

The audit reconciliation established the operative diagnosis:

> **NivXRay is not underbuilt. It is overbuilt in parallel.**

At least 12 distinct capabilities have **≥ 2 competing implementations** coexisting in the same repository. No document declares which one is authoritative. Every new sprint has been landing complete implementations without retiring the old ones. This is the P0 problem — not features, not integrations, not telemetry ingest.

## Decision

Adopt this Canonical Implementation Ledger. For every conceptual capability, one implementation is **CANONICAL** — it owns the truth. All others are marked **FREEZE** (no new work), **MIGRATE** (transition callers to canonical), or **DELETE** (after parity is proven).

The ledger is binding for all future development, whether by human contributors or AI agents. **No PR may add a new implementation of a listed capability.** Extensions must happen inside the canonical module.

---

## Standing rules (apply to every entry below)

1. Every capability has **exactly one CANONICAL** implementation. Multiple canonical impls = policy violation.
2. Every canonical implementation must have a **canonical API** (single FastAPI router prefix). Overlapping routers are legacy.
3. Every canonical implementation must have **canonical tests** in `/app/backend/tests/`. Tests against legacy paths remain valid as parity harnesses only.
4. **Frontend** (`WorkspacePage.jsx` and children) may consume the canonical API only. Direct calls to legacy endpoints are legacy and to be migrated.
5. **Parity gate**: A legacy implementation may only be DELETED after a diff-parity test proves canonical output matches legacy output on the vendor corpus (`backend/corpus/vendor/v1/`).
6. **FREEZE means FREEZE.** No refactors, no bug fixes, no new features on legacy paths. Callers migrate; legacy dies.

---

## Ledger

### 1 · Verdict Engine

| Slot | Value |
|---|---|
| CANONICAL implementation | `backend/v2/verdict/` (engine.py · signals.py · weights.py · correlation.py · progressions.py · profiles.py) |
| CANONICAL API | `/api/v2/verdict/*` — verify router mount |
| CANONICAL data model | `v2/verdict/signals.py::Signal`, weights externalised in `weights.py` |
| CANONICAL tests | `tests/test_verdict_v3.py`, `tests/test_verdict_v3_correlation.py` |
| CANONICAL UI consumer | Workspace verdict card should read from v3 endpoint |
| LEGACY | `services/uaie/orchestrator.py` (verdict emission logic) — **FREEZE** |
| **Action** | Freeze `orchestrator.py` verdict code. Route WorkspacePage verdict fetch to v3 API. Prove parity via corpus replay. Then delete legacy verdict emission from orchestrator. |
| Rationale | v3 has separated signals/weights/correlation into named modules with tests. The legacy path is coupled inside a 1000+ line orchestrator. |

### 2 · Attack Story

| Slot | Value |
|---|---|
| CANONICAL | `backend/v2/investigation/attack_story.py` |
| CANONICAL API | Consumed via `v2/investigation/pipeline.py` → `v2/investigation/report.py` |
| CANONICAL tests | Any `tests/test_attack_story*` under `v2` (verify) |
| CANONICAL UI consumer | Workspace "Attack Story" tab |
| LEGACY | `services/reasoning/behavior_extractor.py`, `backend/v2/semantic/ps_storyline.py` — **FREEZE** both |
| **Action** | Freeze both legacies. `ps_storyline.py` narrative snippets may migrate INTO `attack_story.py` as helpers. `behavior_extractor.py`: retire once workspace reads v2. |
| Rationale | The v2 module has a first-class "story" model; the legacy ones return prose. |

### 3 · Evidence Layer + Evidence Graph

| Slot | Value |
|---|---|
| CANONICAL evidence model | `backend/engine/evidence_graph.py` (+ builder + config + observability) |
| CANONICAL API | Verify: engine module exports; likely surfaced via `routers/correlations.py` or `routers/rc5_entities.py` |
| CANONICAL data model | `engine/evidence_graph.py` node/edge types |
| CANONICAL tests | Verify — grep `engine/evidence_graph` in tests/ |
| CANONICAL UI consumer | Evidence Explorer / RC5 diagnostic UI |
| LEGACY | `services/uaie/evidence.py` (flat list model) — **FREEZE**, then **MIGRATE** callers |
| **Action** | UAIE evidence list becomes a projection view over the graph. Workspace reads graph, not the flat list. |
| Rationale | Graph is a superset of the list; only the graph supports path queries, ancestry, and correlation queries. |

### 4 · Provenance

| Slot | Value |
|---|---|
| CANONICAL | `backend/services/uaie/provenance.py` (ledger-oriented; ties to `uaie/ledger.py`) |
| CANONICAL API | Read-only; exposed via case fetch endpoints |
| CANONICAL tests | Verify |
| LEGACY | `services/confidence_provenance.py`, `services/canonical_evidence_recovery.py` — **FREEZE**, then decide: MIGRATE utilities into `uaie/provenance` OR keep as adjunct modules with clear "does X, provenance owned elsewhere" comments |
| **Action** | Confidence provenance may remain as a separate concern (confidence ≠ evidence) IF an ADR-004a clarifies the boundary. Otherwise merge. |
| Rationale | Provenance is high-risk to split; every claim must trace back through one ledger. |

### 5 · Planner / Pipeline / Orchestrator

| Slot | Value |
|---|---|
| CANONICAL pipeline | `backend/v2/investigation/pipeline.py` |
| CANONICAL API | `routers/workspace_investigation.py` if it invokes v2/investigation/pipeline; verify |
| CANONICAL tests | Verify — grep `v2/investigation/pipeline` in tests/ |
| CANONICAL UI consumer | AUTO INVESTIGATE workspace flow |
| LEGACY | `services/recipe_planner.py`, `services/uaie/planner.py`, `services/uaie/planner_v2.py`, `engine/orchestrator.py` — **FREEZE all 4** |
| **Action** | 5-way planner conflict is the single biggest architectural risk in the repo. The v2 pipeline is the youngest and most cohesive. Freeze everything else immediately. Migrate WorkspacePage.jsx's `autoInvestigate()` to call the v2 pipeline endpoint. |
| Rationale | Multiple planners = deterministic behavior guarantee is currently a lie. Every path picks different heuristics. |

### 6 · Correlation

| Slot | Value |
|---|---|
| CANONICAL | `backend/v2/investigation/cre/` (Correlation Reasoning Engine) |
| CANONICAL API | Verify — likely `routers/correlations.py` invocation path |
| CANONICAL data model | CRE wrappers in `v2/investigation/cre/wrappers/` |
| CANONICAL tests | Verify |
| CANONICAL UI consumer | Workspace correlation view |
| LEGACY | `services/correlation_engine.py`, `services/ice/correlate.py`, `engine/correlation_engine.py`, `v2/verdict/correlation.py` — **FREEZE all 4** |
| **Action** | CRE (Correlation Reasoning Engine) is the youngest and lives inside `v2/investigation/`. All other correlation paths must be marked legacy today. `v2/verdict/correlation.py` may remain as an internal helper of Verdict Engine — verify. |
| Rationale | 5 correlation engines = 5 different truth models. Reduces trust in verdict deterministically. |

### 7 · Knowledge Base

| Slot | Value |
|---|---|
| CANONICAL | `backend/services/knowledge/behavior_registry.py` (BKB · 108 curated entries · 532 LOC) |
| CANONICAL API | Read-only via ICE cluster projection; new admin endpoint TBD |
| CANONICAL data model | Static Python dict → PROMOTE to Mongo collection in future (see ADR-005) |
| CANONICAL tests | `tests/test_bkb_ci_gate.py`, `tests/test_quality_dashboard.py` (locks entry count) |
| CANONICAL UI consumer | Trajectory canvas + BKB admin UI (to be built) |
| LEGACY / PARALLEL | `backend/v2/ikb/entries.py` — **INVESTIGATE first** |
| **Action** | Owner decision needed: is IKB a superset (candidate replacement) or an unrelated concept (Investigation Knowledge Base vs Behavior Knowledge Base)? If superset → BKB migrates to IKB shape. If different concern → rename IKB to disambiguate and declare its own charter. |
| Rationale | BKB is a strategic asset (owner has stated); it must not be diluted by a competing knowledge base with unclear scope. |

### 8 · Golden Corpus / Validation Pack

| Slot | Value |
|---|---|
| CANONICAL corpus location | `backend/corpus/vendor/v1/` (curated vendor reports) |
| CANONICAL harness | `backend/v2/validation/runner.py` |
| CANONICAL taxonomy | `backend/engine/golden_corpus_taxonomy.py` |
| CANONICAL tests | `tests/test_quality_dashboard.py` (CI floors) |
| CANONICAL UI consumer | Benchmark / Quality dashboard page |
| LEGACY | `engine/golden_corpus.py`, `engine/golden_corpus_expansion.py`, `_expansion_r2`, `_categories`, `_obfuscation_family` — **CONSOLIDATE into runner.py or archive** |
| **Action** | The 5 `golden_corpus*` files in engine/ are historical expansions. Read them, extract any unique fixtures into `backend/corpus/vendor/v1/reports/`, then archive the modules. Runner is single owner going forward. |
| Rationale | 3-way corpus fragmentation makes "did we regress on X?" impossible to answer reliably. |

### 9 · Report Generation

| Slot | Value |
|---|---|
| CANONICAL PDF | `backend/engine/report_pdf.py` |
| CANONICAL text | `backend/services/die/investigation_results.py::render` |
| CANONICAL STIX | `backend/engine/stix_exporter.py` |
| CANONICAL Explain export | `backend/engine/explain_export.py` |
| CANONICAL API | Add `/api/v2/report/{case_id}?format=pdf|text|stix|json` |
| CANONICAL UI consumer | Workspace "Export Report" button (**MISSING TODAY — build this**) |
| **Action** | Do NOT build a new report generator. Wire the existing ones into ONE endpoint with a `format=` query parameter. Add UI button. |
| Rationale | Users have never been able to see that PDF/STIX/explain exports exist. This is a wiring problem, not a build problem. |

### 10 · Recursive Artifact Discovery

| Slot | Value |
|---|---|
| CANONICAL (partial) | `backend/services/recursive_child_pipeline.py` (decoder-level) + `backend/v2/investigation/cre/` (correlation-level) |
| CANONICAL API | Currently invoked internally by chain endpoint — external contract missing |
| CANONICAL tests | Recursive decoder tests exist; **artifact-level recursion tests missing** |
| **Status** | 🟡 **PARTIAL** — decoder recursion works end-to-end (proven with Sophos payload). Artifact recursion (a decoded artifact becoming a new investigation with its own children, with parent-child provenance) is **not wired into the workspace UI flow**. |
| **Action** | Explicit ADR-005 needed to define fixed-point termination, cycle detection beyond content-hash, and parent-child persistence in the Evidence Graph. Do NOT ship features that assume recursive artifact discovery is complete. |
| Rationale | This is a P1 architectural gap. Deferred to a dedicated ADR because it's design-heavy, not implementation-heavy. |

### 11 · Workspace / X-Lab Boundary

| Slot | Value |
|---|---|
| CANONICAL workspace surface | Analyst-facing pages in `frontend/src/pages/WorkspacePage.jsx` + `AnalystWorkspacePage.jsx` — decide ONE |
| CANONICAL X-Lab surface | `backend/services/uil/` + engineering pages (`LabPage.jsx`, `MultiLayerBatteryPage.jsx`, `SemanticMappingInspectorPage.jsx`, `IEDDETracePage.jsx`) |
| CANONICAL boundary rule | Workspace consumes canonical APIs. X-Lab may call raw endpoints for exploration. They MUST NOT share React state or persistence collections. |
| **Action** | ADR-006 needed to formally declare page ownership. 34 frontend pages exist today — probably 10 are legacy/duplicate. |
| Rationale | Every regression in the last 4 forks traces back to workspace and X-Lab drifting into each other. |

### 12 · Attack Mapping / ATT&CK

| Slot | Value |
|---|---|
| CANONICAL | `backend/v2/investigation/attack_mapping.py` |
| CANONICAL data model | Verify against MITRE STIX schema |
| CANONICAL tests | Verify |
| LEGACY | Inline MITRE references in `services/knowledge/behavior_registry.py`, `services/reasoning/behavior_extractor.py`, and elsewhere — these are references, not mappings, so probably OK to leave alone |
| **Action** | Declare v2 mapping authoritative for T-ID enrichment (name, tactic, description). Downstream references may continue to use T-IDs as strings. |
| Rationale | One source of truth for MITRE metadata prevents drift. |

### 13 · Negative Explainability

| Slot | Value |
|---|---|
| CANONICAL | `backend/v2/investigation/explainability.py` |
| CANONICAL API | Consumed via v2/investigation/pipeline output |
| CANONICAL tests | Verify |
| CANONICAL UI consumer | **MISSING TODAY — build UI panel** |
| **Action** | Ship the UI panel that renders `explainability.py` output. This is a wiring gap, not an implementation gap. |
| Rationale | Explainability is a differentiator ("why is this NOT malicious?"). It exists in code but analysts never see it. |

---

## Freeze List (effective immediately, until ledger sign-off)

**No new work on:**
- `services/uaie/orchestrator.py`
- `services/uaie/planner.py` · `services/uaie/planner_v2.py`
- `services/uaie/evidence.py` (as canonical — use as projection over graph only)
- `services/recipe_planner.py`
- `services/reasoning/behavior_extractor.py`
- `services/correlation_engine.py`
- `services/ice/correlate.py`
- `engine/orchestrator.py`
- `engine/correlation_engine.py`
- `v2/semantic/ps_storyline.py` (attack-story path)
- All 5 `engine/golden_corpus*` legacy files (except `golden_corpus_taxonomy.py`)
- Any new `memory/*.md` file (89 exist; curate first per audit §22)

## Freeze scope

Freeze means:
- ❌ No new features
- ❌ No refactors
- ❌ No bug fixes (unless a P0 security issue and no canonical alternative exists yet)
- ✅ Read-only inspection for parity testing is fine
- ✅ Extracting reusable fixtures into the canonical module is fine (with a git note)

---

## Verification steps required BEFORE this ADR becomes ACCEPTED

Each row marked "Verify" above needs a 5-minute grep check by any agent or human. Specifically:

1. Which router prefix owns `v2/verdict/engine`? (Grep `include_router` in `server.py`.)
2. Does `WorkspacePage.jsx::autoInvestigate` call `v2/investigation/pipeline` today, or the legacy chain endpoint?
3. Are there tests under `tests/` that hit `v2/investigation/attack_story.py` directly?
4. Does the Trajectory canvas project from `engine/evidence_graph` OR from `services/ice/correlate` (BKB projection)?
5. What is the actual `POST /api/decode/chain` handler chain — how deep does it go into which module tree?

These 5 questions determine whether the ADR is ACCEPTED as-is or needs revision. Answering them takes ~30 minutes total.

---

## Migration Order (once ACCEPTED)

Follow strictly, no reordering:

1. **Verdict Engine v2 becomes canonical** — route WorkspacePage verdict fetch to v3 API. Parity test on vendor corpus. Delete legacy verdict emission.
2. **Correlation Reasoning Engine (CRE) becomes canonical** — freeze the other 4. Migrate callers.
3. **v2 Pipeline becomes canonical planner** — freeze 4 legacy planners. `autoInvestigate()` in WorkspacePage.jsx routes through v2 pipeline.
4. **Evidence Graph becomes canonical evidence model** — flat list model deprecated to projection.
5. **Attack Story consolidation** — one module, one narrative shape.
6. **Report Export UI wiring** — expose PDF/STIX/explain via `/api/v2/report`.
7. **Golden Corpus consolidation** — one runner, fixtures unified.
8. **Explainability UI panel** — wire existing module to workspace.
9. **BKB vs IKB decision** — one KB or two with clear separation.
10. **THEN and only then** — WorkspacePage.jsx split into 8-10 files (this is the biggest change and must ride on a stable API surface, not a moving one).

Estimated: 6-10 weeks of focused consolidation work. No new features during this window.

---

## What we will NOT do until migration is complete

- ❌ EVTX / Sysmon / Windows Event Log adapters
- ❌ CrowdStrike / Defender / SentinelOne / Cisco / Wazuh / Elastic connectors
- ❌ Multi-tenant SaaS
- ❌ Autonomous response
- ❌ New ML/LLM verdict path
- ❌ Investigation Playback UI
- ❌ Sub-technique heatmap expansion
- ❌ Any new memory/*.md documents (curate existing first)
- ❌ Any new decode endpoint

---

## Consequences

**Positive:**
- One truth per capability → verdict, correlation, attack story become deterministic in fact, not just in claim
- Every future PR has a clear canonical target
- Fork agents inherit a coherent architecture, not a maze
- Frontend can be split (P0 debt) against a stable API surface

**Negative:**
- 6-10 weeks with no new features. This is an ownership-cost tradeoff.
- Some existing behavior may change during migration (mitigated by parity tests on vendor corpus)
- Legacy code deletion feels wasteful; it is the point.

**Accepted risk:**
- If the vendor corpus doesn't cover a real edge case, migration parity tests will pass but real inputs may regress. Mitigation: the Validation Sprint (audit §22 item 5) should precede migration item #4 (Evidence Graph) and item #7 (corpus consolidation).

---

## Sign-off required from

- **Product owner** (this ADR's decisions on which impl is canonical)
- **Next agent / human developer**: must read this before touching any of the freeze list

---

_End of ADR-004._
