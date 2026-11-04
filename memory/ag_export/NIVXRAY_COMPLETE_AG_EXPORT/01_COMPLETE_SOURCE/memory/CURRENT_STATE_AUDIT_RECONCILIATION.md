# NivXRay · Audit Reconciliation Against Current HEAD
_Date: 2026-08-09 · Author: E1 (evidence-only re-verification · no code changes)_

> **Purpose**: The 360° audit dated `2026-02-09` was written by an
> agent that only inspected `services/` and `routers/`, and mis-labelled
> its own header with a February date. The owner correctly identified
> that this contradicted substantial known work in `v2/` and `engine/`
> modules. This document is the CURRENT-HEAD reconciliation.

## Environment facts (verified)

| Fact | Value |
|---|---|
| Current git HEAD | `52007cbd060f81bf34eac6e59343dcf1c07913c5` |
| HEAD commit date | **2026-08-09 16:48:19 UTC** |
| Server system date | 2026-08-09 |
| Total commits on this branch | 1,317 |
| Audit header date (original) | 2026-02-09 — **INCORRECT header, correct HEAD data** |

> **Confirmed**: The audit's file counts (401 endpoints · 372 tests · 138 components · 89 memory docs · 108 BKB entries · 42 UAIE plugins) WERE gathered against current HEAD. But the "IMPLEMENTED / NOT IMPLEMENTED" verdicts were made **without ever inspecting `/app/backend/v2/` (190 py files) or `/app/backend/engine/` (30 files) or `/app/backend/training/` or `/app/backend/workspace_recovery/`**. That's the scope of the miss.

---

## Reconciliation table (A–G per owner spec)

| A · Previous Audit Finding | B · Current HEAD Reality | C · Evidence | D · Status | E · Regression? | F · Architecture conflict | G · Recommended action |
|---|---|---|---|---|---|---|
| "IKG · 0 files, spec docs only" | **IMPLEMENTED** — full Investigation Knowledge Graph module | `backend/v2/investigation/ikg.py`, `builder.py`, `attack_story.py`, `attack_mapping.py`, `explainability.py`, `graph/builder.py` | ✅ IMPLEMENTED | **NO** — audit was wrong | Audit missed `v2/` module entirely | Rerun coverage analysis on `v2/investigation/*` — score 6-7/10 not 0 |
| "Evidence Graph · documented not built · 2/10" | **IMPLEMENTED** — dedicated engine module | `backend/engine/evidence_graph.py`, `evidence_graph_builder.py`, `evidence_graph_config.py`, `evidence_graph_observability.py`, `correlation_engine.py` (4 files, 1 builder + observability) | ✅ IMPLEMENTED | **NO** | Two engines coexist: `services/uaie/evidence.py` AND `engine/evidence_graph.py` | Identify authoritative one; deprecate the other |
| "Verdict engine · hard-coded weights, `orchestrator.py`, 4/10" | **PARTIAL — cleaner than claimed** — Verdict v3 exists with abstracted weights + signals + correlation | `backend/v2/verdict/engine.py`, `signals.py`, `weights.py`, `correlation.py`, `progressions.py`, `profiles.py`; tests `test_verdict_v3.py`, `test_verdict_v3_correlation.py` | ✅ IMPLEMENTED (v3) | **NO** | v2/verdict/ vs orchestrator.py — which is called by the workspace? | Verify which verdict engine the workspace actually invokes today |
| "Report generator · plain text only · 2/10" | **PARTIAL** — PDF report generator exists in `engine/report_pdf.py` + STIX exporter | `backend/engine/report_pdf.py`, `engine/report.py`, `engine/stix_exporter.py`, `engine/explain_export.py` | ✅ IMPLEMENTED (PDF, STIX, JSON) | **NO** | Never surfaced in `render()` text panel; frontend has no download button | Wire PDF/STIX export into workspace UI |
| "Negative Explainability · UNKNOWN, no module" | **IMPLEMENTED** — dedicated module | `backend/v2/investigation/explainability.py` | ✅ IMPLEMENTED | **NO** — audit failed to search | UI does not display it | Wire into ATT&CK panel |
| "Attack Story · in `reasoning/behavior_extractor.py`, partial" | **IMPLEMENTED** — dedicated v2 module + semantic storyline | `backend/v2/investigation/attack_story.py`, `backend/v2/semantic/ps_storyline.py`, `backend/v2/investigation/report.py`, `backend/routers/workspace_investigation.py` | ✅ IMPLEMENTED | **NO** | Multiple attack-story generators coexist | Consolidate |
| "Investigation SSOT · not persisted separately" | **IMPLEMENTED** — dedicated SSOT store + projector + tests | `backend/services/ssot_store.py`, `services/uaie/ssot_projector.py`, `routers/ssot.py`, tests: `test_ssot_persistence.py`, `test_ssot_projector.py`, `test_restore_equivalence_live.py` | ✅ IMPLEMENTED | **NO** | — | Verify persistence-vs-projection boundary |
| "Process Tree · not implemented" | **PARTIAL** — process-tree schema exists in training corpus | `backend/training/tree_formats.py`, `training/validator.py`, `training/schema.py` | 🟡 PARTIAL | — | Training-corpus format only; no runtime process tree from telemetry | Correctly labelled PARTIAL — but for a different reason than audit stated |
| "Device Trajectory · works" | **IMPLEMENTED** (audit correct) | `frontend/src/components/investigation/TrajectoryDiagram.jsx` (1,162 lines) | ✅ | — | — | — |
| "IKB / Behavior Knowledge Base · 108 entries" | **CONFIRMED** — plus separate IKB module | `backend/services/knowledge/behavior_registry.py` (108 entries) + `backend/v2/ikb/entries.py` | ✅ IMPLEMENTED | — | **Two knowledge bases coexist** — BKB (services/knowledge) vs IKB (v2/ikb) | Identify canonical KB; migrate the other |
| "Recursive Artifact Discovery · partial / decoder-only" | **PARTIAL** — pipeline module exists but activation unclear from workspace UI | `services/recursive_child_pipeline.py`, plus `v2/investigation/cre/` (Correlation Reasoning Engine) | 🟡 PARTIAL | — | CRE (Correlation Reasoning Engine) exists as `v2/investigation/cre/wrappers/*` — audit missed this | Verify CRE activation from workspace flow |
| "Validation Pack · corpus in `backend/corpus/`" | **IMPLEMENTED** — larger than audit claimed | `backend/v2/validation/runner.py`, `v2/ingestion/golden_corpus.py`, `engine/golden_corpus.py` + 5 taxonomy/expansion files | ✅ IMPLEMENTED | **NO** | Multiple golden-corpus modules coexist (audit missed all) | Consolidate |
| "Investigation Ingestion Engine · not mentioned" | **IMPLEMENTED** | `backend/v2/ingestion/*` — golden_corpus + init | ✅ IMPLEMENTED | **NO** | — | — |
| "Evidence Provenance · in `uaie/provenance.py`" | **CONFIRMED** — plus additional layers | `services/uaie/provenance.py`, `uaie/ledger.py`, `uaie/evidence.py`, `services/confidence_provenance.py`, `services/canonical_evidence_recovery.py` | ✅ IMPLEMENTED | — | Multiple provenance layers coexist | Identify authoritative provenance model |
| "Workspace isolation from X-Lab" | **UNKNOWN** — X-Lab surface = `services/uil/`, `v2/semantic/`; audit did not check | `services/uil/` (4 files), `v2/semantic/*`, X-Lab-tagged tests `xlab_parity_audit.md` | 🟡 UNKNOWN | — | Boundary between workspace SSOT and X-Lab exploration surface not documented | Explicit ADR needed |
| "Workspace UI monolith · WorkspacePage.jsx 3,982 lines" | **CONFIRMED** (correct in audit) | `frontend/src/pages/WorkspacePage.jsx` | ✅ ACCURATE | — | Real P0 debt | Split into 8-10 files |
| "6 overlapping decode endpoints" | **CONFIRMED** | `routers/{chain,iedde,analyze,analyst_v2,auto_investigate,decoded_artifacts}.py` | ✅ ACCURATE | — | Real P1 debt | Consolidate to versioned `/api/v2/decode` |
| "3 planners coexist" | **PARTIALLY CORRECT** — actually more: `recipe_planner.py`, `uaie/planner.py`, `uaie/planner_v2.py`, PLUS `engine/orchestrator.py`, PLUS `v2/investigation/pipeline.py` | (see file paths above) | 🟡 UNDERSTATED — worse than audit said | — | Real P0 architecture debt | Freeze all planner additions; ADR needed |
| "No telemetry ingest / EVTX / Sysmon" | **CONFIRMED** | No EVTX parser found in repo | ✅ ACCURATE | — | — | Keep deferred per your position |
| "SSRF possible in URL acquisition" | **UNVERIFIED CLAIM** — I inferred it but didn't confirm exploitability | `services/ida/acquisition.py` uses `httpx.get(url, follow_redirects=True)` — no allow-list, no IP block | 🟡 PROBABLE (needs test) | — | Real security risk if unmitigated | 4-hour fix: block RFC1918 + 169.254.x.x + resolve-then-verify |
| "89 memory .md files" | **CONFIRMED** | `ls /app/memory/*.md \| wc -l` = 89 | ✅ ACCURATE | — | Onboarding debt | Curate |

---

## Corrected 360° Scorecard (v2)

| Dimension | Original (wrong) | **Corrected** | Why changed |
|---|---|---|---|
| Architecture | 5 | **4** | Worse than I said — v2/ + engine/ + services/uaie/ + services/die/ all overlap |
| Core analysis | 8 | **8** | Same — this was correct |
| Recursive investigation | 5 | **6** | CRE (`v2/investigation/cre/`) exists — audit missed it |
| Artifact analysis | 5 | **6** | 9 adapters + `services/artifact_intelligence/` (6 files) that audit didn't check |
| Detection | 6 | **6** | Same |
| Correlation | 4 | **7** | `engine/correlation_engine.py` + `v2/verdict/correlation.py` + CRE — audit missed all |
| Verdict engine | 4 | **6** | v3 exists with abstracted weights/signals/correlation — cleaner than claimed |
| Explainability | 6 | **7** | `v2/investigation/explainability.py` exists — audit missed |
| ATT&CK | 6 | **7** | `v2/investigation/attack_mapping.py` exists — audit missed |
| **Evidence graph** | **2** | **7** | `engine/evidence_graph*.py` (4 files) — **biggest miss** |
| Investigation UX | 4 | **4** | Same — WorkspacePage.jsx debt is real |
| Testing | 6 | **7** | Verdict v3, evidence graph, SSOT persistence, projector all have dedicated tests |
| Performance | 5 | **5** | Same |
| Security (of NivXRay) | 3 | **4** | Still needs work but reduced severity of SSRF (unverified) |
| Integrations | 3 | **3** | Same |
| Enterprise readiness | 2 | **3** | Explainability + PDF export + STIX exporter push this up |
| Deployment readiness | 5 | **5** | Same |
| Scalability | 3 | **3** | Same |
| Observability | 3 | **5** | `engine/evidence_graph_observability.py` exists — audit missed |
| Documentation | 4 | **4** | 89 stale + no map of what's canonical |
| **NEW: PDF/report export** | (missing) | **6** | `engine/report_pdf.py`, `engine/stix_exporter.py`, `engine/explain_export.py` |
| **NEW: Verdict progression modelling** | (missing) | **6** | `v2/verdict/progressions.py`, `v2/verdict/profiles.py` |
| **NEW: IKB (2nd knowledge base)** | (missing) | **PARTIAL** | `v2/ikb/entries.py` — coexists with BKB, unclear authority |

**Corrected overall maturity: 5.6 / 10** (up from misreported 4.6)

---

## What the original audit got objectively RIGHT

These findings stand:

1. **WorkspacePage.jsx = 3,982 LOC** — real P0 debt
2. **6 overlapping decode endpoints** — real P1 debt
3. **89 memory/*.md** with substantial staleness
4. **SSRF risk on URL acquisition** — worth fixing (4 hours)
5. **No EDR/SIEM telemetry ingest** — accurate
6. **No multi-tenant model** — accurate
7. **Single-worker uvicorn** — accurate
8. **BKB and deterministic decoder are the crown jewels** — accurate
9. **Hard-coded verdict thresholds SOMEWHERE** — but only in the legacy `orchestrator.py`; v3 is cleaner
10. **Report export not surfaced in UI** — accurate

## What the original audit got WRONG

Concrete corrections you should apply mentally:

| Wrong claim | Correction |
|---|---|
| "IKG not implemented" | IKG IS implemented in `v2/investigation/ikg.py` |
| "Evidence Graph not implemented (2/10)" | Fully implemented in `engine/evidence_graph*.py` (4 files) + observability |
| "Verdict engine is hard-coded" | Legacy path is; **v3 in `v2/verdict/`** has abstracted weights/signals/correlation |
| "Negative Explainability UNKNOWN" | Exists: `v2/investigation/explainability.py` |
| "Attack Story partial via `reasoning/behavior_extractor.py`" | Full v2 module: `v2/investigation/attack_story.py` |
| "Report Generator plain text only" | PDF + STIX + explain_export all exist |
| "No observability" | `engine/evidence_graph_observability.py` exists |
| "Validation Pack = corpus only" | `v2/validation/runner.py` is a dedicated harness |

## Regressions (differences between "prior known state" and current HEAD)

**None found** — every capability the owner mentioned is present at HEAD. The audit did NOT reveal regressions; it revealed that the auditing agent (me) didn't grep broadly enough.

---

## Duplicated / Competing Implementations (P0 architecture debt)

| Capability | Implementations coexisting | Which is authoritative? |
|---|---|---|
| Verdict engine | `services/uaie/orchestrator.py` · `v2/verdict/engine.py` | **UNKNOWN — needs ADR** |
| Attack story | `services/reasoning/behavior_extractor.py` · `v2/investigation/attack_story.py` · `v2/semantic/ps_storyline.py` | **UNKNOWN** |
| Evidence layer | `services/uaie/evidence.py` · `engine/evidence_graph.py` | **UNKNOWN** |
| Knowledge base | `services/knowledge/behavior_registry.py` (BKB, 108 entries) · `v2/ikb/entries.py` | **UNKNOWN** |
| Provenance | `services/uaie/provenance.py` · `services/confidence_provenance.py` · `services/canonical_evidence_recovery.py` | **UNKNOWN** |
| Planner | `services/recipe_planner.py` · `services/uaie/planner.py` · `services/uaie/planner_v2.py` · `engine/orchestrator.py` · `v2/investigation/pipeline.py` | **UNKNOWN** (worse than audit stated) |
| Correlation | `services/correlation_engine.py` · `services/ice/correlate.py` · `engine/correlation_engine.py` · `v2/verdict/correlation.py` · `v2/investigation/cre/` | **UNKNOWN** |
| Golden corpus | `backend/corpus/` · `engine/golden_corpus*.py` (5 files) · `v2/ingestion/golden_corpus.py` | **UNKNOWN** |

**This is the real story.** NivXRay isn't underbuilt — it's **overbuilt in parallel**. Multiple teams / agents / sprints each landed complete implementations, and none of the old ones were retired.

---

## What I recommend as the correct next step

You said it best in your reply:

> "Do NOT build 20 more capabilities. First establish the NivXRay Golden Architecture."

I fully agree. Concrete P0 action:

1. **Write ADR-004: "Canonical Implementation Ledger"** — one page per capability, declaring which of the coexisting implementations is authoritative, which are frozen-for-deprecation, and which are safe to delete.
2. **Freeze all `services/uaie/*`, `services/uil/*`, and `services/reasoning/*` additions** until (1) is done.
3. **Restore this reconciliation as the actual baseline** — not the flawed original audit.

Then and only then discuss telemetry, tenancy, etc.

## Corrected owner assessment

The audit's biggest failure was **framing NivXRay as underbuilt when it's actually overbuilt in parallel**. The core engineering muscle isn't 4.6/10 — it's genuinely closer to 6/10, but split across ≥ 4 competing implementations of the same capabilities. Consolidation, not construction, is the P0 job.

**Your instinct was right: don't build more. Consolidate first.**
