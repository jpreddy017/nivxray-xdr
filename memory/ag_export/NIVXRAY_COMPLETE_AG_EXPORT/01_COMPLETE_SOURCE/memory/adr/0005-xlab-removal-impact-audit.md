# X-Lab Removal Impact Audit (Read-Only)

**Date**: 2026-08-11  
**Author**: E1 (session-7)  
**Trigger**: Owner directive after P0.2 closure — "Before P1.1, prove whether X-Lab itself is unnecessary baggage."  
**Method**: Static import graph + runtime endpoint scan + DB collection inventory + frontend consumer trace.  
**Scope**: **Audit only.** No production code touched.

---

## 1. What "X-Lab" actually is in this codebase — precise scope

The name "X-Lab" is used loosely in the codebase for three unrelated subsystems. This audit disambiguates them and is scoped to the **observational X-Lab surface only** (the one the P0.3 isolation guard names).

| # | Subsystem | Backend | Frontend | DB | Purpose |
|---|---|---|---|---|---|
| **A** | **X-Lab observational surface** (target of this audit) | `routers/timeline_lab.py`, `routers/semantic_lab.py` | `pages/SemanticMappingInspectorPage.jsx`, `nivxforge/lab2/*`, `nivxforge/pages/XLabGraphPopoutPage.jsx` | none | Read-only preview over the schema-1.0 pipeline (Timeline / Attack Chain / Correlation / Full Pipeline / Semantic Mapping) |
| **B** | **Analyst Practice Lab** (NOT X-Lab, do not remove) | `routers/lab.py` | `pages/LabPage.jsx`, `Header.jsx` nav item "Practice Lab" | `lab_attempts`, `lab_stats` | Gamified training / leaderboard using NXGEC gold corpus. User-visible feature. |
| **C** | **`nivxforge/` package** (shared infrastructure, NOT X-Lab, do not remove) | `backend/nivxforge/**` (CIM, learning, investigation pipeline, ingress gate, verdict engine) | `frontend/src/nivxforge/{cim,components,design,hooks}` (Workspace-adjacent CIM UI) | multiple canonical stores | Core canonical investigation infrastructure. Used by `routers/ops.py`, `routers/auto_investigate.py`, `routers/analyst_v2.py`, `routers/analyst_corrections.py`, `routers/learning_engine.py`. |

**The rest of this document concerns only subsystem A.**

---

## 2. Backend inventory — X-Lab observational surface

### 2.1 Routers (removable)

| File | LOC | Endpoints | Consumers |
|---|---:|---|---|
| `backend/routers/timeline_lab.py` | 306 | `POST /api/v2/timeline/preview`, `POST /api/v2/attack-chain/preview`, `POST /api/v2/correlation/preview`, `POST /api/v2/pipeline/preview` | Zero frontend consumers (grep result below) |
| `backend/routers/semantic_lab.py` | 116 | `GET /api/v2/semantic/registry`, `POST /api/v2/semantic/preview` | **`frontend/src/pages/SemanticMappingInspectorPage.jsx`** (only) |

**Registration**: `backend/server.py` lines 348-354. Two 2-line `include_router()` blocks — self-contained.

### 2.2 Backend services (**NOT removable — shared with Workspace**)

Both routers import from `backend/nivxforge/investigation/pipeline/*` (12 modules, 8586 LOC total, 956 KB).

These same modules are ALSO consumed by Workspace-side code:

| Consumer | Where | Module used |
|---|---|---|
| `nivxforge/investigation/summary_composer.py` | Workspace: `routers/ops.py`, `routers/auto_investigate.py` | `pipeline.orchestrator` |
| `nivxforge/investigation/incident_narrative_override.py` | Workspace enrichment path | `pipeline.orchestrator`, `pipeline.narrative_engine` |
| `v2/investigation/report.py` | Workspace report builder | `pipeline.orchestrator`, `pipeline.narrative_engine` |

**Verdict**: **`nivxforge/investigation/pipeline/*` must remain intact.** It is shared infrastructure, not X-Lab-exclusive.

### 2.3 Startup / background jobs / config

- `server.py` imports both routers directly at module scope (lines 97 optional, 348 and 353 mandatory). Removal = 4 lines deleted, 0 conditional imports.
- No scheduled/background jobs reference `timeline_lab` or `semantic_lab`.
- No env variables gate them.
- No middleware, no dependency injection wiring.

### 2.4 Database collections

- `timeline_lab.py`: **zero DB writes/reads.** Pure functions over the pipeline.
- `semantic_lab.py`: **zero DB writes/reads.** Pure functions.

**Storage impact of removal: 0 bytes.** No collection to drop.

### 2.5 Backend tests (must be updated/removed)

| File | LOC | Fate |
|---|---:|---|
| `tests/canonical/api/test_workspace_isolation_guard.py` | 204 | **Keep, but simplify.** Currently uses X-Lab endpoints as the "hostile side" of the isolation test. After removal, the isolation guard becomes a static one — "no `routers.timeline_lab` / `routers.semantic_lab` imports exist anywhere". Same file, tighter contract. |
| `tests/parity/test_verdict_parity_workspace_vs_xlab.py` | 114 | **Rename & keep.** Contrary to the file name, this tests `/api/decode/smart` (X-Lab was one nickname for this route) vs `/api/v2/auto-investigate` (Workspace). It does NOT exercise `timeline_lab` or `semantic_lab`. Rename to `test_verdict_engine_parity.py`. |
| `tests/parity/test_osint_parity_workspace_vs_xlab.py` | 290 | Same as above — rename, keep. Uses `/api/decode/smart`, not the observational surface. |
| `tests/test_lab_narrative.py` | 93 | **Keep.** Tests `routers/lab.py` (Practice Lab), not X-Lab. |

---

## 3. Frontend inventory — X-Lab observational surface

### 3.1 Consumers of X-Lab endpoints (found via grep for `/v2/timeline`, `/v2/attack-chain`, `/v2/correlation`, `/v2/pipeline`, `/v2/semantic`)

**Only one production consumer file exists in the frontend:**

- `frontend/src/pages/SemanticMappingInspectorPage.jsx`  
  - Route: `/lab/semantic-mapping-inspector` (mounted in `App.js` line 184)  
  - Uses `GET /v2/semantic/registry` and `POST /v2/semantic/preview`  
  - Not linked from `Header.jsx` navigation — reachable only by direct URL.

**Zero consumers exist for `/v2/timeline/*`, `/v2/attack-chain/*`, `/v2/correlation/*`, `/v2/pipeline/*`.** These 4 backend endpoints are dead traffic from the frontend's perspective.

### 3.2 Removable frontend files

| Path | Size | Purpose | Consumers |
|---|---:|---|---|
| `frontend/src/pages/SemanticMappingInspectorPage.jsx` | 12 KB | UI for the semantic mapping preview | Only reached by direct URL `/lab/semantic-mapping-inspector` — no nav link |
| `frontend/src/nivxforge/pages/XLabGraphPopoutPage.jsx` | 4 KB | Popped-out X-Lab evidence graph window (uses `xlab.graph.popout.cio` localStorage key, `xlab-graph-popout` BroadcastChannel) | Referenced in `App.js` lazy import (line 82) but **NOT mounted to any `<Route>` — dead code path** |
| `frontend/src/nivxforge/lab2/` (14 files, 384 KB) | 384 KB | Lab2 UI shell (Lab2Shell, Lab2Provider, Lab2InvestigateRenderer, LabV2, LensRegistry, EventBus, SelectionBus, LearningAppliedPanel, VerdictExplanationCard, evidence-graph/, labv2.demo.js, labv2.projector.js, labv2.styles.js, Lab2ToggleButton) | Reached only by `?lab2=1` query flag in `nivxforge/pages/InvestigatePage.jsx` lines 22-24, 93-94, 191 |

### 3.3 Non-removable frontend files (verify carefully)

- `frontend/src/nivxforge/pages/InvestigatePage.jsx` — Workspace-adjacent, imports Lab2. If Lab2 is removed, **must patch** lines 22-24, 93-94, 191 to remove the `?lab2=1` toggle (safe deletion, defaults to legacy renderer).
- `frontend/src/pages/LabPage.jsx` — **Practice Lab** (subsystem B). Keep.
- `frontend/src/components/Header.jsx` line 59 — "Practice Lab" nav item points to `/lab` = subsystem B. Keep.

### 3.4 Storage keys the frontend leaks (bonus finding)

`pages/WorkspacePage.jsx` lines 1030-1044 already sweeps `xlab.*` localStorage keys on CLEAR. Post-removal, these sweep loops become dead code and can be tightened.

---

## 4. Dependency graph — does Workspace touch X-Lab?

Static import trace using the exact patterns from the P0.3 workspace-isolation guard:

```
Workspace production modules (routers/die.py, routers/ops.py, routers/cases.py,
                              routers/decode.py, routers/planner.py, routers/analyze.py,
                              routers/v2.py, services/die/*)

     import  routers.timeline_lab   →  0 matches
     import  routers.semantic_lab   →  0 matches
     from    routers.timeline_lab   →  0 matches
     from    routers.semantic_lab   →  0 matches
```

Runtime dependency (P0.3 isolation runtime guard, already green):

```
100 × POST /api/v2/timeline/preview,
100 × POST /api/v2/attack-chain/preview,
100 × GET  /api/v2/semantic/registry,
100 × POST /api/v2/semantic/preview,
interleaved with
POST /api/die/investigation-results  →  Workspace SSOT bit-identical (verified)
```

**Result: Workspace has ZERO direct or indirect dependency on the X-Lab observational surface.**

---

## 5. Estimated reduction if X-Lab is removed

| Dimension | Before | After | Delta |
|---|---:|---:|---:|
| Backend routers | `timeline_lab.py` 12 KB + `semantic_lab.py` 8 KB | 0 KB | −20 KB source |
| Backend routes registered | 6 X-Lab routes | 0 | −6 routes off `/api` router |
| Backend startup imports | 2 heavy imports pulling in `pipeline.*` at process start | replaced by lazy import inside `summary_composer` / `incident_narrative_override` (already lazy inside those files) | Small process-start speedup; heap saving depends on Python's import caching (marginal — `pipeline/*` stays loaded by Workspace anyway) |
| Frontend bundle | `SemanticMappingInspectorPage.jsx` 12 KB + `XLabGraphPopoutPage.jsx` 4 KB + `nivxforge/lab2/` 384 KB | 0 KB | **−400 KB source** (lazy-loaded chunks, so per-user download impact depends on whether the analyst ever visited `/lab/semantic-mapping-inspector` or clicked the Lab2 toggle) |
| Backend tests | Isolation guard (204 LOC, X-Lab-side) + parity tests (2 files, mis-named) | Isolation guard becomes static-only (~40 LOC) + parity tests renamed | Net −150 LOC test churn |
| DB collections | 0 X-Lab collections | 0 | 0 bytes storage delta |
| Config / env | 0 flags | 0 | 0 delta |

**Headline**: ~20 KB backend code, ~400 KB frontend source, 6 dead routes, 0 storage — a modest but real cleanup.

---

## 6. Regression risks (honest)

**Low-risk removals** (proven zero Workspace impact by P0.3):
- `routers/timeline_lab.py` + all its 4 endpoints — no frontend consumer, no Workspace consumer.
- `nivxforge/pages/XLabGraphPopoutPage.jsx` — lazy-imported but never routed.
- `nivxforge/lab2/*` — only reached by `?lab2=1` flag, no default path.

**Medium-risk removals** (need Workspace regression pass):
- `routers/semantic_lab.py` — **has one live frontend consumer** (`SemanticMappingInspectorPage.jsx`). If the owner uses that inspector page for engineering validation, removal drops that surface. Two options:
  1. Remove backend + frontend inspector together (cleanest).
  2. Keep semantic_lab.py, remove timeline_lab.py only (partial cleanup).

**Not-at-risk** (audit-verified):
- `nivxforge/investigation/pipeline/*` — shared, must stay.
- `nivxforge/investigation/summary_composer.py`, `incident_narrative_override.py`, `v2/investigation/report.py` — Workspace-side consumers of `pipeline.orchestrator` + `pipeline.narrative_engine`. Untouched.
- Analyst Practice Lab (`routers/lab.py` + `LabPage.jsx`) — completely separate.
- Verdict / OSINT parity tests — they never exercised the observational endpoints; safe to rename.

---

## 7. Recommended removal plan (execute only on owner sign-off)

### Phase X-Lab.R1 — Frontend-first (safe, reversible)
1. Delete `frontend/src/nivxforge/pages/XLabGraphPopoutPage.jsx`.
2. Delete `App.js` line 82 lazy import of the popout page.
3. Delete `frontend/src/nivxforge/lab2/` (14 files).
4. In `frontend/src/nivxforge/pages/InvestigatePage.jsx`: remove lines 22-24 (Lab2 imports), lines 93-94 (`isLab2Enabled()` branch), and line 191 (`<Lab2ToggleButton />`).
5. Tighten `frontend/src/pages/WorkspacePage.jsx` lines 1030-1044 to drop the now-obsolete `xlab.*` sweep (or leave as defensive one-time cleanup for existing users' localStorage).

### Phase X-Lab.R2 — Timeline surface (no consumers)
1. Delete `backend/routers/timeline_lab.py`.
2. Delete `backend/server.py` lines 353-354.

### Phase X-Lab.R3 — Semantic surface (has one consumer — owner decision required)
- **Option A (full removal):** Delete `backend/routers/semantic_lab.py`, `backend/server.py` lines 348-349, `frontend/src/pages/SemanticMappingInspectorPage.jsx`, and `App.js` lines 56 + 184.
- **Option B (partial keep):** Leave `semantic_lab.py` in place as a single-consumer inspector tool. Rename to signal its status: `routers/semantic_inspector.py`. Not truly "X-Lab" anymore.

### Phase X-Lab.R4 — Test hygiene
1. Rewrite `tests/canonical/api/test_workspace_isolation_guard.py` to a pure static-import guard (drop the runtime interleave — nothing to interleave with anymore). Keep the file to prevent regression re-introduction.
2. Rename `tests/parity/test_verdict_parity_workspace_vs_xlab.py` → `test_verdict_engine_parity.py` and `tests/parity/test_osint_parity_workspace_vs_xlab.py` → `test_osint_engine_parity.py`. Update in-file docstrings.
3. Leave `tests/test_lab_narrative.py` untouched (Practice Lab).

---

## 8. Workspace regression suite required after removal

Minimum set to run before declaring the removal complete:

1. `cd /app/backend && python -m pytest tests/canonical/api/` — P0.2 + P0.3 firewall (46 tests, ~170 s).
2. `cd /app/backend && python -m pytest tests/parity/test_verdict_engine_parity.py tests/parity/test_osint_engine_parity.py` — verdict + OSINT engine parity.
3. `cd /app/backend && python -m pytest tests/test_lab_narrative.py` — Practice Lab still functional.
4. `cd /app/backend && python -m pytest tests/investigation/` — the shared pipeline modules that stay (37 test files).
5. Manual smoke on `/api/die/investigation-results` for CSV + DOCX + URL inputs (frontend Workspace end-to-end).
6. Manual smoke on `/lab` (Practice Lab) — should be untouched.

Success criteria: every test above green; response payloads for `/api/die/investigation-results` byte-identical before/after removal for the CSV + prose fixtures used by P0.2.

---

## 9. Answer to the owner's core question

> "If we remove X-Lab, will it damage Workspace? If not, we can remove it and save memory/storage."

- **Workspace damage on removal**: **None** for the timeline surface, **none** for the lab2 UI shell, **none** for the popout page.
- **One collateral loss**: the `/lab/semantic-mapping-inspector` engineering-validation page loses its backend. Owner decides A vs B in Phase X-Lab.R3.
- **Storage saving**: 0 bytes DB, ~20 KB backend source, ~400 KB frontend source.
- **Memory saving**: marginal — `nivxforge/investigation/pipeline/*` stays loaded because Workspace imports it too.
- **Real benefit**: 6 dead API routes removed, one whole isolation-guard runtime path retired, and an unclear "X-Lab" naming that appears in 5 test files and 3 subsystems (A, B, C confusion) gets resolved.

**Verdict**: **X-Lab observational surface is safely removable.** Recommend proceeding with Phase X-Lab.R1 + R2 unconditionally, and R3 Option A if the owner does not use the semantic inspector.

**STOP** — awaiting owner sign-off before any deletion.
