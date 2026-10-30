# EDR-A0-02 — GitHub, Code and Engine Ownership MRI

**Reference:** EDR-A0-02 · **Date:** 2026-10-30 · **Mode:** STRICTLY READ ONLY · **Status:** investigation only, no modification authorization
**Baselines:** `NivXForge_EDR_Architecture_Assessment_v0.1`, `NivXForge_EDR_Deep_Architecture_XRay_v0.2`, `EDR-A0-01_PRODUCTION_TOPOLOGY_EVIDENCE.md`
**Change performed:** NONE. No merge, rebase, branch/PR mutation, dependency install, build, deployment, database access or production test. Only reads: local file/AST inspection, `git ls-files`/`ls-tree`, authenticated **GET-only** GitHub API, and two public `GET`s of deployed `build-info.json`.

**Confidence vocabulary:** `SOURCE-VERIFIED` (read/parsed in this workspace now) · `REPO-VERIFIED` (GitHub API read now) · `DEPLOY-VERIFIED` (live artifact read now) · `INHERITED` (A0-01/baseline, not re-proved) · `UNKNOWN`.

---

## 1 · Exact inspected revisions

| Subject | Value | Confidence |
|---|---|---|
| Workspace checkout | `/app` HEAD `5040c08cfd27e835c1ea9013c5d959ae9ea79c5c`, branch `fix/dt-v3-auth-contract-backend`, 2,567 commits, 13,845 tracked paths | SOURCE-VERIFIED |
| Primary repository | `jpreddy017/nivxray-xdr` — **56 branches, 23 open PRs** (read 2026-10-30) | REPO-VERIFIED |
| `main` | `752a00ffefee` | REPO-VERIFIED |
| EDR frontend production branch | `phase2/edr-production` → `35d47cc96352…` — matches the SHA the baseline attributed to the EDR deployment | REPO-VERIFIED |
| XDR frontend production branch | `release/xdr-b8-selector-candidate` → `e2f15a252630…` — matches the baseline XDR deployment SHA | REPO-VERIFIED |
| Deployed EDR artifact provenance | `GET https://edr.nivxforge.com/build-info.json` → `{"product":"nivxray-edr","product_scope":"edr","api_origin":"https://nivxray.nivxforge.com","phase":"2","cross_product_origins":0,"built_at":"2026-10-28T16:15:44Z"}` | DEPLOY-VERIFIED |
| Deployed XDR artifact provenance | same file on `xdr.nivxforge.com` → `product_scope":"xdr"`, same `api_origin`, `built_at 2026-09-30T17:37:18Z` | DEPLOY-VERIFIED |
| Reviewer repository | `jpreddy017/nivxforge-g3-reviewer-handoff`: `reviewer/g3-clean-pass` → **`d2f8b7429e9018cde7e049e69e7c316277de147f`** (frozen G3 candidate), `reviewer/g3-evidence-d2f8b742` → `681376555e5c…`, `reviewer/g3-known-risk-closure` → `84488ae98…`, `main` → `7aa969dc1…` | REPO-VERIFIED |
| Reviewer repo shape | the tree at `d2f8b742` is a **full monorepo copy** (`backend/`, `apps/`, `frontend/`, `agents/`, `vercel.json`, `.emergent/`, …) — importable as an application, not a patch-only export. It also still carries a `.tok` blob at the root | REPO-VERIFIED |
| M1 installer source | `engineering/m1-g3-integrated` candidate `388bb3d6…` (snapshot bundles in `/app`); G4 corrected candidate `4cfb7cb08a6a` on `engineering/m1-g4-signed-mask-fix-chatgpt-20261030`, open as **draft** PR #27 | SOURCE-VERIFIED + REPO-VERIFIED |
| Backend deployment revision | **UNKNOWN** (carried from A0-01 — no build stamp, no platform read) | UNKNOWN |

**Artifact→SHA linkage caveat:** `build-info.json` records scope, API origin and build time but **no commit SHA**, and the JS bundle carries no stamp. Linking the live EDR artifact to `35d47cc9…` therefore remains INHERITED, not proven.

---

## 2 · Source tree and component ownership inventory

Counts are source files (`.py`/`.js`/`.jsx`/`.ps1`), SOURCE-VERIFIED in this checkout.

### 2.1 EDR-exclusive source

| Component | Path | Files | Notes |
|---|---|---|---|
| Windows sensor + M1 installer | `agents/nivxforge-windows/` | 8 | `nivxforge_sensor.py`, `nivxforge_setup.py`, `nivxforge_journal.py`, installer PS1, Sysmon canary. **`nivxforge_m1.py` is absent here** — it exists only on `engineering/m1-g3-integrated` and in the snapshot bundles |
| Linux sensor | `agents/nivxforge-linux/` | 4 | includes a `.state/outbox.jsonl` working artifact |
| Agent shared helper | `agents/_shared/nivxforge_exclusions.py` | 1 | shared **between the two agents only** |
| EDR ingest/identity/queue plane | `backend/edr_plane/` | 83 | raw events, enrollment, processing queue, policy, fabric, canonical bridge, canonical index contract, detection replay, response |
| EDR trajectory projection | `backend/edr_trajectory/` | 24 | includes `v3_presentation.py` — the module changed by candidate `d2f8b742` |
| EDR behaviour | `backend/edr_behavior/` | 15 | |
| EDR investigation | `backend/edr_investigation/` | 6 | |
| EDR ML | `backend/edr_ml/` | 9 | |
| EDR API routers | `backend/routers/edr*.py` | 17 | `edr.py` + 16 `edr_*.py`; **21** EDR `include_router` calls in `server.py` |
| EDR query services | `backend/services/edr/` | 7 | `endpoint_query`, `endpoint_health`, `device_identity`, `file_trajectory`, `telemetry_freshness`, `observation_narrative` |
| EDR frontend | `apps/nivxray-xdr/src/nivxforge/` | 102 | `pages/`, `components/`, `device/`, `trajectory/` (legacy), `trajectory_amp/`, `trajectory_v3/`; 13 test files in 3 `__tests__` dirs |
| EDR backend tests | `backend/tests/edr/` 113, `edr_trajectory/` 21, `edr_behavior/` 7, `edr_investigation/`+`edr_ml/` 11, root-level `*edr*` 7 | 159 | |

### 2.2 Platform scale for contrast

`backend/` holds **1,512** non-test Python modules; **154** of them (10.2 %) are EDR-owned by the classifier above. `backend/tests/` holds 962 test modules. Frontend: `src/nivxforge/` 102 files vs `src/xdr/` 273.

### 2.3 Naming hazard

`backend/nivxforge/` (106 files: `attribution/`, `cim/`, `engines/`, `learning/`, `investigation/`, `observability/`) is **NOT** the EDR product. It is the NivXRay analysis/attribution engine package, imported by `routers/auto_investigate.py`, `routers/learning_engine.py`, `routers/analyst_corrections.py`, `routers/ops.py`, `server.py`, `services/canonical_evidence_recovery.py`, `v2/investigation/report.py` — i.e. by **Workspace/XDR** code paths. Any extraction keyed on the string `nivxforge` would move the wrong package.

---

## 3 · Import and dependency graph (backend, AST-derived)

Produced by parsing every non-test module under `backend/` and resolving local imports.

### 3.1 EDR → non-EDR (outbound coupling)

```text
backend/edr_* , backend/routers/edr_*
      │
      ├── deps                                  ← 23 EDR modules   [Mongo client, JWT auth, config]
      ├── services.edr.endpoint_query           ←  6   (EDR-owned service, listed for completeness)
      ├── services.edr (package)                ←  4
      ├── v2.ingestion.canonical                ←  3   edr_plane.file_content_acquisition,
      │                                                 file_identity, windows_eventlog
      ├── v2.ingestion.telemetry_bridge         ←  3   edr_plane.canonical_bridge,
      │                                                 edr_trajectory.platform_seed, prodshape
      ├── services (package)                    ←  3
      ├── detection_content.xdr_pipeline        ←  2   edr_plane.canonical_bridge, detection_replay
      ├── routers.xdr_rbac                      ←  2   edr_plane.authority, routers.edr_tenancy
      ├── services.session_context              ←  2   routers.edr, routers.edr_tenancy
      ├── services.dashboard_lenses             ←  2   routers.edr_session, routers.edr_tenancy
      ├── services.mitre_catalogue              ←  2   edr_trajectory.attack, e1_shape_preview
      ├── v2.case_engine.schema                 ←  1   edr_plane.canonical_bridge
      ├── detection_content.library.registry    ←  1   edr_plane.detection_replay
      ├── detection_content.rule_store_binding  ←  1   routers.edr_wave0
      ├── security.secret_policy                ←  1   edr_plane.authority
      ├── services.activity.projector           ←  1   routers.edr
      └── routers.xdr_audit_log                 ←  1   routers.edr_session
```

### 3.2 non-EDR → EDR (inbound coupling)

```text
server                                            → 26 EDR modules (all routers + 10 edr_plane
                                                     modules: processing_queue, raw_events, fabric,
                                                     policy.store, enrollment.store/rejection,
                                                     exclusions.store, response, delivery_counters,
                                                     endpoint_address_observation)
detection_content.telemetry.nivxforge_sensor_dsm  → edr_plane, edr_plane.canonical_bridge
detection_content.xdr_pipeline                    → edr_plane
scripts.wave_b_foundation_measure                 → edr_plane, edr_plane.reputation
tools.apply_34h_target_indexes                    → edr_plane.canonical_index_contract
tools.measure_34d_canonical_index                 → edr_plane.canonical_index_contract
tools.measure_34e_identity_contract               → edr_plane, canonical_index_contract
tools.preflight_34a                               → edr_plane.behavior_evidence_adapter,
                                                     edr_trajectory.production_adapter
tools.preflight_34c                               → edr_trajectory.production_adapter
```

**Reading:** outbound coupling is small and concentrated (`deps`, `v2.ingestion.*`, `detection_content.*`, three `services.*`, two `routers.xdr_*`). Inbound coupling is dominated by `server.py` — the single composition root — plus the XDR detection pipeline and the sensor DSM, which reach **into** `edr_plane`. The latter is the harder direction: XDR detection content currently depends on EDR internals.

### 3.3 Frontend graph

```text
apps/nivxray-xdr/src/nivxforge/**  (102 files, one Vite package shared with XDR)
      ├── @/nivxforge/*            internal (NivXForgeConsole ×17, OpsPrimitives ×10, edrApi ×8 …)
      ├── @/lib/api                ×11   shared axios client  (API_BASE = REACT_APP_BACKEND_URL + /api)
      ├── @/lib/tenant             ×3    shared tenant helper
      ├── @/xdr/nx/apiError        ×10   XDR-owned error model
      ├── @/xdr/lib/pivots         ×1
      ├── @/xdr/lib/mitre/navigatorLayer ×1
      ├── ../../ampModel, ../../EdrSidebar  (3 relative escapes)
      └── react / react-router-dom / lucide-react / vitest

Reverse: 8 XDR files import nivxforge code —
  xdr/components/ActivityDetailsPanel.jsx, StaticAnalysisBridge.jsx, XdrContextBar.jsx,
  xdr/pages/XdrEndpointsPage.jsx, XdrControlCenterPage.jsx, XdrFleetFileTrajectoryPage.jsx,
  XdrEntity360Page.jsx, xdr/assets/AssetsPage.jsx

Routing: App.jsx declares 23 `/edr/*` and 61 `/xdr/*` routes inside ONE <ProductScopeGuard>.
Runtime API coupling: src/nivxforge/edrApi.js calls /xdr/rbac/session-context,
  /xdr/respond/actions, /xdr/respond/health, /xdr/respond/pending-approvals.
```

### 3.4 Build-time graph

One `apps/nivxray-xdr` package, one `vercel.json`, one `scripts/vercel-build.sh`, both Vercel projects sharing the same Root Directory. Product identity comes **only** from `NIVX_PRODUCT_SCOPE` (`xdr` default), with `API_ORIGIN` from `XDR_PROD_API_ORIGIN` (default `https://nivxray.nivxforge.com`) and `NIVX_CROSS_PRODUCT_ORIGINS=0` by default. The script's own comment states that `productScope.js` + `ProductScopeGuard.jsx` are the **only** thing preventing `xdr.nivxforge.com/edr/trajectory` from rendering EDR on the XDR host — a build-time, not infrastructural, product boundary.

---

## 4 · EDR → XDR / Workspace coupling matrix

| # | Coupling | Class | Evidence | Independence impact |
|---|---|---|---|---|
| C1 | `backend/deps.py` — single Motor client, `db` proxy, JWT auth, and 6 mandatory env keys (`MONGO_URL`, `DB_NAME`, `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `EMERGENT_LLM_KEY`) | **Shared runtime** | 23 EDR modules import it | EDR cannot start without platform-wide config, incl. an LLM key it does not need to ingest telemetry |
| C2 | `server.py` is the only composition root (21 EDR + 35 XDR `include_router` calls) and starts EDR workers | **Shared runtime** | AST graph §3.2 | No EDR-only ASGI entrypoint exists today |
| C3 | `v2.ingestion.canonical` / `v2.ingestion.telemetry_bridge` | **Shared source** | 6 EDR modules | Canonicalisation algorithm is platform-owned; EDR consumes it |
| C4 | `detection_content.xdr_pipeline`, `.library.registry`, `.rule_store_binding` | **Shared source + runtime** | `canonical_bridge`, `detection_replay`, `edr_wave0` | Detection content is XDR-owned; EDR detections depend on it |
| C5 | `detection_content.telemetry.nivxforge_sensor_dsm` imports `edr_plane.canonical_bridge` | **Shared runtime (inbound)** | §3.2 | XDR depends on EDR internals — reverse dependency, blocks a clean cut |
| C6 | `routers.xdr_rbac` imported by `edr_plane.authority` and `routers.edr_tenancy` | **Shared runtime** | §3.1 | EDR authorization is derived from XDR RBAC |
| C7 | `services.session_context`, `services.dashboard_lenses`, `services.activity.projector`, `services.mitre_catalogue`, `routers.xdr_audit_log` | **Shared source** | §3.1 | Session/tenant authority, lenses, ATT&CK catalogue and audit sink are platform-owned |
| C8 | Frontend `@/lib/api`, `@/lib/tenant`, `@/xdr/nx/apiError`, `@/xdr/lib/pivots`, `@/xdr/lib/mitre/*` | **Shared source** | §3.3 | EDR UI cannot build without XDR/shared modules |
| C9 | 8 XDR components import EDR UI code | **Shared source (inbound)** | §3.3 | Extracting EDR UI breaks XDR pages unless a package boundary is introduced first |
| C10 | `edrApi.js` → 4 `/xdr/*` runtime endpoints | **Shared runtime** | §3.3 | EDR session context and response approvals are served by XDR routes; an EDR-only backend would 404 them |
| C11 | One frontend package, one `vercel.json`, one build script, scope by env var | **Shared source (build)** | §3.4 | Product boundary is a build flag, not a repository boundary |
| C12 | `security.secret_policy` | **Shared source** | `edr_plane.authority` | Credential policy is platform-owned |
| C13 | `v2.case_engine.schema` | **Shared source** | `canonical_bridge` | Case/evidence schema shared |
| C14 | `backend/nivxforge/` analysis engines | **Workspace/XDR exclusive** (despite the name) | §2.3 | Must **not** be moved with EDR |
| C15 | Cross-product evidence collections (`xdr_canonical_evidence`, `v2_shadow_observations`) written from `edr_plane/canonical_bridge.py` | **Shared runtime (data)** | baseline A07, source | Data-layer coupling; out of scope here, decided in A0-03 |

**Classification tally (source-level):** EDR-exclusive — agents, `edr_plane`, `edr_trajectory`, `edr_behavior`, `edr_investigation`, `edr_ml`, `routers/edr*`, `services/edr`, `src/nivxforge`, EDR tests. XDR-exclusive — `src/xdr`, `routers/xdr_*`, `detection_content/*`. Workspace-exclusive — `backend/nivxforge/*`, `workspace/`, `workspace_recovery/`, decoder/investigation routers. Shared source — `deps`, `v2/*`, `services/*`, `security/*`, `canonical/*`, `@/lib/*`, frontend package. Shared runtime — `server.py`, Mongo client, auth, EDR workers, `/xdr/*` endpoints consumed by the EDR UI. Unknown ownership — `backend/canonical/` (41), `backend/engine/` (43), `backend/security_state/` (81) were not import-traced in this pass.

---

## 5 · Engine and worker ownership matrix

| Engine / worker | Location | Owner | Lifecycle today | Extraction note |
|---|---|---|---|---|
| EDR processing queue workers | `edr_plane/processing_queue.py`, started by `server.py` `start_workers(worker_count=1, reconcile_interval_seconds=60)` | EDR | starts with the **shared** API process | one authoritative writer; two API instances = two writers |
| EDR index creation | `server.py` startup + `edr_plane/canonical_index_contract.py` | EDR | shared startup | index names are environment-sensitive (known preview drift) |
| Canonical bridge | `edr_plane/canonical_bridge.py` | EDR code, **shared outputs** | invoked from queue processing | writes into XDR canonical/shadow collections |
| Detection replay / rule binding | `edr_plane/detection_replay.py`, `edr_wave0.py` | EDR consumer of XDR content | request/worker path | depends on `detection_content` registry |
| Trajectory V3 projection | `edr_trajectory/*`, `routers/edr_trajectory_v3.py`, `routers/edr.py` | EDR | request path | the `d2f8b742` candidate touches `v3_presentation.py` only |
| Behaviour / ML / investigation engines | `edr_behavior/`, `edr_ml/`, `edr_investigation/` | EDR | request path (flagged) | flags not inventoried in this pass |
| NivXRay attribution/learning engines | `backend/nivxforge/` | Workspace/XDR | request path | do not move |
| FileStore retention sweeper, content/bootstrap tasks | `server.py` | Platform | shared startup | would be inherited accidentally by a naive EDR entrypoint |
| Windows/Linux sensor runtime | `agents/*` | EDR | on endpoint | frozen; not to be modified in this track |

---

## 6 · Branch and PR provenance ledger

**56 branches / 23 open PRs** (REPO-VERIFIED 2026-10-30). Classification:

| Class | Items |
|---|---|
| **Deployed** | `phase2/edr-production` `35d47cc9…` (EDR frontend, INHERITED linkage); `release/xdr-b8-selector-candidate` `e2f15a25…` (XDR frontend) |
| **Approved / frozen, not merged** | G3 EDR candidate `d2f8b742` on `reviewer/g3-clean-pass` (separate reviewer repo, **absent from `nivxray-xdr`**); M1 G3 `388bb3d6…` on `engineering/m1-g3-integrated`; G4-corrected installer `4cfb7cb08a6a` (PR #27, draft, "REVIEW ONLY") |
| **Experimental / on hold** | 15 of 23 open PRs carry `[HOLD]`, `[DRAFT]`, `[NO-GO]` or `DRAFT` state: #8, #9 ("NO-GO"), #10–#17, #19–#22, #24, #25, #27 |
| **Overlapping candidate families** | M1 installer: #22 → #24 → #25 → #27 (chained on `engineering/m1-approved-one-installer-20261023`); E3 trajectory: #6, #7 (both onto `feature/e3-edr-engines`); XDR command intelligence: #11 → #12/#13/#14; staging/publish chain: #15 → #16 → #17/#18 |
| **Apparently abandoned** | `conflict_201026_1238`, `conflict_310826_2116` (merge-conflict residue), `engineering/vercel-guard-probe`, `test/gate4-frozen-proof`, `feature/process-graph-falcon`, `feature/unified-xdr-edr-platform-blueprint` — no open PR; **not verified as abandoned**, and nothing was deleted |
| **Local-only branches** | this checkout holds 27 refs including `engineering/m1-g4-preparation`, `engineering/m1-g4-acl-ancestor-fix`, `fix/dt-v3-auth-contract-backend` (current HEAD) — some not present upstream |

**Provenance hazard:** `main` (`752a00ff`), the deployed EDR frontend branch (`35d47cc9`), the deployed XDR branch (`e2f15a25`) and both frozen candidates (`d2f8b742`, `4cfb7cb0`) are five different trees. No branch in `nivxray-xdr` contains the approved G3 EDR candidate.

---

## 7 · Confirmed duplicates vs intentional representations

| Observation | Class | Evidence |
|---|---|---|
| 13,845 tracked paths resolve to **7,821 unique blobs** — 6,024 paths are content-duplicates of another tracked path | **Byte-identical historical copies**; Git deduplicates internally, working tree does not. Top blob appears **787×**, next 236×, 121×, 52× | `git ls-tree -r HEAD` blob-hash frequency |
| `rocket-p0/` — 1.2 GB on disk, a near-complete second copy of the product tree (`rocket-p0/f1/apps`, `/backend`, `/docs`, `/scripts`) — but only **8 files tracked** | **Untracked working-tree bloat.** It is NOT in the repository; it pollutes every recursive grep and inflates the pod disk | `du -sh`, `git ls-files rocket-p0` |
| `rocket-e2e/` + `rocket-evidence/` — 1,318 tracked files | **Tracked evidence corpus**, not application code | `git ls-files` |
| `memory/` ≈144 MiB incl. `NIVXRAY_XDR_SOURCE_EXPORT.html` (52 MB) and 5 identical `.gz` exports | **Byte-identical historical exports** (baseline A17) | baseline + blob frequency |
| Legacy / V3 / E3 trajectory UIs (`trajectory/`, `trajectory_amp/`, `trajectory_v3/`) | **Intentional parallel representations**, not byte-identical; one confirmed wrong entrypoint (`EdrDevicePage.jsx` → legacy renderer) | SOURCE-VERIFIED (baseline A03 reconfirmed) |
| Raw → canonical → shadow observation stages | **Derived representations**, distinct roles | baseline A07 |
| `agents/nivxforge-windows/nivxforge_setup.py` (enterprise) vs `nivxforge_m1.py` (M1, on another branch) | **Active parallel implementations** of installation; both real, different generations | EDR-A0 M1 verification |
| M1 installer PRs #22/#24/#25/#27 | **Overlapping candidates**, one approved (`4cfb7cb0`) | REPO-VERIFIED |
| `backend/nivxforge/` vs the NivXForge EDR product | **Name collision, not duplication** | §2.3 |

Nothing was deleted, merged, pruned or modified.

---

## 8 · Proposed minimum independently buildable EDR source boundary (design analysis only)

**Move as EDR-owned (≈ 420 source files):**
`agents/nivxforge-windows/`, `agents/nivxforge-linux/`, `agents/_shared/`, `backend/edr_plane/`, `backend/edr_trajectory/`, `backend/edr_behavior/`, `backend/edr_investigation/`, `backend/edr_ml/`, `backend/routers/edr*.py`, `backend/services/edr/`, `apps/.../src/nivxforge/`, and the 159 EDR backend test modules + 13 frontend EDR tests.

**Must be newly authored for an EDR runtime (small, additive, not yet authorized):**
1. An **EDR-only ASGI entrypoint** mounting only the 21 EDR routers and owning the EDR worker + index startup (today `server.py` does both for all products).
2. An **EDR-scoped config/deps module** requiring only what EDR needs (`MONGO_URL`, `DB_NAME`, `JWT_SECRET`, auth pepper, TTLs) — removing `EMERGENT_LLM_KEY`/admin-seed coupling **only if** fail-closed auth is preserved.
3. An **EDR session/authorization authority** replacing `routers.xdr_rbac` and the frontend's four `/xdr/*` calls with EDR-owned or versioned cross-product APIs.

**Must be consumed as versioned libraries, never forked:**
`v2.ingestion.canonical`, `v2.ingestion.telemetry_bridge`, `v2.case_engine.schema`, `services.mitre_catalogue`, `services.session_context`, `services.activity.projector`, `security.secret_policy`, and the `detection_content` registry/rule binding.

**Must stay behind and be de-coupled first (reverse dependencies):**
`detection_content.telemetry.nivxforge_sensor_dsm` and `detection_content.xdr_pipeline` import `edr_plane`; 8 XDR UI files import `src/nivxforge`. These break XDR if EDR leaves without an interface.

**Explicitly excluded:** `backend/nivxforge/`, `workspace*/`, `decoders/`, `reasoning/`, `training/`, `src/xdr/`, `routers/xdr_*`, and all evidence/export corpora.

**Frontend boundary:** the minimum honest cut is to make `src/nivxforge` a package with explicit dependencies on `@/lib/api`, `@/lib/tenant` and three `@/xdr/*` modules, then invert those three — not to copy the Vite app.

---

## 9 · Risks, unknowns and required follow-up evidence

| # | Risk / unknown | Why it matters | Next read-only check |
|---|---|---|---|
| R1 | Deployed backend revision still UNKNOWN (A0-01) | The whole ownership map is source-side; it cannot be asserted of production | authorized platform read of the production deployment revision |
| R2 | Reverse dependencies (C5, C9) | An EDR extraction silently breaks XDR | enumerate every symbol those 10 call sites use |
| R3 | `backend/canonical/`, `engine/`, `security_state/` (165 files) not import-traced | Could hide further shared-runtime coupling | extend the AST pass to these packages |
| R4 | Feature flags (`NIVX_FLAG_*`, `VITE_E3_DT_V3`) not inventoried | Code presence ≠ active path | read flag defaults in source and `build-info.json`; deployed flag values remain unverified |
| R5 | Candidate `d2f8b742` is absent from `nivxray-xdr` | Release provenance split across two repositories | keep the branch/SHA ledger as the single source of truth |
| R6 | `.tok` blob at the root of the reviewer repo tree | Credential artifact in a repo proposed for import | separate, scoped credential-hygiene task (baseline already lists rotation debt) |
| R7 | `rocket-p0/` 1.2 GB untracked | Distorts every recursive scan and consumes pod disk | confirm origin/ownership before anything is proposed; **no deletion in this track** |
| R8 | 6,024 duplicate tracked paths | Inflates any repository-split estimate | per-path dedup report with retention owner, read-only |
| R9 | Collection-level reader/writer ownership not mapped | Prerequisite for any data boundary | A0-03 scope — deliberately not started |

---

## 10 · A0-02 verdict

### **PARTIAL**

**Closed:** inspected revisions pinned across both repositories and the live artifacts (incl. the newly read `build-info.json` provenance); EDR-owned module inventory with counts; AST-derived two-directional backend import graph; frontend import/runtime/build-time graph; a 15-row coupling matrix with explicit classes; engine and worker ownership; a 56-branch / 23-PR provenance ledger separating deployed, approved, experimental and apparently-abandoned candidates; duplicate-vs-intentional classification backed by blob-identity counts; and a minimum EDR source boundary naming the three components that must be newly authored and the reverse dependencies that must be inverted first.

**Not closed:** the deployed backend revision (R1, inherited from A0-01); three backend packages not yet import-traced (R3); feature-flag effectiveness (R4); symbol-level detail of the reverse dependencies (R2); and collection-level data ownership, which belongs to A0-03 and was **not** started.

No repository mutation, merge, rebase, branch or PR change, dependency install, build, deployment, database access or production test occurred. Stopping here as instructed.
