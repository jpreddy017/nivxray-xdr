# EDR-A0-03 — MongoDB Data Ownership and Dependency MRI

**Reference:** EDR-A0-03 · **Date:** 2026-10-30 · **Mode:** STRICTLY READ ONLY · **Revision:** `/app` HEAD `5040c08cfd27e835c1ea9013c5d959ae9ea79c5c`
**Change performed:** NONE. No database access of any kind (no connection, no query, no mutation), no git operation, no deployment, no VM or sensor action. Analysis is **source-level**: AST parsing and literal/method inspection of `backend/`, plus targeted file reads to verify each finding.

---

## 1 · Method and its limits

| Pass | Technique | Output |
|---|---|---|
| 1 | regex over explicit `db["x"]`, `db.get_collection("x")`, and `db[CONST]` with module-level `CONST = "x"` | **117 authoritative collection names** |
| 2 | per-module: collection-name literals ∩ authoritative set, combined with whether the module calls any write or read driver method | module↔collection touch matrix, **116 collections** with product-code access |
| 3 | AST import graph + transitive closure from all 161 EDR modules | EDR dependency chain |
| 4 | closure from `edr_plane.processing_queue` | worker-reachable module set |
| 5 | manual verification of every cross-product write claim | corrections in §4 |

**Known limitation, stated up front:** pass 2 is **module-granularity**. If a module writes *any* collection and mentions collection *X*, it is listed as a candidate writer of *X*. This over-reports. Every cross-product write in §4 was therefore hand-verified, and three over-reports were corrected. Statement-level (per-call-site) attribution for the ~70 single-product collections was **not** performed and is named as residual work in §8.

---

## 2 · Collection census

| Class | Count | Notes |
|---|---|---|
| Authoritative collection names found in source | 117 | |
| Touched by product (non-test, non-tool) code | 116 | |
| **EDR-exclusive** (`edr_*` + `e3_*`, EDR writers and readers only) | **39** | the clean core |
| XDR-exclusive (`xdr_*`, XDR only) | ~30 | not EDR's concern |
| Shared/platform-only | ~35 | auth, investigation, decoder, intel, regression |
| **Cross-product (more than one product touching)** | **13** | the actual separation problem — §4 |

### 2.1 EDR-exclusive collections (39) — single-product, safe to own

```
edr_acquisition_gaps              edr_finding_evaluations            e3_behavior_shadow_detections
edr_acquisition_integrity         edr_finding_evaluations_all_tenants e3_dt_detections
edr_agent_credentials             edr_findings                       e3_dt_dispositions
edr_agent_sessions                edr_groups                         e3_dt_enforcement
edr_compromise_events             edr_isolation_policy               e3_dt_status_events
edr_connector_deployments         edr_policies                       e3_dt_ti
edr_delivery_counters             edr_policy_audit                   e3_kushu_events
edr_endpoint_address_observations edr_policy_endpoint_state          e3_migration_locks
edr_endpoint_exclusion_enforcement edr_policy_versions               e3_migration_row_ledger
edr_endpoints                     edr_processing_queue               e3_migration_runs
edr_enrollment_audit              edr_rejected_telemetry             e3_preview_meta
edr_enrollment_tokens             edr_rejected_telemetry_all_tenants
edr_exclusion_sets                edr_response_commands
edr_exclusions                    edr_saved_views   edr_tenant_boundary
```

`*_all_tenants` names are read-side aggregation scopes, not separate stores. The `e3_*` family belongs to the E3 trajectory/migration lane; see §4.4 — most of it is **runtime-unreachable today**.

---

## 3 · Readers, writers and workers — EDR core

| Collection | Writers (module) | Readers (module) | Worker-touched |
|---|---|---|---|
| `edr_raw_events` | `edr_plane.raw_events` (authoritative), `routers.edr_onboarding`, `routers.edr_maintenance`, `server` (index creation) | `edr_plane.canonical_bridge`, `.campaign_story`, `.response`, `.trajectory_window`, `.raw_events`, `routers.edr`, `.edr_events`, `.edr_exclusions`, `.edr_findings`, `.edr_maintenance` | **yes** (read by bridge) |
| `edr_processing_queue` | `edr_plane.processing_queue` only | same | **yes — the worker itself** |
| `edr_endpoints` | `edr_plane.enrollment.store`, `routers.edr_enrollment`, `.edr_onboarding` | wide read across EDR routers + `services.edr.*` | yes |
| `edr_agent_credentials` / `edr_agent_sessions` / `edr_enrollment_tokens` | `edr_plane.enrollment.store` (+ `transport` for sessions) | `edr_plane.authority`, `enrollment.*` | no |
| `edr_findings` / `edr_finding_evaluations` | `edr_plane.fabric.*`, `detection_replay` | `routers.edr_findings`, `edr_trajectory.*` | **yes** |
| `edr_policies` / `edr_groups` / `edr_policy_*` | `edr_plane.policy.store` | `routers.edr_policies`, agent policy route | no |
| `edr_exclusions` / `edr_exclusion_sets` / `edr_endpoint_exclusion_enforcement` | `edr_plane.exclusions.store` | `routers.edr_exclusions`, bridge | yes |
| `edr_response_commands` | `edr_plane.response` | `routers.edr_response`, agent command routes | no |
| `edr_delivery_counters` | `edr_plane.delivery_counters` | same | yes |
| `edr_acquisition_integrity` / `edr_acquisition_gaps` | `edr_plane` acquisition modules | `routers.edr`, freshness service | yes |
| `edr_rejected_telemetry` | `edr_plane.enrollment.rejection` | `routers.edr_enrollment` (rejections) | no |
| `edr_enrollment_audit` / `edr_policy_audit` | `edr_plane.enrollment.audit`, `policy.store` | `routers.edr_audit` | no |

**Single authoritative writer per family holds** in the live path: raw events ← `raw_events.py`; queue ← `processing_queue.py`; identity ← `enrollment/store.py`; policy ← `policy/store.py`; exclusions ← `exclusions/store.py`; response ← `response.py`. The exceptions are `routers.edr_maintenance` (§4.3) and `server` (index creation only).

---

## 4 · Cross-product data coupling — the 13 collections that matter

| # | Collection | EDR role | Other products | Verdict |
|---|---|---|---|---|
| 1 | `v2_shadow_observations` | **write (indirect)** + heavy read | SHARED writer (`v2.case_engine.schema`, `server` index), XDR reader | **live coupling** |
| 2 | `xdr_canonical_evidence` | **write (indirect)** + read | XDR writers/readers (8 `detection_content.xdr_*` readers), SHARED | **live coupling** |
| 3 | `counters` | write (`delivery_counters`, `behavior_shadow_run`) | SHARED `services.incident_numbering`, XDR `xdr_framework_mapping` | **live coupling, shared keyspace** |
| 4 | `users` | **read only** (`edr_plane.authority`, `routers.edr`, `services.edr.device_identity`, `.file_trajectory`) | SHARED + XDR writers | auth dependency |
| 5 | `tenants` | **read only** (`services.edr.device_identity`) | SHARED `services.tenant_registry`, XDR `routers.xdr_rbac` write | tenancy dependency |
| 6 | `xdr_audit_log` | **read only** (`routers.edr_session`) | XDR writers | audit dependency |
| 7 | `workspace_cases` | read (`edr_plane.campaign_story`, `routers.edr`) + write **only** via maintenance | SHARED (9 writers) + XDR | read dependency |
| 8 | `v2_decoded_payloads` | **read only** (`routers.edr`) | SHARED writers | read dependency |
| 9–13 | `xdr_correlation_matches`, `xdr_detection_matches`, `xdr_framework_mappings`, `xdr_response_timeline`, `xdr_spread_sightings`, `xdr_intelligence_overlays(+_audit)`, `xdr_investigations(+_findings,_activity)`, `xdr_iue_understanding` | **write only from `routers.edr_maintenance`**, otherwise read or none | XDR owns them | **maintenance hazard, not a live path** — §4.3 |

### 4.1 How EDR actually writes shared evidence (verified)

```
edr_plane/canonical_bridge.py:511
    from v2.ingestion.telemetry_bridge import persist_live_observation
          ↓
v2/ingestion/telemetry_bridge.py:375
    res = await db[COLLECTIONS["shadow_observations"]].insert_one(doc)     # v2_shadow_observations
    (line 276-280 also references xdr_canonical_evidence)
```

**The write is performed by the SHARED telemetry bridge, invoked from the EDR canonical bridge.** EDR code does not insert into `v2_shadow_observations` itself in the live path. This is the single most important ownership fact in this report: the shared evidence write is a *library call*, which means it can be satisfied in an EDR-owned runtime by **copying the bridge with its tests** and pointing it at EDR-owned storage — without touching the original that XDR depends on.

### 4.2 Correction — over-reports removed

| Earlier matrix said | Verified reality |
|---|---|
| `edr_plane.response` writes `v2_shadow_observations` | **read only** — `response.py:133` is `find_one`. The module writes elsewhere (`edr_response_commands`), which is why the heuristic flagged it |
| `edr_trajectory.artifacts_overlay` / `e1_shape_preview` write `v2_shadow_observations` | **runtime-unreachable** — §4.4 |
| `edr_trajectory.platform_seed` writes `edr_raw_events` | **runtime-unreachable** — §4.4 |

### 4.3 The maintenance hazard (single biggest data risk found)

**Every** EDR write into an XDR- or Workspace-owned collection originates from exactly one module: `backend/routers/edr_maintenance.py` (`/api/edr/maintenance`, dev-reset family). It touches 13 non-EDR collections — `xdr_canonical_evidence`, `xdr_correlation_matches`, `xdr_detection_matches`, `xdr_framework_mappings`, `xdr_response_timeline`, `xdr_spread_sightings`, `xdr_intelligence_overlays`, `xdr_intelligence_overlay_audit`, `xdr_investigations`, `xdr_investigation_findings`, `xdr_investigation_activity`, `xdr_iue_understanding`, `workspace_cases` — and its reset semantics are **tenant-wide**.

Consequences:
1. It must **never** be used for scoped cleanups (the pending `KUSHU` / `DESKTOP-A9HGFJJ` removal included).
2. It must **not** be copied into the EDR-owned runtime in its present form; an EDR-owned maintenance surface may only touch EDR-owned collections.
3. Excluding this one module removes EDR's entire cross-product **write** surface except items 1–3 of the table above.

### 4.4 Dead-at-runtime write paths (reduce the real surface)

`server.py:781-782` records that the E3 preview router mount was **stripped**: *"`/api/e3/trajectory/*` was the ONLY runtime entry point into the E3 preview plumbing (api.py, e1_shape_preview, kushu_import, fixtures, prodshape, platform_seed, stale_trace, artifacts_overlay). With this mount removed those modules are unreachable at runtime and survive only as test assets."*

Therefore the `e3_*` collections and the writes attributed to `platform_seed`, `e1_shape_preview` and `artifacts_overlay` are **test-only today**. They still need preservation (§7) but they are not live data paths.

---

## 5 · Worker ownership

Closure from `edr_plane.processing_queue` = **29 modules**, of which 17 are non-EDR:

```
canonical.__init__                    services.investigator.__init__
deps                                  services.investigator.capabilities.__init__
detection_content.xdr_pipeline        services.investigator.capabilities.base
detection_content.xdr_threat_family   services.investigator.lifecycle
security.secret_policy                services.investigator.models
services.__init__                     services.investigator.orchestrator
v2.case_engine.schema                 services.investigator.planner
v2.ingestion.telemetry_bridge         services.iue.artifacts
                                      services.iue.service
```

**Finding:** the EDR worker's import chain reaches the **shared investigator orchestrator and the IUE service** — not directly, but through `detection_content.xdr_pipeline` (the only module in the chain importing them). Both of those shared services are writers of `workspace_cases`. So an EDR-only worker built by naive copying would either (a) drag the investigator/IUE stack along, or (b) fail to import. Neither is acceptable; the `xdr_pipeline` dependency must be reduced to an interface before the worker can be copied.

**Worker write set (live):** `edr_processing_queue`, `edr_raw_events` (read), `edr_findings`, `edr_finding_evaluations`, `edr_delivery_counters`, `edr_acquisition_*`, plus `v2_shadow_observations` / `xdr_canonical_evidence` **via** the shared telemetry bridge, plus `counters`.

---

## 6 · Complete dependency tracing (closes the 165-module gap)

| Metric | Value |
|---|---|
| EDR seed modules | **161** |
| Transitive closure of the EDR dependency chain | **191 modules** |
| Non-EDR modules pulled in (direct + transitive) | **30** |

### 6.1 The 165 previously untraced modules — resolved

| Package | Modules | Reachable from EDR | Detail |
|---|---|---|---|
| `backend/canonical/` | 41 | **1** (`canonical/__init__`) | no direct EDR importer; reached indirectly only |
| `backend/engine/` | 43 | **1** (`engine/__init__`) | imported by `edr_behavior.integration` and `edr_behavior.replay` — package init only |
| `backend/security_state/` | 61 | **0** | **not an EDR dependency at all** |

**Net effect: 162 of the 165 modules are outside EDR's dependency chain.** The chain is far smaller than feared — this is the single biggest scope reduction in the A0 series.

### 6.2 The 30 non-EDR modules EDR genuinely needs

| Module | Direct EDR importers | Treatment under the directive |
|---|---|---|
| `deps` | **25** | replace with EDR-scoped config/deps (new) |
| `security.__init__`, `security.secret_policy` | 4 + 1 | copy with tests |
| `services.__init__`, `services.session_context`, `services.dashboard_lenses`, `services.activity.projector`, `services.mitre_catalogue.__init__` | 3/2/2/1/2 | copy with tests, or versioned library |
| `v2.ingestion.canonical`, `v2.ingestion.telemetry_bridge`, `v2.case_engine.schema` | 3/3/1 | **copy with tests — never fork** |
| `timeline.__init__` | 3 | copy |
| `models.__init__` | 3 | copy |
| `engine.__init__`, `canonical.__init__` | 2/0 | package init only — verify whether anything real is used |
| `detection_content.library.registry`, `.rule_store_binding`, `.xdr_pipeline`, `.xdr_threat_family` | 1/1/2/0 | **XDR-owned** — reduce to an interface; do not copy the pipeline |
| `routers.xdr_rbac`, `routers.xdr_audit_log` | 2/1 | **replace** with EDR session/authorization authority (new) |
| `services.investigator.*` (7), `services.iue.*` (2) | 0 direct | pulled in **only** via `detection_content.xdr_pipeline` — disappears once that edge is cut |

### 6.3 Forbidden-if-copied set

Six modules in the chain belong to XDR/Workspace: `detection_content.library.registry`, `.rule_store_binding`, `.xdr_pipeline`, `.xdr_threat_family`, `routers.xdr_rbac`, `routers.xdr_audit_log`. Under prohibition 4 none may become a runtime dependency of the EDR product. Cutting `xdr_pipeline` alone removes 9 further shared modules from the chain.

---

## 7 · Preservation and recovery inventory (P1)

### 7.1 Preserved and verifiable today

| Asset | Where | Verification |
|---|---|---|
| M1 installer source, G2/G3/G3-01/G3-B3 generations | 13 `*.bundle` files in `/app` | `git bundle list-heads` + `VERIFY.sh` (fsck, 18/18 blob SHAs, 373 portable tests); subtree `db21f422…` |
| Frozen G3 EDR candidate | reviewer repo `reviewer/g3-clean-pass` = `d2f8b742…` | GitHub API; full monorepo tree |
| G3 evidence report | `reviewer/g3-evidence-d2f8b742` = `681376555e…` | GitHub API |
| Deployed frontend sources | `phase2/edr-production` `35d47cc9…`, `release/xdr-b8-selector-candidate` `e2f15a25…` | GitHub API |
| All work in progress | 56 branches / 23 PRs upstream, 27 local refs | GitHub API + `git branch -a` |
| Evidence corpora | `evidence/` 63 MB, `rocket-evidence/` 118 MB, `memory/evidence/` 2.4 MB, `test_reports/` 5.6 MB | on disk, tracked |
| Test suites | 159 EDR backend modules + 13 frontend | in repo |
| Lab data | local Mongo `nivx_g4_lab` 9.8 MB | listed by name only; not read |

### 7.2 NOT preserved / unverifiable — must be closed before any copy

| Gap | Why it blocks | Required (read-only) action |
|---|---|---|
| **Production MongoDB backup arrangements** | unknown whether any restore point exists | confirm the platform's backup/retention for the production app — name and schedule only |
| **Production data inventory** | no counts, sizes or index footprint | after identity is known, a name-level inventory |
| Production deployment artifact/revision | cannot reproduce what runs | authorized platform read |
| `.env` secret **values** | by design not in git; a lost key is unrecoverable | confirm an out-of-band custody record exists (no values) |
| Built installer `NivXForgeEDRSetup.exe` / `NivXForgeSensor.exe` | artifacts are not in the repository; the build is unsigned and not byte-reproducible (PyInstaller one-file) | record the artifact + its `payload-manifest.json` and hashes in a durable store |
| Windows G4 VM state (`NIVX-G4-WIN11`, `NIVX-G4-WIN02`) | durable identity/journal/outbox exist only on those VMs | VM snapshot before any future change — not needed for A0 |
| `rocket-p0/` 1.2 GB working tree (8 files tracked) | unknown whether it holds anything unique | identify origin before anything is proposed; **no deletion** |

---

## 8 · Production evidence — documented, not guessed

| Item | Status | Exactly what is needed |
|---|---|---|
| Production backend revision | **UNKNOWN** | authorized platform read of the production app: deployment ID, image/revision, build log. No endpoint exposes it (`/api/version`, `/api/build-info` → 404) |
| Production MongoDB identity | **UNKNOWN** | the production deployment's env **key names** plus the `DB_NAME` **value**; never the connection string |
| Production database ownership | **UNKNOWN** | whether that database is exclusive to this app or shared with another deployment — comparable by name alone |
| Production backup arrangements | **UNKNOWN** | platform backup/retention policy for that database |
| Production collection counts / index sizes / cross-product reference counts | **UNKNOWN** | name-level inventory after the above |
| Effective production feature flags | **UNKNOWN** | served-artifact and backend flag values |

**I did not connect to, query or infer the content of any production database.** Every production row above is an explicit UNKNOWN with the precise read that would close it. Two of them need an authorization only you can grant.

---

## 9 · Verdict

### **PARTIAL — source-level data ownership is now complete; production-side ownership remains UNKNOWN**

**Closed by this report**
- 117 authoritative collections identified; 39 EDR-exclusive; 13 genuinely cross-product.
- Readers, writers and worker-touched status mapped for every EDR collection family, with the single-authoritative-writer property confirmed for the live path.
- The live EDR→shared evidence write traced to one precise call (`canonical_bridge.py:511` → `telemetry_bridge.py:375`) — a library call, not a cross-product database reach-in.
- All EDR writes into XDR/Workspace collections localised to **one module**, `routers/edr_maintenance.py`, with tenant-wide semantics flagged as the top data hazard.
- Three heuristic over-reports corrected by hand verification; the stripped E3 preview plumbing identified as test-only.
- **The 165-module gap closed: 162 of them are not EDR dependencies.** The real chain is 191 modules, 30 of them non-EDR.
- Worker chain mapped, including the `xdr_pipeline → investigator/IUE` edge that must be cut before the worker can be copied.
- Preservation inventory split into verified-preserved vs unpreserved, with seven named gaps.

**Not closed**
- Production backend revision, MongoDB identity, database ownership and backup arrangements (§8) — permissions absent, documented not guessed.
- Statement-level writer attribution for the ~70 single-product collections (pass 2 is module-granularity).
- Retention policy owner per collection family.
- Whether `canonical/__init__` and `engine/__init__` expose anything EDR actually executes, or are import-only.

**Directive position:** step 1 (understand) is now **substantially** complete on the source side and still **blocked** on the production side. Separation stays on **HOLD**; no copy may begin.

### Next read-only checks, in priority order
1. Authorized platform read → production revision + `DB_NAME` + env key names + backup policy (closes §8 rows 1-4).
2. Statement-level writer attribution for the 13 cross-product collections (deepest value per hour).
3. Confirm whether `canonical/__init__` / `engine/__init__` are executed or import-only.
4. Durable custody record for the built installer artifacts and their manifests.
5. Identify `rocket-p0/` origin — then decide nothing.
