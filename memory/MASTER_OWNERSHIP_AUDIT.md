# MASTER OWNERSHIP + WIRING AUDIT
## MATRIX 2 (ownership + wiring) · MATRIX 3 (missing / blocked) · ORPHAN WIRING WORKLIST

**Phase: AUDIT ONLY. No wiring, no route changes, no engine changes, no UI
changes, no deletions were performed.** The only files created are this
document, `/app/memory/MASTER_PARITY_MATRIX.md`, and three read-only audit
scripts under `/app/scripts/master_audit_*.py`.

Executed under `/app/memory/MASTER_GATE.md` and the owner's audit rules of
2026-06 (depth **2C**, legacy scope **2A**, runtime probing **YES / GET
only**, deliverables **B — all three matrices in one pass, then STOP**).

---

## 0 · METHOD — HOW "WIRED" WAS DECIDED

The gate forbids inferring wiring from filename, folder name, component
existence, API definition, test existence, seed data, mock data or
documentation. Every wiring claim below rests on the five-part test the
owner specified:

```
CODE EXISTS  +  ROUTER REGISTERED  +  APP RUNNING
             +  REAL UI/PRODUCT ROUTE  +  HTTP/API REACHABILITY
```

Evidence sources, all captured in this session:

| # | Source | Artefact | What it proves |
|---|---|---|---|
| E1 | Live OpenAPI of the running backend (`/api/openapi.json`, **775 registered routes**) | `/tmp/openapi.json` | router + app registration |
| E2 | Read-only runtime probe, **117 authenticated GETs** as `admin@nivxray.com` | `/app/memory/master_audit_runtime_probe.json` · `scripts/master_audit_runtime_probe.py` | HTTP reachability + real-data vs honest-empty |
| E3 | Frontend→backend reconciliation over both product shells (**189 `/api` literals**, 154 matched a live route, 35 did not) | `/app/memory/master_audit_frontend_wiring.json` · `scripts/master_audit_frontend_wiring.py` | whether a product surface actually calls the capability |
| E4 | `supervisorctl status` + `ss -ltnp` | in-session | which processes are actually running |
| E5 | Direct MongoDB collection counts (read-only) | in-session | whether a wired capability has real data behind it |
| E6 | React route table + rail definition + one authenticated screenshot per product | in-session | real UI route reachability |

**No POST/PUT/PATCH/DELETE was executed anywhere.** No response action, no
sync, no rotation, no drain was triggered.

### Status vocabulary (only these, per the gate)
`REAL_RUNTIME_VERIFIED` · `END_TO_END_VALIDATED` ·
`IMPLEMENTED_NOT_RUNTIME_VERIFIED` · `REFERENCE_CAPTURE_REQUIRED` ·
`BLOCKED` · `NOT_IMPLEMENTED` · plus `LEGACY-DUPLICATE` / `ORPHAN` in the
matrices.

### Legacy vs Orphan — the distinction the owner mandated
| Class | Meaning | Consequence |
|---|---|---|
| **LEGACY-DUPLICATE** | superseded / out-of-product lineage | do **not** wire |
| **ORPHAN** | current, valid implementation, not connected to the product runtime | **candidate to wire — this is the value the audit exists to find** |
| **MISSING** | no implementation exists | build only after this audit is approved |
| **BLOCKED** | implemented or designed, external dependency required | state the dependency, never fabricate it |

---

## 1 · THE ANSWER TO THE QUESTION THIS AUDIT EXISTS TO ANSWER

> *"What have we already built that we should now wire?"*

Seven findings. Every one is an **existing, authoritative implementation**
that is not reaching the product. None of them requires a new engine.

| # | Finding | Class | Evidence |
|---|---|---|---|
| **F-1** | **Endpoint identity aliasing is wired for Device Trajectory only.** `GET /api/edr/process-tree` and `/api/edr/endpoint-detections` *resolve* the alias (`identity.resolved: true`, same hostname, same `device_iid`) and then query on the **raw supplied string**. Supplied `dev_42e8c6dc74b9` → **0 nodes / 0 detections / 0 events evaluated**. Supplied `ep_2d57cbe6f80152062109` → **54 nodes · 49 observed · 5 ghost roots** and **10 detections / 971 events evaluated**. Same endpoint. The console therefore renders *"NO MATCHING EVIDENCE"* and *"NO RULE FIRED"* on an endpoint that has both. | **ORPHAN (mis-wired)** · authoritative capability, false-honest empty state | E2 + live re-probe of both identifiers + E6 screenshots of `/edr/process-tree` and `/edr/detections` |
| **F-2** | **The NivXForge EDR console advertises its own proven surfaces as unavailable.** `EdrOverviewPage.jsx` hardcodes `available: false` for **Detections · Process Tree · Files · Network** and renders a disabled *"Not available / Reserved · later slice"* button — while `/edr/detections` and `/edr/process-tree` are **routed, implemented (295 / 242 lines) and render**, and their APIs return real data (F-1 aside). The same card also points Device Trajectory at the **legacy** `/edr/trajectory` instead of the canonical `/edr/device-trajectory`. | **ORPHAN (stale product flag)** | E6 + `nivxforge/pages/EdrOverviewPage.jsx:16-26` |
| **F-3** | **The EDR product's Response tab is a reserved stub while the authoritative endpoint-response UI lives inside the XDR admin console.** `/edr/response` renders `EdrReservedPages.jsx` ("Arrives in a later slice"), yet `GET /api/edr/response/actions` returns **41 200 bytes of real command records** and the response-evidence surface is `REAL_ENDPOINT_VALIDATED` at `/xdr/admin/edr-response`. Endpoint response is an **EDR-owned** capability presented only in XDR. | **ORPHAN + ownership misplacement** | E2 + `xdr/admin/EdrResponseBody.jsx` + `nivxforge/pages/EdrReservedPages.jsx:60` |
| **F-4** | **Collector split-brain — two collector runtimes, and the console reads the silent one.** The standalone collector **is running** (supervisor `xdr_collector`, port **8055**, tenant `nivx-live`, forwarding to `/api/xdr/ingest/telemetry`) and reports `ingest.state: connected`, **35 delivered · 3 dead-letter**, with a real syslog connector in `.state/connectors.json` (`syslog-3daed23d`, UDP 5514, CEF/LEEF). The console reads the **landed** collector inside the backend (separate outbox at `/app/backend/xdr_state/outbox.db`), which reports `ingest.state: not_configured`, **0 delivered**, all transports `never_connected`, 0 connectors. The operator is told there is no ingest while a real one is delivering. | **ORPHAN (running but invisible) + DUPLICATE STATE STORE** | E4 + `curl localhost:8055/api/xdr/outbox/health` vs `/api/xdr/collector/telemetry-health` |
| **F-5** | **The whole XDR Respond plane is implemented and not deployed.** `apps/nivxray-xdr-response/` is a complete standalone FastAPI service (registry · adapters · vendor adapters · persisted execution state machine · approvals · evidence forwarder). It is **not** under supervisor, **no** port is listening, and `VITE_XDR_RESPONSE_URL` is unset, so `responseEngineApi.js` yields `RESPONSE_ENGINE_NOT_DEPLOYED` and `/xdr/respond/{playbooks,automation-rules,approvals}` run on browser-local stores. Its base sink is wired and has received data: `xdr_response_executions` = **231 rows**. | **ORPHAN — implemented, unwired** (explicitly *not* legacy) | E4 + E5 + `apps/nivxray-xdr-response/main.py` + `xdr/respond/responseEngineApi.js:11-22` |
| **F-6** | **Four authoritative engines are wired to routes that do not exist.** `xdr/adopt/baseCapabilities.js` makes **live** calls and therefore renders *"XDR ADAPTER NOT YET CONNECTED"* for capabilities that are present and reachable: `POST /api/verdict/stage2` → **404** (real: `/api/verdict/stage2/compute`, `…/status` = 200); `GET /api/ioc/lookup` → **404** (real: `/api/ioc/enrich`, `/api/ioc/health` = 200); `GET /api/behavior-registry` → **404** (real: `/api/behaviors/registry` = 200); `/api/mitigations*` → **404** (real: `/api/decode/mitigations/*`). Consumers affected: `XdrCompletenessPanel.jsx`, `XdrRecommendationsPanel.jsx`, `consumerPanels.jsx`. | **ORPHAN by wrong path** | E3 + direct probes (404 vs 200) |
| **F-7** | **Two XDR surfaces hold real data with no consumer at all.** `/api/xdr/spread/*` (5 routes, `REACHABLE_200`) has **zero** frontend callers, while `xdr_spread_watchlist` = **181 docs** and `xdr_spread_sightings` = **421 docs** including tenant `default`. `XdrDashboardPage.jsx` (Control Center tiles, consuming `/api/xdr/dashboard/tiles`, `REACHABLE_200_DATA`) is **imported in `App.jsx` and never mounted on a route** — `/xdr` and `/xdr/dashboard` both redirect to `/xdr/incidents`. It is the only imported-but-unrouted page in the build. | **ORPHAN** | E3 + E5 + static analysis of `App.jsx` (37 imported page components, 1 unrouted) |

| **F-8** | **The XDR product genuinely depends on the "legacy" lineage — 39 routes are adopted, not dead.** `XdrRuleTuningPage.jsx` runs on the `/api/regression/*`, `/api/batch/*` and `/api/corpus/validate/*` harness; `XdrRecommendationsPanel.jsx` + `recommendationEngine.js` read `/api/decode/mitigations/evidence_driven`; `IntelligenceControlPanel.jsx` reads `/api/intelligence/policy/*`; the adopt panels read `/api/die/*` and `/api/iedde/analyze`. Per the owner's rule 2 these are reclassified **`SHARED · adopted-in-product`**, not legacy. | **NOT legacy — adopted** | E3 (see §2.4, 39 routes) |

**Nothing in F-1…F-7 needs a new engine, a simplified re-implementation or a
second store.** Every one is a connection defect. **F-8 is the inverse
warning**: 39 routes of the "old" lineage are load-bearing for the current
XDR product, so the legacy lineage may be left unwired but must **not** be
removed.

---

## 2 · MATRIX 2 — OWNERSHIP + WIRING

### 2.0 · Runtime facts this matrix rests on

| Fact | Value |
|---|---|
| Registered backend routes | **775** |
| Classified to a product surface (XDR / EDR / SHARED) — route level | **555** |
| Adopted from the earlier lineage — reclassified `SHARED · adopted-in-product` because a current product surface calls them (owner rule 2) | **39** |
| Legacy lineage with **no** product consumer — lineage level (decision 2A) | **181** across 35 lineages |
| Unclassified stubs | 3 (`/api/`, `/api/investigation`, `/api/investigator/capabilities`) |
| Processes actually running | `backend` (8001) · `frontend` (3000, `/app/apps/nivxray-xdr`) · `mongodb` · **`xdr_collector` (8055)** |
| Processes **not** running | `apps/nivxray-xdr-response` (no supervisor program, no listener) |
| Frontend `/api` literals | 189 → **154 resolve to a live route**, 35 do not |
| React routes | **44** (`/login`, `/edr/login`, 31 XDR, 11 EDR, catch-all) |
| Imported-but-unrouted page components | **1** (`XdrDashboardPage`) |

### 2.1 · ENGINE / SERVICE PACKAGE OWNERSHIP
*(the §7 critical technology audit — one row per package, answering: what it
does · authoritative? · which product · duplicate? · registered · running ·
reachable · real data · correct UI · correct downstream · obsolete?)*

| Package | What it actually does | Authoritative? | Owner | Registered / Running / Reachable | Real data | Duplicate of anything? | State |
|---|---|---|---|---|---|---|---|
| `backend/edr_plane/` (`trajectory_window` · `canonical_bridge` · `campaign_story` · `response` · `isolation_policy` · `raw_events` · `enrollment` · `capability`) | the EDR evidence + response plane; projects canonical observations, bridges sensor evidence into the shared detection fabric, owns the response lifecycle and the capability-truth registry | **YES** | **EDR** (surface) on **SHARED** fabric | registered · running · reachable | yes — 8 128 `edr_raw_events`, 7 025 `v2_shadow_observations` | no | `REAL_RUNTIME_VERIFIED` |
| `backend/services/edr/` (`device_identity` · `endpoint_health` · `file_trajectory` · `observation_narrative`) | endpoint identity aliasing, health, fleet file trajectory, narrative | **YES** | **EDR** | registered · running · reachable | partially — `file_trajectory` starved (G-4: `artefacts.file[].sha256`/name unpopulated) | no | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — **alias resolution is applied on the trajectory path only (F-1)** |
| `backend/detection_content/` (native Sigma · rule store binding · DSM registry · engine registry · correlation library · LOLBAS) | the ONE detection fabric; 5 Linux EDR rules + library + store binding; DSM registry resolves every telemetry source | **YES** | **SHARED** — XDR authors, EDR consumes | registered · running · reachable (`/api/xdr/detection/*` 200, `…/rule-bindings` 38 KB) | yes | no — `rule_store_binding` deliberately delegates to the existing parser/evaluator | `REAL_RUNTIME_VERIFIED` |
| `backend/v2/` (`ingestion` · `normalization` · `cem` · `case_engine` · `investigation` (+`ikg`) · `verdict` · `trajectory` · `ikb` · `shadow/irg` · `artifact_store` · `report` · `mdr` · `validation` · `routers`) | the authoritative analytical fabric — canonical evidence, case store, investigation/IKG, verdict, IRG | **YES** | **SHARED** | registered (67 routes) · running · reachable | yes — 561 `workspace_cases` | no; `v2/case_engine` + `workspace_cases` is the **only** case engine — Y3.2 Casebook must project onto it | `REAL_RUNTIME_VERIFIED` |
| `backend/services/` (~40 sub-packages: `attack_graph` · `attack_story` · `attack_evidence` · `correlation_engine` · `evidence_inspector` · `activity` · `canonicalizer` · `cem` · `dashboard_lenses` · `session_context` …) | the shared projection/service layer behind incidents, investigation, correlation, evidence and tenant scoping | **YES** | **SHARED** | registered · running · reachable (incident detail 7 KB, attack-graph 24 KB, investigation 36 KB) | yes | no | `REAL_RUNTIME_VERIFIED` |
| `backend/engine/` (`correlation_engine` · `evidence_graph*` · `entity_classifier` · `golden_corpus*` · `orchestrator` · `parsers` · `interpreters` · `detectors`) | the earlier analysis engine; **still a live dependency** — `v2/jobs/pipeline.py` imports `engine.models.AnalystReport`, and 10 modules under `routers`/`v2`/`services` import it | partly | **SHARED (live dependency)** + legacy lineage inside it | registered · running · reachable | yes | its `correlation_engine` co-exists with `services/correlation_engine` and `xdr_correlation` → **three correlation surfaces, ownership unresolved** | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` — **must NOT be labelled legacy: current code depends on it** |
| `backend/reasoning/` (`candidate_engine` · `confidence_engine` · `moe_panel` · `explainer` · `llm_tiebreaker` · `scorer`) | decoder-era reasoning / MoE panel | no | **LEGACY lineage**, but **live**: imported by `routers/{threat_model,moe_panel,learning}.py` | registered · running · reachable | n/a | no | `LEGACY-DUPLICATE` for the product; **do not delete — three live routers import it** |
| `backend/nivxforge/` (`investigation/` (+`pipeline`, `normalizers`) · `preview/router` · `attribution` · `learning` · `observability` · `engines`) | **NOT the NivXForge EDR backend** — a name collision. This is the older investigation/CIO/ADR-0014 lineage. Its `/api/nivxforge/*` router **is registered and reachable** (9 routes, `health` + preview diagnostics = 200) and `services/canonical_evidence_recovery.py:201` imports `nivxforge.investigation.ingress_gate` in a **production** path | no — superseded by `v2/investigation` + `edr_plane` | **LEGACY-DUPLICATE · PARTIALLY REUSED** (owner option **D**) | registered · running · reachable | preview/diagnostic payloads only | **yes — duplicate of `v2/investigation`** (own graph, verdict engine, CIO, normalizers incl. `cisco_secure_endpoint.py`, `microsoft_defender.py`, `sysmon.py`) | `LEGACY-DUPLICATE` — *"superseded by the current authoritative `v2`/`edr_plane` implementation; retained because one production path and one registered router still depend on it."* **Do not wire. Do not delete.** |
| `backend/workspace/` (`convergence` · `interpreter_ownership`) | decoder-era workspace convergence | no | **LEGACY lineage**, live via `services/recipe_planner.py`, `services/l0_bridge.py` | registered · running | n/a | no | `LEGACY-DUPLICATE` |
| `backend/l1_evidence/` + `backend/l2_investigation/` | the L1/L2 evidence + investigation-state lineage; reached only through `routers/workspace_investigation.py` (18 `/api/investigation/*` routes) | superseded | **LEGACY-DUPLICATE · PARTIALLY REUSED** | registered · running · reachable | yes | **yes — duplicate of `v2/investigation`** | `LEGACY-DUPLICATE` |
| `apps/nivxray-xdr-collector/` | full collection/transport framework: REST poller · webhook receiver (HMAC) · **syslog UDP/TCP** · payload formats (CEF/LEEF) · outbox with dead-letter + replay · dedup · delivery worker · identity | **YES** | **XDR** | **RUNNING** (supervisor `xdr_collector`, :8055) · **NOT reachable from the console** (only 8001/3000 traverse the ingress; `VITE_XDR_COLLECTOR_URL` unset) | **yes — 35 delivered, 3 dead-letter, 1 real syslog connector** | **partially landed twice**: `routers/xdr_collector_landing.py` imports this same package via `sys.path` (one code path) but points it at a **different `XDR_STATE_DIR`** → two independent outboxes | **ORPHAN — running, real data, invisible to the product (F-4)** |
| `apps/nivxray-xdr-response/` | the response plane: `ActionRegistry` · `adapters` + `vendor_adapters` · `Executor` · persisted `ExecutionStore` · approvals · `EvidenceForwarder` → `POST /api/xdr/response-evidence` | **YES** | **XDR** | code exists · **NOT running** (no supervisor program, no listener) · not reachable | its base sink has data: `xdr_response_executions` **231**, `xdr_response_evidence` 2 | no — the base backend has **no** playbook/automation/approval/execute engine, so this is the only one | **ORPHAN — implemented, unwired (F-5)** · `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| `backend/routers/xdr_collectors.py` + `xdr_data_sources.py` (native Mongo control plane) | RBAC-gated, audit-logged data-source/collector CRUD; `CONNECTED` assigned only by real telemetry through `/api/xdr/ingest/telemetry` | **YES** | **XDR** | registered · running · reachable (`200`, `count: 0` for tenant `default`) | `xdr_collectors` **111** docs, `xdr_data_sources` **22** docs — but **only** for `nivx-live` and `p08-*` test tenants, so `count: 0` on `default` is *correct scoping*, not a defect | **overlaps** the landed collector's disk-backed connector registry (`/api/xdr/collector/connectors`) → **two registries for one concept** | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` · **duplicate-surface risk, ownership must be decided before either is extended** |
| `backend/edr_plane/capability/` | the capability-truth registry (135 rows, `downgraded_claims: 0`) | **YES** | **EDR** | registered · running · reachable · consumed by `xdr/admin/EdrCapabilityTruthBody.jsx` | yes | no | `REAL_RUNTIME_VERIFIED` — but it is surfaced **inside the XDR admin console**, not the EDR product |
| `backend/xdr_state/` | the landed collector's outbox + root key | n/a | XDR | on disk, in use by the landed collector | outbox **0 delivered** | **duplicate of** `apps/nivxray-xdr-collector/.state/` | see **F-4** |

### 2.2 · PRODUCT UI SURFACE OWNERSHIP (runtime-verified)

| Surface | Route | Owner | Wired? | State |
|---|---|---|---|---|
| XDR login | `/login` | XDR | yes | `REAL_RUNTIME_VERIFIED` |
| EDR login | `/edr/login` | EDR | yes — NivXForge branding, own shell | `REAL_RUNTIME_VERIFIED` |
| **Unauthenticated deep link into an EDR route** | `/edr/*` → `Protected` | EDR | **no** — renders the **NivXRay XDR** login, not the NivXForge EDR login | **product-identity leak** · `NOT_IMPLEMENTED` |
| XDR rail | 8 primaries + indented children | XDR | yes — verified live: `Control Center · Incidents · Investigate · Intelligence · Automate · Assets · Client Management · Administration` | `REAL_RUNTIME_VERIFIED` |
| Control Center (tile grid) | rail → `/xdr/mss-dashboard` | XDR | partial — `XdrDashboardPage` (tiles) is **unrouted** (F-7) | `ORPHAN` |
| Incidents queue | `/xdr/incidents` | XDR | yes — 276 incidents, count tiles, filters, saved views | `REAL_RUNTIME_VERIFIED` |
| Incident record · Notes tab | `/xdr/incidents/:id` | XDR | honest reserve — `/api/incidents/:id/notes` does not exist; local draft only | `NOT_IMPLEMENTED` (declared) |
| Incident record · Related tab | `/xdr/incidents/:id` | XDR | honest reserve — `/api/xdr/incidents/:id/related` does not exist | `NOT_IMPLEMENTED` (declared) |
| Respond · Playbooks / Automation Rules / Approvals | `/xdr/respond/*` | XDR | **no** — browser-local stores; engine exists but is not deployed (F-5) | `ORPHAN` |
| Assets / Endpoints | `/xdr/endpoints` | XDR (pivots to EDR per D-4) | yes | `IMPLEMENTED_NOT_RUNTIME_VERIFIED` |
| Fleet File Trajectory | `/xdr/intelligence/files/:key` | **EDR capability hosted in XDR** | yes (calls `/api/edr/file-trajectory`) | `BLOCKED` on data (G-4) + ownership question |
| XDR administration (34 sections) | `/xdr/admin/:section` | XDR | mostly yes; `agents`, `response-policies` declare `connected: false`; `sdl` disabled | mixed |
| **EDR administration** (`edr-enrollment` · `edr-response` · `edr-capability-truth`) | `/xdr/admin/*` | **EDR capabilities hosted in the XDR console** | yes, but in the wrong product | **ownership misplacement** |
| EDR rail | 11 tabs | EDR | yes | `REAL_RUNTIME_VERIFIED` |
| EDR Device Trajectory (AMP) | `/edr/device-trajectory` | EDR | yes — canonical operational surface | `END_TO_END_VALIDATED` |
| EDR Detections | `/edr/detections` | EDR | routed + implemented, **renders empty on the device_iid** (F-1) and is advertised unavailable (F-2) | `ORPHAN` |
| EDR Process Tree | `/edr/process-tree` | EDR | routed + implemented, **renders empty on the device_iid** (F-1) and is advertised unavailable (F-2) | `ORPHAN` |
| EDR Campaign Story | `/edr/campaign-story` | EDR | yes — 30 KB real projection | `END_TO_END_VALIDATED` |
| EDR Files | `/edr/files` | EDR | reserved stub; backend `/api/edr/file-trajectory` exists but is data-starved | `BLOCKED` (G-4) |
| EDR Network | `/edr/network` | EDR | reserved stub; **no** endpoint network/DNS collection exists | `BLOCKED` |
| EDR Response | `/edr/response` | EDR | reserved stub while the real surface lives in XDR admin (F-3) | `ORPHAN` |
| EDR Threat Hunting · Forensics · Live Query | `/edr/{hunting,forensics,live-query}` | EDR | reserved stubs, no backend | `NOT_IMPLEMENTED` |
| `/xdr/edr/device-trajectory` | permanent context-preserving redirect (D-2) | shared | yes | `REAL_RUNTIME_VERIFIED` |

### 2.3 · ROUTE-LEVEL TABLE — XDR / EDR / SHARED

Columns: **Route · Methods · Product-surface consumer (running frontend source) · Runtime probe verdict**. `—` in the consumer column means *no product surface calls this route* → orphan candidate. `NOT_PROBED` means the route was not in the read-only probe set (registration + consumer evidence only).

#### EDR · capability-truth registry  (10 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/edr/wave0/capabilities/summary` | GET | `xdr/admin/EdrCapabilityTruthBody.jsx`, `xdr/admin/adminMeta.js` | REACHABLE_200_DATA |
| `/api/edr/wave0/capabilities/{capability_id}` | GET | `xdr/admin/EdrCapabilityTruthBody.jsx`, `xdr/admin/adminMeta.js` | REACHABLE_200_DATA |
| `/api/edr/wave0/capabilities` | GET | `xdr/admin/EdrCapabilityTruthBody.jsx`, `xdr/admin/adminMeta.js` | NOT_PROBED |
| `/api/edr/wave0/contracts/{name}/schema` | GET | — | NOT_PROBED |
| `/api/edr/wave0/contracts` | GET | — | REACHABLE_200_DATA |
| `/api/edr/wave0/detection-rule-bindings` | GET | — | REACHABLE_200_DATA |
| `/api/edr/wave0/filter-taxonomy` | GET | `xdr/admin/EdrCapabilityTruthBody.jsx` | REACHABLE_200_DATA |
| `/api/edr/wave0/raw-events/replay-candidates` | GET | — | NOT_PROBED |
| `/api/edr/wave0/raw-events/stats` | GET | — | REACHABLE_200_DATA |
| `/api/edr/wave0/sensors` | GET | — | REACHABLE_200_DATA |

#### EDR · endpoint enrolment + credential lifecycle  (5 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/edr/enrollment/endpoints/{endpoint_id}/revoke` | POST | `xdr/admin/EdrEnrollmentBody.jsx`, `xdr/admin/adminMeta.js` | NOT_PROBED |
| `/api/edr/enrollment/endpoints/{endpoint_id}/rotate` | POST | `xdr/admin/EdrEnrollmentBody.jsx`, `xdr/admin/adminMeta.js` | NOT_PROBED |
| `/api/edr/enrollment/endpoints` | GET | `xdr/admin/EdrEnrollmentBody.jsx`, `xdr/admin/adminMeta.js` | REACHABLE_200_DATA |
| `/api/edr/enrollment/rejections` | GET | `xdr/admin/EdrEnrollmentBody.jsx` | REACHABLE_200_DATA |
| `/api/edr/enrollment/tokens` | GET,POST | `xdr/admin/EdrEnrollmentBody.jsx` | REACHABLE_200_DATA |

#### EDR · endpoint evidence projection  (13 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/edr/campaign-story` | GET | `nivxforge/pages/EdrCampaignStoryPage.jsx` | REACHABLE_200_DATA |
| `/api/edr/context` | GET | `nivxforge/NivXForgeConsole.jsx`, `nivxforge/edrApi.js` | REACHABLE_200_DATA |
| `/api/edr/detections` | GET | `nivxforge/edrApi.js`, `xdr/pages/XdrIncidentDomainPage.jsx` | ROUTED_NEEDS_PARAMS_422 |
| `/api/edr/device-trajectory` | GET | `nivxforge/edrApi.js`, `xdr/components/EndpointLanes.jsx` +1 | REACHABLE_200_EMPTY |
| `/api/edr/endpoint-detections` | GET | `nivxforge/edrApi.js` | ROUTED_NEEDS_PARAMS_422 |
| `/api/edr/endpoints/{endpoint_id}/linked-incidents` | GET | `nivxforge/components/LinkedXdrIncidents.jsx`, `nivxforge/edrApi.js` +2 | REACHABLE_200_DATA |
| `/api/edr/endpoints/{endpoint_id}/trajectory/focus` | GET | `nivxforge/edrApi.js`, `nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` +1 | REACHABLE_200_DATA |
| `/api/edr/endpoints/{endpoint_id}/trajectory` | GET | `nivxforge/edrApi.js`, `nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` +1 | REACHABLE_200_DATA |
| `/api/edr/endpoints` | GET | `nivxforge/edrApi.js`, `nivxforge/trajectory/EdrDeviceTrajectoryPage.jsx` +1 | REACHABLE_200_DATA |
| `/api/edr/file-trajectory` | GET | `nivxforge/edrApi.js` | ROUTED_NEEDS_PARAMS_422 |
| `/api/edr/fleet-spread-index` | GET | `nivxforge/edrApi.js` | REACHABLE_200_DATA |
| `/api/edr/observation-narrative` | GET | `nivxforge/edrApi.js` | ROUTED_NEEDS_PARAMS_422 |
| `/api/edr/process-tree` | GET | `nivxforge/edrApi.js`, `xdr/adopt/baseCapabilities.js` +3 | REACHABLE_200_DATA |

#### EDR · endpoint response lifecycle  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/edr/response/actions/{command_id}` | GET | `xdr/admin/EdrResponseBody.jsx`, `xdr/admin/adminMeta.js` | NOT_PROBED |
| `/api/edr/response/actions` | GET,POST | `xdr/admin/EdrResponseBody.jsx`, `xdr/admin/adminMeta.js` | REACHABLE_200_DATA |
| `/api/edr/response/isolation-policy` | GET,PUT | `xdr/admin/EdrResponseBody.jsx` | REACHABLE_200_DATA |

#### SHARED · IOC intelligence  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/ioc/enrich/one` | POST | — | NOT_PROBED |
| `/api/ioc/enrich` | POST | — | NOT_PROBED |
| `/api/ioc/health` | GET | — | NOT_PROBED |

#### SHARED · IUE understanding lanes  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/iue/lane-a/analyze` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/lane-a/status` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/lane-b/analyze` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/lane-c/analyze-b64` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/lane-c/analyze` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/lane-c/status` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iue/timeline/fuse` | POST | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/enginePanels.jsx` | NOT_PROBED |

#### SHARED · LOLBAS content pack  (12 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/lolbas/coverage` | GET | `xdr/admin/DetectionContentBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/lolbas/ensure-synced` | POST | `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/entries/{name}/disable` | POST | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/entries/{name}/enable` | POST | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/entries/{name}` | GET | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/entries` | GET | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/lolbas/match` | POST | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/primitives` | GET | `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/rollback/{version_id}` | POST | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/status` | GET | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/lolbas/sync` | POST | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |
| `/api/xdr/lolbas/versions` | GET | `xdr/admin/ContentPackLolbasBody.jsx`, `xdr/admin/DetectionContentBody.jsx` | NOT_PROBED |

#### SHARED · MITRE catalogue  (5 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/mitre/catalogue/coverage` | GET | `xdr/pages/XdrMitreHeatmap.jsx` | REACHABLE_200_DATA |
| `/api/mitre/catalogue` | GET | — | NOT_PROBED |
| `/api/mitre/heatmap/probe` | POST | — | NOT_PROBED |
| `/api/mitre/heatmap/tactic/{name}` | GET | — | NOT_PROBED |
| `/api/mitre/heatmap` | GET | — | NOT_PROBED |

#### SHARED · RBAC / authorisation  (13 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/rbac/groups/{group_id}` | DELETE | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/groups` | GET,POST | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/permissions` | GET | `xdr/admin/UsersRolesBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/rbac/roles/{role_id}/clone` | POST | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/roles/{role_id}` | DELETE,GET,PUT | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/roles` | GET,POST | `xdr/admin/UsersRolesBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/rbac/session-context` | GET | `nivxforge/edrApi.js`, `xdr/admin/UsersRolesBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/rbac/simulate` | POST | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/users/{user_id}/effective` | GET | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/users/{user_id}/roles/{assignment_id}` | DELETE | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/users/{user_id}/roles` | POST | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/users/{user_id}` | DELETE,PUT | `xdr/admin/UsersRolesBody.jsx` | NOT_PROBED |
| `/api/xdr/rbac/users` | GET,POST | `xdr/admin/UsersRolesBody.jsx` | REACHABLE_200_DATA |

#### SHARED · SSOT  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/ssot/{investigation_id}` | GET | — | NOT_PROBED |

#### SHARED · UAIE catalogue  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/uaie/catalog.dot` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/uaie/catalog` | GET | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/enginePanels.jsx` | NOT_PROBED |
| `/api/uaie/compare` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/uaie/dry-run` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |

#### SHARED · UIL classification  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/uil/classify` | POST | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/enginePanels.jsx` | NOT_PROBED |
| `/api/uil/investigate` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/uil/split` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |

#### SHARED · activity inventory  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/activity/inventory` | POST | `components/incidents/tabs/ActivityTab.jsx`, `xdr/pages/incidents/record/tabs/TimelineTab.jsx` | ROUTED_METHOD_MISMATCH_405 |

#### SHARED · administration  (34 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/admin/behaviors/preview` | POST | — | NOT_PROBED |
| `/api/admin/data-sources/summary` | GET | `xdr/admin/PlatformOverviewBody.jsx` | NOT_PROBED |
| `/api/admin/detection/summary` | GET | `xdr/admin/PlatformOverviewBody.jsx` | NOT_PROBED |
| `/api/admin/finetune/dataset.jsonl` | GET | — | NOT_PROBED |
| `/api/admin/finetune/dataset/summary` | GET | — | NOT_PROBED |
| `/api/admin/finetune/dataset` | GET | — | NOT_PROBED |
| `/api/admin/finetune/stats` | GET | — | NOT_PROBED |
| `/api/admin/finetune/test-offline-llm` | POST | — | NOT_PROBED |
| `/api/admin/ioc/composition` | GET | `xdr/admin/PlatformOverviewBody.jsx` | NOT_PROBED |
| `/api/admin/llm-telemetry` | GET | — | NOT_PROBED |
| `/api/admin/lolbas/status` | GET | — | NOT_PROBED |
| `/api/admin/lolbas/sync` | POST | — | NOT_PROBED |
| `/api/admin/models/catalog` | GET | — | NOT_PROBED |
| `/api/admin/models/{model_id}/test` | POST | — | NOT_PROBED |
| `/api/admin/models/{model_id}` | DELETE,PUT | — | NOT_PROBED |
| `/api/admin/models` | GET,POST | — | NOT_PROBED |
| `/api/admin/osint/services` | GET | — | NOT_PROBED |
| `/api/admin/osint/settings` | PUT | — | NOT_PROBED |
| `/api/admin/osint/test/{service_id}` | POST | — | NOT_PROBED |
| `/api/admin/playbooks/{playbook_id}/votes` | GET | — | NOT_PROBED |
| `/api/admin/resource-protection` | GET | — | NOT_PROBED |
| `/api/admin/samples/benchmark/all` | POST | — | NOT_PROBED |
| `/api/admin/samples/bulk` | POST | — | NOT_PROBED |
| `/api/admin/samples/dashboard` | GET | — | NOT_PROBED |
| `/api/admin/samples/{sid}/benchmark` | POST | — | NOT_PROBED |
| `/api/admin/samples/{sid}` | DELETE,GET,PUT | — | NOT_PROBED |
| `/api/admin/samples` | GET,POST | — | NOT_PROBED |
| `/api/admin/stats` | GET | `xdr/admin/PlatformOverviewBody.jsx` | NOT_PROBED |
| `/api/admin/taxii/config` | GET,POST | — | NOT_PROBED |
| `/api/admin/taxii/history` | GET | — | NOT_PROBED |
| `/api/admin/taxii/push` | POST | — | NOT_PROBED |
| `/api/admin/taxii/test` | POST | — | NOT_PROBED |
| `/api/admin/training-notes/sync-url` | POST | — | NOT_PROBED |
| `/api/admin/users` | GET | — | NOT_PROBED |

#### SHARED · authoritative incident record  (23 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/incidents/{incident_id}/assignee` | PATCH | `xdr/pages/XdrIncidentsPage.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/attack-evidence` | GET | — | NOT_PROBED |
| `/api/incidents/{incident_id}/attack-graph` | GET | `xdr/pages/incidents/record/tabs/AttackGraphTab.jsx` | REACHABLE_200_DATA |
| `/api/incidents/{incident_id}/attack-story` | GET | `xdr/pages/incidents/record/tabs/AttackStoryTab.jsx` | REACHABLE_200_DATA |
| `/api/incidents/{incident_id}/inspector/{kind}/{ref_id}` | GET | `xdr/components/EvidenceInspector.jsx`, `xdr/design/SharedEvidenceInspector.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/intelligence/overlays/{target_kind}/{target_id}/{field_key}/history` | GET | — | NOT_PROBED |
| `/api/incidents/{incident_id}/intelligence/overlays/{target_kind}/{target_id}/{field_key}` | DELETE,GET,PUT | — | NOT_PROBED |
| `/api/incidents/{incident_id}/intelligence/overlays` | GET | `xdr/pages/incidents/record/tabs/AutoInvestigationTab.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/investigation/executions` | GET | — | NOT_PROBED |
| `/api/incidents/{incident_id}/investigation/findings` | GET | — | NOT_PROBED |
| `/api/incidents/{incident_id}/investigation` | GET | `xdr/pages/incidents/record/tabs/AutoInvestigationTab.jsx` | REACHABLE_200_DATA |
| `/api/incidents/{incident_id}/operations` | PATCH | — | NOT_PROBED |
| `/api/incidents/{incident_id}/report/blocks/{block_id}/suppress` | POST | — | NOT_PROBED |
| `/api/incidents/{incident_id}/report/blocks/{block_id}` | DELETE,PATCH | `xdr/pages/incidents/record/tabs/ReportTab.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/report/blocks` | POST | `xdr/pages/incidents/record/tabs/ReportTab.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/report/pdf` | GET | `xdr/pages/incidents/record/tabs/ReportTab.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/report` | GET | `xdr/pages/incidents/record/tabs/ReportTab.jsx` | NOT_PROBED |
| `/api/incidents/{incident_id}/state` | PATCH | `xdr/pages/incidents/record/LifecycleStrip.jsx`, `xdr/pages/incidents/record/tabs/ClosureTab.jsx` +1 | NOT_PROBED |
| `/api/incidents/{incident_id}/summary` | GET | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/consumerPanels.jsx` +5 | REACHABLE_200_DATA |
| `/api/incidents/{incident_id}/threat-model` | GET | `xdr/pages/incidents/record/ThreatAssessmentCard.jsx` | REACHABLE_200_DATA |
| `/api/incidents/{incident_id}/understanding` | GET | — | NOT_PROBED |
| `/api/incidents/{incident_id}` | GET | `lib/incidentsApi.js`, `xdr/adopt/baseCapabilities.js` +1 | REACHABLE_200_DATA |
| `/api/incidents` | GET | `lib/incidentsApi.js`, `xdr/pages/XdrDashboardPage.jsx` +3 | REACHABLE_200_DATA |

#### SHARED · authoritative ingest boundary  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/ingest/telemetry` | POST | — | NOT_PROBED |

#### SHARED · behaviour provenance  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/behavioral/attach` | POST | — | NOT_PROBED |
| `/api/behavioral/case/{case_id}` | DELETE,GET | — | NOT_PROBED |
| `/api/behavioral/sysmon/evtx` | POST | — | NOT_PROBED |
| `/api/behavioral/sysmon` | POST | — | NOT_PROBED |

#### SHARED · behaviour registry  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/behaviors/registry/{behavior_type}` | GET | — | NOT_PROBED |
| `/api/behaviors/registry` | GET | — | NOT_PROBED |

#### SHARED · case store  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/cases/reinvestigate-broken` | POST | — | NOT_PROBED |
| `/api/cases/save` | POST | — | NOT_PROBED |
| `/api/cases/{case_id}/reinvestigate` | POST | — | NOT_PROBED |
| `/api/cases/{case_id}/sigma` | GET | — | NOT_PROBED |
| `/api/cases/{case_id}/yara` | GET | — | NOT_PROBED |
| `/api/cases/{case_id}` | DELETE,GET | — | NOT_PROBED |
| `/api/cases` | GET | — | REACHABLE_200_DATA |

#### SHARED · content supply chain  (42 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/admin/content-supply-chain/architecture/audit/summary` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/architecture/audit` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/binding/match` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/binding/report` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/canonical-evidence/count` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/collector-runtime/bootstrap-snort` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/collector-runtime/status` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/collector-runtime/{collector_id}/start` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/collector-runtime/{collector_id}/stop` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/contracts/declare` | POST | `xdr/admin/EngineRoleAdminBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/contracts/report` | GET | `xdr/admin/EngineRoleAdminBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/contracts/{engine_id}` | GET | `xdr/admin/EngineRoleAdminBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/contracts` | GET | `xdr/admin/EngineRoleAdminBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/dsm/registry` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/e2e/snort-golden` | POST | `xdr/admin/GoldenPipelineTrace.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/engines/control-plane/dependencies` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/engines/control-plane` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/engines/list` | GET | `xdr/admin/EngineRoleAdminBody.jsx`, `xdr/admin/NormalizationBody.jsx` +1 | NOT_PROBED |
| `/api/admin/content-supply-chain/engines/report` | GET | `xdr/admin/EnginesBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/evidence/{evidence_ref}` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/frameworks` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/harness/engines` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/harness/run` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/annotations/{ann_id}` | DELETE,PATCH | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/annotations` | GET,POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/attack-chain-graph` | GET | `xdr/design/IncidentOverviewV2.jsx`, `xdr/pages/incidents/record/tabs/MitreTab.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/closure-classification` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/executive-summary` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/framework-mappings/resolve` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/framework-mappings` | GET | `xdr/admin/FrameworkMappingsPanel.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/playbooks` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/incidents/{incident_id}/threat-family` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/investigation/{incident_id}` | GET | `xdr/admin/InvestigationLanes.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/osint-cache/summary` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/recommendations/{recommendation_id}/decision` | POST | — | NOT_PROBED |
| `/api/admin/content-supply-chain/report` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/response-strategies/{family}` | GET | `xdr/admin/ResponseStrategiesBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/response-strategies` | GET | `xdr/admin/ResponseStrategiesBody.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/response/actions` | GET | — | NOT_PROBED |
| `/api/admin/content-supply-chain/response/{incident_id}/recompute` | POST | `xdr/admin/ClosedLoopPanel.jsx`, `xdr/pages/incidents/record/tabs/RecommendationsTab.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/response/{incident_id}` | GET | `xdr/admin/ResponseFabricPanel.jsx` | NOT_PROBED |
| `/api/admin/content-supply-chain/samples` | GET | — | NOT_PROBED |

#### SHARED · correlation engine  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/correlation/matches` | GET | `xdr/admin/CorrelationRulesBody.jsx`, `xdr/investigation/AttackChainPanel.jsx` | REACHABLE_200_DATA |
| `/api/xdr/correlation/replay` | POST | `xdr/admin/CorrelationRulesBody.jsx` | NOT_PROBED |
| `/api/xdr/correlation/rules/{rule_id}/disable` | POST | `xdr/admin/CorrelationRulesBody.jsx` | NOT_PROBED |
| `/api/xdr/correlation/rules/{rule_id}/enable` | POST | `xdr/admin/CorrelationRulesBody.jsx` | NOT_PROBED |
| `/api/xdr/correlation/rules` | GET,POST | `xdr/admin/CorrelationRulesBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/correlation/signals` | POST | — | NOT_PROBED |
| `/api/xdr/correlation/status` | GET | `xdr/admin/CorrelationRulesBody.jsx` | REACHABLE_200_DATA |

#### SHARED · correlation records  (17 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/correlations/cem/{case_id}` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/correlations/compare` | POST | — | NOT_PROBED |
| `/api/correlations/find-related` | POST | — | NOT_PROBED |
| `/api/correlations/fingerprint/{case_id}` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/correlations/provenance/{case_id}` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/correlations/scan` | POST | — | NOT_PROBED |
| `/api/correlations/{cid}/chain` | GET | — | NOT_PROBED |
| `/api/correlations/{cid}/graph` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/correlations/{cid}/link` | POST | — | NOT_PROBED |
| `/api/correlations/{cid}/suggestions/{case_id}/confirm` | POST | — | NOT_PROBED |
| `/api/correlations/{cid}/suggestions/{case_id}/dismiss` | POST | — | NOT_PROBED |
| `/api/correlations/{cid}/suggestions` | GET | — | NOT_PROBED |
| `/api/correlations/{cid}/summary` | GET | — | NOT_PROBED |
| `/api/correlations/{cid}/timeline` | GET | — | NOT_PROBED |
| `/api/correlations/{cid}/unlink` | POST | — | NOT_PROBED |
| `/api/correlations/{cid}` | DELETE,GET,PATCH | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/correlations` | GET,POST | `xdr/adopt/baseCapabilities.js` | REACHABLE_200_DATA |

#### SHARED · detection content plane  (11 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/detection/ensure-synced` | POST | `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/inventory` | GET | `xdr/pages/XdrDetectionsPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/detection/policy` | GET | `xdr/pages/XdrDetectionsPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/detection/rules/{rule_id}/disable` | POST | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/rules/{rule_id}/enable` | POST | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/rules/{rule_id}` | GET | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/rules` | GET | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/detection/sources/catalog` | GET | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/status` | GET | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/detection/sync` | POST | `xdr/pages/XdrDetectionsPage.jsx` | NOT_PROBED |
| `/api/xdr/detection/versions` | GET | `xdr/admin/DetectionRegistryBody.jsx`, `xdr/pages/XdrDetectionsPage.jsx` | REACHABLE_200_DATA |

#### SHARED · enrichment  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/enrichment/bulk` | POST | — | NOT_PROBED |
| `/api/enrichment/classify` | GET | — | NOT_PROBED |
| `/api/enrichment/config` | GET,POST | — | NOT_PROBED |
| `/api/enrichment/ioc` | POST | — | NOT_PROBED |

#### SHARED · indicator spread / sightings  (5 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/spread/policy` | GET | — | REACHABLE_200_DATA |
| `/api/xdr/spread/signals` | GET | — | HTTP_400 |
| `/api/xdr/spread/{watch_id}/retire` | POST | — | NOT_PROBED |
| `/api/xdr/spread/{watch_id}` | GET | — | REACHABLE_200_DATA |
| `/api/xdr/spread` | GET,POST | — | HTTP_400 |

#### SHARED · investigation projections  (17 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/investigation/behaviors/explain` | POST | — | NOT_PROBED |
| `/api/investigation/coverage/consumer_matrix` | GET | — | NOT_PROBED |
| `/api/investigation/coverage/health` | GET | — | NOT_PROBED |
| `/api/investigation/coverage/rule_efficiency` | GET | — | NOT_PROBED |
| `/api/investigation/coverage/summary` | GET | — | NOT_PROBED |
| `/api/investigation/summary` | POST | — | NOT_PROBED |
| `/api/investigation/{case_id}/capabilities` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/detections` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/hunting` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/iocs` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/state/transition` | POST | — | NOT_PROBED |
| `/api/investigation/{case_id}/state` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/story` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/summary` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/threat` | GET | — | NOT_PROBED |
| `/api/investigation/{case_id}/workspace` | GET,PUT | — | NOT_PROBED |
| `/api/investigation/{case_id}` | DELETE,GET | — | NOT_PROBED |

#### SHARED · investigation records  (6 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/investigations/lookup` | POST | — | NOT_PROBED |
| `/api/investigations/recent` | GET | — | NOT_PROBED |
| `/api/investigations/{iid}/note` | POST | — | NOT_PROBED |
| `/api/investigations/{iid}/timeline` | GET | — | NOT_PROBED |
| `/api/investigations/{iid}` | DELETE | — | NOT_PROBED |
| `/api/investigations` | GET | — | REACHABLE_200_DATA |

#### SHARED · knowledge base  (6 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/kb/entries/{slug}` | DELETE,GET | `xdr/pages/XdrKbPage.jsx` | NOT_PROBED |
| `/api/kb/entries` | GET | `xdr/pages/XdrKbPage.jsx` | NOT_PROBED |
| `/api/kb/rebuild` | POST | — | NOT_PROBED |
| `/api/kb/save-from-investigation` | POST | — | NOT_PROBED |
| `/api/kb/search` | GET | `xdr/pages/XdrKbPage.jsx` | NOT_PROBED |
| `/api/kb/stats` | GET | `xdr/pages/XdrKbPage.jsx` | REACHABLE_200_DATA |

#### SHARED · liveness  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/health/deep` | GET | — | NOT_PROBED |
| `/api/health` | GET | — | REACHABLE_200_DATA |

#### SHARED · narrative composition  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/narration/incident/{incident_id}/attack-story` | GET | — | NOT_PROBED |
| `/api/narration/incident/{incident_id}/cross-lane-story` | GET | — | NOT_PROBED |
| `/api/narration/incident/{incident_id}/executive-summary` | GET | `xdr/design/ExecutiveSummaryPanel.jsx` | NOT_PROBED |
| `/api/narration/incident/{incident_id}/r46-overlay-summary` | GET | — | NOT_PROBED |
| `/api/narration/incident/{incident_id}/report-narration` | GET | — | NOT_PROBED |
| `/api/narration/providers` | GET | — | NOT_PROBED |
| `/api/narration/render` | POST | — | NOT_PROBED |

#### SHARED · observation projections  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/observation/wave1-report` | GET | — | NOT_PROBED |

#### SHARED · one auth engine, two products  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/auth/change-password` | POST | — | NOT_PROBED |
| `/api/auth/login` | POST | `App.jsx`, `lib/auth.jsx` | NOT_PROBED |
| `/api/auth/me` | GET | `lib/auth.jsx` | NOT_PROBED |

#### SHARED · outbound webhooks  (6 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/webhooks/{webhook_id}/deliveries` | GET | `xdr/admin/WebhooksBody.jsx` | NOT_PROBED |
| `/api/xdr/webhooks/{webhook_id}/replay/{delivery_id}` | POST | `xdr/admin/WebhooksBody.jsx` | NOT_PROBED |
| `/api/xdr/webhooks/{webhook_id}/rotate-secret` | POST | `xdr/admin/WebhooksBody.jsx` | NOT_PROBED |
| `/api/xdr/webhooks/{webhook_id}/test` | POST | `xdr/admin/WebhooksBody.jsx` | NOT_PROBED |
| `/api/xdr/webhooks/{webhook_id}` | DELETE,GET,PUT | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/WebhooksBody.jsx` +1 | NOT_PROBED |
| `/api/xdr/webhooks` | GET,POST | `xdr/admin/WebhooksBody.jsx` | REACHABLE_200_DATA |

#### SHARED · platform metrics  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/platform/metrics` | GET | `xdr/admin/PlatformOverviewBody.jsx` | REACHABLE_200_DATA |
| `/api/platform/snapshot` | POST | — | NOT_PROBED |
| `/api/platform/timeseries` | GET | `xdr/admin/PlatformOverviewBody.jsx` | NOT_PROBED |

#### SHARED · product documentation  (39 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/docs/adr-004.html` | GET | — | NOT_PROBED |
| `/api/docs/adr-004.md` | GET | — | NOT_PROBED |
| `/api/docs/adr-004` | GET | — | NOT_PROBED |
| `/api/docs/assets/{filename}` | GET | — | NOT_PROBED |
| `/api/docs/audit-reconciliation.html` | GET | — | NOT_PROBED |
| `/api/docs/audit-reconciliation.md` | GET | — | NOT_PROBED |
| `/api/docs/audit-reconciliation` | GET | — | NOT_PROBED |
| `/api/docs/automation/coverage` | GET | — | NOT_PROBED |
| `/api/docs/automation/scaffold` | POST | — | NOT_PROBED |
| `/api/docs/automation/suggest-fix` | POST | — | NOT_PROBED |
| `/api/docs/business/{slug}` | GET | — | NOT_PROBED |
| `/api/docs/business` | GET | — | NOT_PROBED |
| `/api/docs/cheatsheet-bundle` | GET | — | NOT_PROBED |
| `/api/docs/cheatsheet/{doc_id}` | GET | — | NOT_PROBED |
| `/api/docs/current-state-audit.html` | GET | — | NOT_PROBED |
| `/api/docs/current-state-audit.md` | GET | — | NOT_PROBED |
| `/api/docs/current-state-audit` | GET | — | NOT_PROBED |
| `/api/docs/explain/feedback/recent` | GET | — | NOT_PROBED |
| `/api/docs/explain/feedback/stats` | GET | — | NOT_PROBED |
| `/api/docs/explain/feedback` | POST | — | NOT_PROBED |
| `/api/docs/explain` | POST | — | NOT_PROBED |
| `/api/docs/export/docx` | GET | — | NOT_PROBED |
| `/api/docs/export/html` | GET | — | NOT_PROBED |
| `/api/docs/export/pdf` | GET | — | NOT_PROBED |
| `/api/docs/features/{feature_id}` | GET | `xdr/pages/XdrDocsPage.jsx` | NOT_PROBED |
| `/api/docs/features` | GET | `xdr/pages/XdrDocsPage.jsx` | NOT_PROBED |
| `/api/docs/guide` | GET | — | NOT_PROBED |
| `/api/docs/p0-p1-baseline.html` | GET | — | NOT_PROBED |
| `/api/docs/p0-p1-baseline.md` | GET | — | NOT_PROBED |
| `/api/docs/p0-p1-baseline` | GET | — | NOT_PROBED |
| `/api/docs/rag/reindex` | POST | — | NOT_PROBED |
| `/api/docs/rag/stats` | GET | `xdr/pages/XdrDocsPage.jsx` | NOT_PROBED |
| `/api/docs/related` | GET | — | NOT_PROBED |
| `/api/docs/screenshots/{workflow_id}/{filename}` | GET | — | NOT_PROBED |
| `/api/docs/screenshots/{workflow_id}` | GET | — | NOT_PROBED |
| `/api/docs/search` | GET | — | NOT_PROBED |
| `/api/docs/stats` | GET | `xdr/pages/XdrDocsPage.jsx` | REACHABLE_200_DATA |
| `/api/docs/workflows/{workflow_id}` | GET | `xdr/pages/XdrDocsPage.jsx` | NOT_PROBED |
| `/api/docs/workflows` | GET | `xdr/pages/XdrDocsPage.jsx` | NOT_PROBED |

#### SHARED · programmatic access  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/api-keys/{key_id}/revoke` | POST | `xdr/admin/ApiKeysBody.jsx` | NOT_PROBED |
| `/api/xdr/api-keys/{key_id}/rotate` | POST | `xdr/admin/ApiKeysBody.jsx` | NOT_PROBED |
| `/api/xdr/api-keys/{key_id}` | DELETE,GET,PUT | `xdr/admin/ApiKeysBody.jsx` | NOT_PROBED |
| `/api/xdr/api-keys` | GET,POST | `xdr/admin/ApiKeysBody.jsx` | REACHABLE_200_DATA |

#### SHARED · public CIO schema  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/schemas/latest/cio.schema.json` | GET | — | NOT_PROBED |
| `/api/schemas/v1/cio.schema.json` | GET | — | NOT_PROBED |

#### SHARED · reporting  (5 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/report/stix/download` | POST | — | NOT_PROBED |
| `/api/report/stix/investigation` | POST | — | NOT_PROBED |
| `/api/report/stix` | POST | — | NOT_PROBED |
| `/api/report/{fmt}` | POST | — | NOT_PROBED |
| `/api/report` | POST | — | NOT_PROBED |

#### SHARED · response evidence sink  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/response-evidence/{execution_id}` | GET | `xdr/intel/XdrRecommendationsPanel.jsx`, `xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` +1 | NOT_PROBED |
| `/api/xdr/response-evidence` | POST | `xdr/intel/XdrRecommendationsPanel.jsx`, `xdr/investigation/EvidenceFirstInvestigationWorkspace.jsx` | NOT_PROBED |

#### SHARED · response fabric alias  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/response/actions` | GET | — | REACHABLE_200_DATA |
| `/api/response/{incident_id}/recompute` | POST | — | NOT_PROBED |
| `/api/response/{incident_id}` | GET | — | REACHABLE_200_DATA |

#### SHARED · secrets store  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/secrets/{secret_id}/reveal` | POST | `xdr/admin/SecretsBody.jsx` | NOT_PROBED |
| `/api/xdr/secrets/{secret_id}/rotate` | POST | `xdr/admin/SecretsBody.jsx` | NOT_PROBED |
| `/api/xdr/secrets/{secret_id}` | DELETE,GET,PUT | `xdr/admin/SecretsBody.jsx` | NOT_PROBED |
| `/api/xdr/secrets` | GET,POST | `xdr/admin/SecretsBody.jsx` | REACHABLE_200_DATA |

#### SHARED · sensor transport + telemetry auth  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/edr/agent/command-result` | POST | — | NOT_PROBED |
| `/api/edr/agent/command-verification` | POST | — | NOT_PROBED |
| `/api/edr/agent/commands` | GET | — | NOT_PROBED |
| `/api/edr/agent/enroll` | POST | — | NOT_PROBED |
| `/api/edr/agent/session` | POST | — | NOT_PROBED |
| `/api/edr/agent/telemetry` | POST | — | NOT_PROBED |
| `/api/edr/agent/whoami` | GET | — | NOT_PROBED |

#### SHARED · session records  (8 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/session/from-investigation` | POST | — | NOT_PROBED |
| `/api/session/investigate` | POST | — | NOT_PROBED |
| `/api/session/render/nist.md` | POST | — | NOT_PROBED |
| `/api/session/render/nist.pdf` | POST | — | NOT_PROBED |
| `/api/session/{session_id}/input/{input_id}` | GET | — | NOT_PROBED |
| `/api/session/{session_id}/nist.md` | GET | — | NOT_PROBED |
| `/api/session/{session_id}/nist.pdf` | GET | — | NOT_PROBED |
| `/api/session/{session_id}` | GET | — | NOT_PROBED |

#### SHARED · tamper-evident audit  (4 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/audit-log/emit` | POST | `xdr/admin/AuditLogBody.jsx` | NOT_PROBED |
| `/api/xdr/audit-log/verify/chain` | GET | `xdr/admin/AuditLogBody.jsx` | REACHABLE_200_DATA |
| `/api/xdr/audit-log/{event_id}` | GET | `xdr/admin/AuditLogBody.jsx` | NOT_PROBED |
| `/api/xdr/audit-log` | GET | `xdr/admin/AuditLogBody.jsx` | REACHABLE_200_DATA |

#### SHARED · telemetry adapters  (9 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/telemetry/adapters/{name}/normalise` | POST | — | NOT_PROBED |
| `/api/telemetry/adapters` | GET | — | NOT_PROBED |
| `/api/telemetry/correlate` | POST | — | NOT_PROBED |
| `/api/telemetry/frontend/recent` | GET | — | NOT_PROBED |
| `/api/telemetry/frontend` | POST | — | NOT_PROBED |
| `/api/telemetry/pollers/status` | GET | — | NOT_PROBED |
| `/api/telemetry/runner/health` | GET | — | NOT_PROBED |
| `/api/telemetry/runner/recent` | GET | — | NOT_PROBED |
| `/api/telemetry/verdict-inputs` | POST | — | NOT_PROBED |

#### SHARED · threat intelligence  (19 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/threat-intel/config` | GET,POST | — | NOT_PROBED |
| `/api/threat-intel/enrich-batch` | POST | — | NOT_PROBED |
| `/api/threat-intel/enrich` | POST | — | NOT_PROBED |
| `/api/threat-intel/feeds/status` | GET | — | NOT_PROBED |
| `/api/threat-intel/feeds/sync` | POST | — | NOT_PROBED |
| `/api/threat-intel/iocs` | GET | — | NOT_PROBED |
| `/api/threat-intel/lookup/{value}` | GET | — | NOT_PROBED |
| `/api/threat-intel/rss/crawl` | POST | — | NOT_PROBED |
| `/api/threat-intel/rss/feeds` | GET | — | NOT_PROBED |
| `/api/threat-intel/rss/pending/promote-high-confidence` | POST | — | NOT_PROBED |
| `/api/threat-intel/rss/pending/{note_id}/dismiss` | POST | — | NOT_PROBED |
| `/api/threat-intel/rss/pending/{note_id}/promote` | POST | — | NOT_PROBED |
| `/api/threat-intel/rss/pending/{note_id}` | DELETE | — | NOT_PROBED |
| `/api/threat-intel/rss/pending` | GET | — | NOT_PROBED |
| `/api/threat-intel/rss/trending` | GET | — | NOT_PROBED |
| `/api/threat-intel/sources` | GET | — | NOT_PROBED |
| `/api/threat-intel/stats` | GET | — | NOT_PROBED |
| `/api/threat-intel/sync-all` | POST | — | NOT_PROBED |
| `/api/threat-intel/sync/{source_id}` | POST | — | NOT_PROBED |

#### SHARED · timeline  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/timeline/events/{investigation_id}` | DELETE | — | NOT_PROBED |
| `/api/timeline/events` | GET,POST | — | NOT_PROBED |
| `/api/timeline/recent` | GET | — | NOT_PROBED |

#### SHARED · v2 authoritative fabric  (67 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/v2/analyze/report` | POST | — | NOT_PROBED |
| `/api/v2/analyze` | POST | — | NOT_PROBED |
| `/api/v2/artifacts/by-sha/{sha256}` | GET | — | NOT_PROBED |
| `/api/v2/artifacts/{artifact_iid}/custody` | POST | — | NOT_PROBED |
| `/api/v2/artifacts/{artifact_iid}/link/case` | POST | — | NOT_PROBED |
| `/api/v2/artifacts/{artifact_iid}/link/entity` | POST | — | NOT_PROBED |
| `/api/v2/artifacts/{artifact_iid}/link/observation` | POST | — | NOT_PROBED |
| `/api/v2/artifacts/{artifact_iid}` | GET | — | NOT_PROBED |
| `/api/v2/artifacts` | POST | — | NOT_PROBED |
| `/api/v2/auto-investigate/jobs/{job_id}` | GET | — | NOT_PROBED |
| `/api/v2/auto-investigate/jobs` | POST | — | NOT_PROBED |
| `/api/v2/auto-investigate` | POST | — | NOT_PROBED |
| `/api/v2/cases/{case_id}/ancestry/process/{process_iid}` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/artifacts` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/investigation/explain/{pattern_id}` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/investigation` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationWorkspacePage.jsx` +1 | NOT_PROBED |
| `/api/v2/cases/{case_id}/irg` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/mitre/coverage` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/observations` | POST | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/report.bundle.zip` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/report.md` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/report.pdf` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/report.stix.json` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/report` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/trajectory/device` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/verdicts/aggregate` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}/verdicts` | GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | NOT_PROBED |
| `/api/v2/cases/{case_id}` | DELETE,GET | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationWorkspacePage.jsx` +1 | NOT_PROBED |
| `/api/v2/cases` | GET,POST | `xdr/pages/XdrEvidenceExplorerPage.jsx`, `xdr/pages/XdrInvestigationsListPage.jsx` | REACHABLE_200_DATA |
| `/api/v2/decoded-artifacts/stats/summary` | GET | `nivxforge/edrApi.js`, `xdr/components/StaticAnalysisBridge.jsx` | NOT_PROBED |
| `/api/v2/decoded-artifacts/{sha256}` | GET | `nivxforge/edrApi.js`, `xdr/components/StaticAnalysisBridge.jsx` | NOT_PROBED |
| `/api/v2/decoded-artifacts` | GET | — | NOT_PROBED |
| `/api/v2/ikb/{entry_id}` | GET | — | NOT_PROBED |
| `/api/v2/ikb` | GET | — | NOT_PROBED |
| `/api/v2/ingest/csv` | POST | — | NOT_PROBED |
| `/api/v2/ingest/evtx` | POST | — | NOT_PROBED |
| `/api/v2/ingest/json` | POST | — | NOT_PROBED |
| `/api/v2/ingest/ndjson` | POST | — | NOT_PROBED |
| `/api/v2/ingest/syslog` | POST | — | NOT_PROBED |
| `/api/v2/ingest/webhook` | POST | — | NOT_PROBED |
| `/api/v2/ingestion/formats` | GET | — | NOT_PROBED |
| `/api/v2/ingestion/golden/{dataset_id}` | POST | — | NOT_PROBED |
| `/api/v2/ingestion/golden` | GET | — | NOT_PROBED |
| `/api/v2/ingestion/upload` | POST | — | NOT_PROBED |
| `/api/v2/parse` | POST | — | NOT_PROBED |
| `/api/v2/plugins` | GET | — | NOT_PROBED |
| `/api/v2/report-writer/generate/from-model` | POST | — | NOT_PROBED |
| `/api/v2/report-writer/generate/markdown` | POST | — | NOT_PROBED |
| `/api/v2/report-writer/generate` | POST | — | NOT_PROBED |
| `/api/v2/security-state/evaluate` | POST | — | NOT_PROBED |
| `/api/v2/security-state/streaming/status` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/capabilities` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/causality` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/counterfactual` | POST | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/history` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/interventions/plan` | POST | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/interventions/stage` | POST | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/ledger` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/provenance` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/reachability` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/response/verify` | POST | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}/transitions` | GET | — | NOT_PROBED |
| `/api/v2/security-state/{case_id}` | GET | `xdr/pages/XdrInvestigationWorkspacePage.jsx` | NOT_PROBED |
| `/api/v2/validation/datasets` | GET | — | NOT_PROBED |
| `/api/v2/validation/run/{dataset_id}` | GET | — | NOT_PROBED |
| `/api/v2/validation/run` | GET | — | NOT_PROBED |
| `/api/v2/verdict/profiles` | GET | — | NOT_PROBED |

#### SHARED · verdict engine  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/verdict/stage2/auto-compute` | POST | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/verdict/stage2/compute` | POST | `components/incidents/tabs/InvestigationTab.jsx`, `xdr/adopt/baseCapabilities.js` +1 | NOT_PROBED |
| `/api/verdict/stage2/status` | GET | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |

#### UNCLASSIFIED · —  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/` | GET | — | NOT_PROBED |
| `/api/investigation` | GET,POST | — | NOT_PROBED |
| `/api/investigator/capabilities` | GET | — | NOT_PROBED |

#### XDR · MSS / control-center projection  (8 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/mss/analyst-workload` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/auto-investigation` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/customer-operations` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/detection-overview` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/kpis` | GET | `lib/incidentsApi.js`, `xdr/pages/incidents/PriorityStrip.jsx` | REACHABLE_200_DATA |
| `/api/xdr/mss/recent-activity` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/soc-queue` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |
| `/api/xdr/mss/state-distribution` | GET | `lib/incidentsApi.js` | REACHABLE_200_DATA |

#### XDR · collection + transport plane  (29 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/collector/collectors/{collector_id}` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/collectors` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/connectors/{cid}/inject` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/connectors/{cid}/start` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/connectors/{cid}/stop` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/connectors/{cid}/test` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/connectors/{cid}` | DELETE,GET,PATCH | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/connectors` | GET,POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_EMPTY |
| `/api/xdr/collector/data-sources` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_EMPTY |
| `/api/xdr/collector/ingest-preflight` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/landing` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/outbox/drain-once` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/outbox/health` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/outbox/{rid}/replay` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collector/outbox/{rid}` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/outbox` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/source-types` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/telemetry-health` | GET | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | REACHABLE_200_DATA |
| `/api/xdr/collector/webhooks/{secret_id}` | POST | `xdr/admin/IntegrationsBody.jsx`, `xdr/admin/collectorApi.js` | NOT_PROBED |
| `/api/xdr/collectors/catalog` | GET | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |
| `/api/xdr/collectors/protocols/catalog` | GET | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |
| `/api/xdr/collectors/{cid}/disable` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}/enable` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}/rotate-credential` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}/start` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}/stop` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}/test` | POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/collectors/{cid}` | DELETE,GET,PUT | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |
| `/api/xdr/collectors` | GET,POST | `xdr/admin/CollectorsBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |

#### XDR · control-center tiles  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/dashboard/tiles` | GET | `lib/incidentsApi.js`, `xdr/pages/XdrDashboardPage.jsx` | REACHABLE_200_DATA |

#### XDR · data-source control plane  (7 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/data-sources/kinds/catalog` | GET | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |
| `/api/xdr/data-sources/{ds_id}/disable` | POST | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/data-sources/{ds_id}/enable` | POST | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/data-sources/{ds_id}/rotate-credential` | POST | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/data-sources/{ds_id}/test` | POST | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/data-sources/{ds_id}` | DELETE,GET,PUT | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | NOT_PROBED |
| `/api/xdr/data-sources` | GET,POST | `xdr/admin/DataSourcesBody.jsx`, `xdr/admin/PipelineStrip.jsx` | REACHABLE_200_DATA |

#### XDR · global search  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/search/capabilities` | GET | `xdr/pages/XdrSearchPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/search` | GET | `xdr/pages/XdrSearchPage.jsx` | REACHABLE_200_DATA |

#### XDR · incident queue operations  (3 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/incidents/bulk/assign` | POST | `lib/incidentsApi.js` | NOT_PROBED |
| `/api/xdr/incidents/bulk/state` | POST | `lib/incidentsApi.js` | NOT_PROBED |
| `/api/xdr/incidents/{incident_id}/response-executions` | GET | `xdr/investigation/XdrCompletenessPanel.jsx` | REACHABLE_200_DATA |

#### XDR · investigation corpus  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/scenarios/{scenario_id}` | GET | — | NOT_PROBED |
| `/api/xdr/scenarios` | GET | — | REACHABLE_200_DATA |

#### XDR · investigation scenario match  (1 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/investigation/{incident_id}/scenario-match` | POST | `xdr/investigation/ScenarioIntelligencePanel.jsx` | NOT_PROBED |

#### XDR · queue saved views  (2 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/saved-views/{view_id}` | DELETE,GET,PUT | `lib/incidentsApi.js` | NOT_PROBED |
| `/api/xdr/saved-views` | GET,POST | `lib/incidentsApi.js` | REACHABLE_200_DATA |

#### XDR · rule authoring  (8 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/rule-studio/lanes/schemas` | GET | `xdr/pages/XdrRuleStudioPage.jsx` | NOT_PROBED |
| `/api/xdr/rule-studio/lanes/{lane}/schema` | GET | `xdr/pages/XdrRuleStudioPage.jsx`, `xdr/rule-studio/VisualConditionBuilder.jsx` +1 | NOT_PROBED |
| `/api/xdr/rule-studio/lanes` | GET | `xdr/pages/XdrRuleStudioPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/rule-studio/rules/{rule_id}/gate` | POST | `xdr/pages/XdrRuleStudioPage.jsx` | NOT_PROBED |
| `/api/xdr/rule-studio/rules/{rule_id}/promote` | POST | `xdr/pages/XdrRuleStudioPage.jsx` | NOT_PROBED |
| `/api/xdr/rule-studio/rules/{rule_id}/transition` | POST | `xdr/pages/XdrRuleStudioPage.jsx` | NOT_PROBED |
| `/api/xdr/rule-studio/rules` | GET,POST | `xdr/pages/XdrRuleStudioPage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/rule-studio/status` | GET | `xdr/pages/XdrRuleStudioPage.jsx` | REACHABLE_200_DATA |

#### XDR · vendor integration plane  (13 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/vendor/_catalog` | GET | — | REACHABLE_200_DATA |
| `/api/xdr/vendor/cortex/actions` | GET,POST | `xdr/design/CortexOnboardingWizard.jsx`, `xdr/design/RecommendationsTabV2.jsx` | REACHABLE_200_DATA |
| `/api/xdr/vendor/cortex/connections/{integration_id}/audit` | GET | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/connections/{integration_id}/ingest` | GET | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/connections/{integration_id}/poll` | POST | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/connections/{integration_id}/rotate` | POST | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/connections/{integration_id}` | DELETE,GET | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/connections` | GET,POST | `xdr/design/CortexOnboardingWizard.jsx` | REACHABLE_200_DATA |
| `/api/xdr/vendor/cortex/probe` | POST | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/cortex/webhooks/{integration_id}` | POST | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |
| `/api/xdr/vendor/{vendor_key}/connections` | GET,POST | — | REACHABLE_200_DATA |
| `/api/xdr/vendor/{vendor_key}/metadata` | GET | — | NOT_PROBED |
| `/api/xdr/vendor/{vendor_key}/probe` | POST | `xdr/design/CortexOnboardingWizard.jsx` | NOT_PROBED |

#### XDR · vulnerability exposure  (9 routes)

| Route | Methods | Product-surface consumer | Runtime verdict |
|---|---|---|---|
| `/api/xdr/cve/assets` | GET,POST | `xdr/pages/XdrExposurePage.jsx` | NOT_PROBED |
| `/api/xdr/cve/ensure-synced` | POST | `xdr/pages/XdrExposurePage.jsx` | NOT_PROBED |
| `/api/xdr/cve/exposures/compute` | POST | `xdr/pages/XdrExposurePage.jsx` | NOT_PROBED |
| `/api/xdr/cve/exposures` | GET | `xdr/pages/XdrExposurePage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/cve/list` | GET | `xdr/pages/XdrExposurePage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/cve/software` | GET,POST | `xdr/pages/XdrExposurePage.jsx` | NOT_PROBED |
| `/api/xdr/cve/status` | GET | `xdr/pages/XdrExposurePage.jsx` | REACHABLE_200_DATA |
| `/api/xdr/cve/sync` | POST | `xdr/pages/XdrExposurePage.jsx` | NOT_PROBED |
| `/api/xdr/cve/{cve_id}` | GET | `xdr/pages/XdrExposurePage.jsx` | REACHABLE_200_DATA |

### 2.4 · ADOPTED FROM THE EARLIER LINEAGE — reclassified, NOT legacy (owner rule 2)

These routes belong to the earlier malware-analysis / decoder-laboratory lineage **but a current product surface actually calls them**, so per the owner's rule they are classified by their real role — `SHARED · adopted-in-product` — and must NOT be treated as legacy or removed.

| Route | Methods | Lineage of origin | Product-surface consumer | Runtime verdict |
|---|---|---|---|---|
| `/api/analyze` | POST | single-payload analysis lab | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrDetectionRuleEditorPage.jsx` | NOT_PROBED |
| `/api/batch/history/{run_id}` | DELETE,GET,PATCH | batch payload test harness | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/history` | GET | batch payload test harness | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/test/example` | GET | batch payload test harness | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/test/json` | POST | batch payload test harness | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/test/mine/preview` | POST | batch payload test harness | `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/test/mine` | POST | batch payload test harness | `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/batch/test` | POST | batch payload test harness | `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/corpus/validate/example` | GET | corpus validation lab | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | REACHABLE_200_NON_JSON |
| `/api/corpus/validate/json` | POST | corpus validation lab | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/corpus/validate` | POST | corpus validation lab | `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/corrections/analytics` | GET | analyst-correction lab | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/corrections/pending` | GET | analyst-correction lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/corrections/preview` | POST | analyst-correction lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/corrections` | GET,POST | analyst-correction lab | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/decode/mitigations/evidence_driven` | POST | decoder guidance + mitigations lab | `xdr/adopt/baseCapabilities.js`, `xdr/intel/XdrRecommendationsPanel.jsx` +1 | NOT_PROBED |
| `/api/die/analyze` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/enginePanels.jsx` | NOT_PROBED |
| `/api/die/case/{case_id}` | GET | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/chain` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/intent` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/iocs` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/lolbas/{binary}` | GET | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/narrate` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/powershell/ast` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/die/understand` | POST | IEDDE / decoder-intelligence lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/iedde/analyze` | POST | IEDDE analyser | `xdr/adopt/baseCapabilities.js`, `xdr/adopt/enginePanels.jsx` | ROUTED_METHOD_MISMATCH_405 |
| `/api/intelligence/health` | GET | intelligence overlay lab | `xdr/components/IntelligenceControlPanel.jsx` | NOT_PROBED |
| `/api/intelligence/policy/global` | GET,PUT | intelligence overlay lab | `xdr/components/IntelligenceControlPanel.jsx` | NOT_PROBED |
| `/api/intelligence/policy/incident/{incident_id}/effective` | GET | intelligence overlay lab | `xdr/components/IntelligenceControlPanel.jsx` | NOT_PROBED |
| `/api/intelligence/policy/incident/{incident_id}` | DELETE,GET,PUT | intelligence overlay lab | `xdr/components/IntelligenceControlPanel.jsx` | NOT_PROBED |
| `/api/planner/advise` | POST | planner lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/planner/trace` | POST | planner lab | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/corpus/entries/{entry_id}` | DELETE | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/corpus/entries` | GET,POST | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/gate` | GET | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/history` | GET | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/latest` | GET | regression harness | `xdr/adopt/baseCapabilities.js`, `xdr/pages/XdrRuleTuningPage.jsx` | NOT_PROBED |
| `/api/regression/run` | POST | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |
| `/api/regression/runs/{run_id}` | GET | regression harness | `xdr/adopt/baseCapabilities.js` | NOT_PROBED |

**39 adopted routes.** The dominant consumers are `xdr/pages/XdrRuleTuningPage.jsx` (regression · batch · corpus harness), `xdr/adopt/baseCapabilities.js` + `xdr/adopt/enginePanels.jsx` (the adopt-before-invent panels), `xdr/intel/XdrRecommendationsPanel.jsx` (`/api/decode/mitigations/evidence_driven`) and `xdr/components/IntelligenceControlPanel.jsx` (`/api/intelligence/policy/*`).

### 2.5 · LEGACY LINEAGE — module/lineage level (owner decision 2A, NOT endpoint-by-endpoint)

Every route below has **no** product-surface consumer in either shell.

| Lineage prefix | Routes | Lineage | Owner | Action |
|---|---|---|---|---|
| `/api/rc5/*` | 19 | RC5 semantic-engine sprint | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/decode/*` | 16 | decoder guidance + mitigations lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/learner/*` | 16 | learner lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/die/*` | 12 | IEDDE / decoder-intelligence lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/deck/*` | 9 | pitch-deck download | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/nivxforge/*` | 9 | older investigation/CIO lineage (name collision: NOT the EDR backend) | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/audit/*` | 8 | audit download lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/documents/*` | 8 | document workspace lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/lab/*` | 8 | gamified decoder lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/training/*` | 8 | training lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/analyze/*` | 7 | single-payload analysis lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/benchmark/*` | 6 | benchmark harness | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/corrections/*` | 6 | analyst-correction lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/files/*` | 6 | file upload lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/history/*` | 6 | run history lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/learning/*` | 6 | learning lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/ai/*` | 5 | AI assistant lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/threat-model/*` | 3 | threat-model lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/artifacts/*` | 2 | artifact lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/emit/*` | 2 | emit lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/learning-engine/*` | 2 | learning engine lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/lolbas/*` | 2 | LOLBAS export lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/moe/*` | 2 | mixture-of-experts panel | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/share/*` | 2 | share lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/batch/*` | 1 | batch payload test harness | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/examples/*` | 1 | sample library | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/intelligence/*` | 1 | intelligence overlay lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/metrics/*` | 1 | metrics lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/operations/*` | 1 | operations lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/osint/*` | 1 | OSINT lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/recipe/*` | 1 | recipe lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/system/*` | 1 | system lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/troubleshoot/*` | 1 | troubleshoot engine | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/understand/*` | 1 | understanding lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |
| `/api/upload/*` | 1 | upload lab | LEGACY-DUPLICATE / OUT-OF-PRODUCT | do not wire |

**Legacy lineage total: 181 routes** across 35 lineages, of 775 registered routes.

---

## 3 · MATRIX 3 — MISSING / BLOCKED

Split strictly into **BLOCKED** (implementation or design exists, an external
dependency is required) and **MISSING** (no implementation exists). Nothing
here may be filled with fabricated telemetry, detections, metrics or
observables.

### 3.1 · BLOCKED — dependency named, never fabricated

| # | Capability | Owner | Dependency | Status |
|---|---|---|---|---|
| B-1 | Multi-source XDR correlation across a **second telemetry domain** (DNS / network / identity / email) | XDR | a real second telemetry domain. **Note from this audit**: a real syslog/CEF-LEEF collector *is* running and has delivered 35 envelopes (F-4) — the blocker may be closer than recorded, but the console currently sees none of it, so nothing is claimed | `BLOCKED · REAL_SECOND_TELEMETRY_DOMAIN_REQUIRED` (`G-16 / FLOW-5`) |
| B-2 | Endpoint isolation / release containment proof | EDR | `CAP_NET_ADMIN` on a privileged host (`CapEff 00000000a80405fb` here); `scripts/p0_f10_isolation_proof.py` must pass on a VM or `--cap-add=NET_ADMIN` | `BLOCKED` — capped at BACKEND_IMPLEMENTED, `CAPABILITY_UNAVAILABLE` in-console |
| B-3 | Fleet File Trajectory content | EDR | `artefacts.file[].sha256` / name are unpopulated by the sensor (`G-4`) — surface exists, evidence is starved | `BLOCKED` (data) |
| B-4 | Process **exit** observation · file **writer** attribution · sub-poll-interval execution | EDR | eBPF (the sensor polls `/proc`; polling cannot distinguish exit from a missed scan) | `BLOCKED` — declared visibility gap |
| B-5 | Endpoint network + DNS telemetry (`/edr/network`) | EDR | Linux sensor collects no network/DNS | `BLOCKED` |
| B-6 | Registry · USB · memory · services · persistence telemetry | EDR | not available on Linux; requires the Windows agent | `BLOCKED` |
| B-7 | Windows agent | EDR | not implemented (`P0-I`) | `NOT_IMPLEMENTED` |
| B-8 | Reference columns `Vulnerabilities` · `Security Risk Score` · `Managed` · multi-vendor `Sources` | XDR | no collector in this build; layout parity achievable, content parity is not | `BLOCKED` (content) |
| B-9 | 52 store rules that cannot fire (`STORE_CONTENT_INCOMPLETE`: 39 declare no logsource, 13 carry no detection block) + 23 `LICENSE_BLOCKED` + 22 `NO_TELEMETRY` — **0 of 98 authored rules are `BOUND`** | SHARED | rule **content** authoring, not engine work | `BLOCKED` (content) |
| B-10 | Cisco parity on 10+ unseen surfaces | both | owner-supplied reference captures | `REFERENCE_CAPTURE_REQUIRED` — see `MASTER_PARITY_MATRIX.md` |

### 3.2 · MISSING — no implementation exists

| # | Capability | Owner | Note |
|---|---|---|---|
| M-1 | Incident-scoped **notes** API (`/api/incidents/:id/notes`) | XDR | UI declares it reserved; drafts are browser-local |
| M-2 | Cross-incident **related** projection (`/api/xdr/incidents/:id/related`) | XDR | UI declares it reserved (Phase 4) |
| M-3 | **Extension registry** API (`/api/xdr/extensions`) | XDR | Capability Hub reads a client-side registry only |
| M-4 | EDR **Threat Hunting** free-form telemetry search | EDR | reserved stub |
| M-5 | EDR **Forensics** snapshot / targeted collection | EDR | reserved stub |
| M-6 | EDR **Live Query** with approval workflow | EDR | reserved stub |
| M-7 | Casebook / analyst ribbon (Y3.2 · V-5 · N-5) | XDR | **must project onto existing `workspace_cases`/worklog — no second case engine** |
| M-8 | Incidents **preview drawer** (Y3.3 · V-18 · I-10) | XDR | list-context-preserving slide-out |
| M-9 | Control Center **customisable tile grid** (Y3.4 · V-20 · I-12 · I-13) | XDR | tile framework; `XdrDashboardPage` is the existing starting point (F-7) |
| M-10 | `Edit Labels` · `Rules` · `Download CSV` on device inventory | EDR/XDR | no backend |
| M-11 | Approval step + response **policy** in the endpoint response plane | EDR | `Approved by` / `Policy` correctly render `⊘` with a reason today |
| M-12 | `response_to_incident_binding` — responses are correlated by endpoint+time, never incident-keyed | EDR | disclosed gap |
| M-13 | Canonical-id scheme divergence (`cev_raw_<hex>_pl` vs `cev_<hex>_0`) | SHARED | both ids shown side by side rather than hidden — real defect, unfixed |
| M-14 | `raw.sha256` in the CES projection (`v2/ingestion/canonical.py:326`) is a digest of the event key, **not** a file hash | SHARED | evidence-integrity naming defect, tracked separately |

### 3.3 · Open defects carried into this audit (not fixed here)

| # | Defect | Status |
|---|---|---|
| D-a | `tests/edr/test_p0_f4_endpoint_process_tree.py` — **3 failures**, reproduced on a clean tree | pre-existing |
| D-b | `device_identity.list_devices()` filters tenants **in memory**, not in the Mongo predicate | tech debt |
| D-c | The running standalone collector reports **0 connectors** via its own API while `.state/connectors.json` records 1 enabled syslog connector | new — found in this audit |
| D-d | `/api/xdr/spread` and `/api/xdr/spread/signals` return **HTTP 400** to an authenticated cross-tenant admin | new — found in this audit |

---

## 4 · ORPHAN ENGINE / SERVICE WIRING WORKLIST
### FOR REVIEW AND APPROVAL ONLY — NOTHING WILL BE WIRED WITHOUT YOUR SIGN-OFF

| P | Component | Owner | Existing capability | Current runtime | Required product | Dependency | What must be wired | Risk | Status |
|---|---|---|---|---|---|---|---|---|---|
| **P0** | `services/edr/device_identity` alias resolution on the **process-tree** and **endpoint-detections** query paths | EDR | proven ancestry (54 nodes / 49 observed / 5 ghost roots) + 10 detections / 971 events evaluated on the same endpoint | resolves the alias, then queries the raw string → empty | NivXForge EDR | none | apply the already-resolved alias set to the Mongo predicate, as the trajectory path already does | **low** code risk, **high** correctness value — today the console asserts "no matching evidence" where evidence exists | ORPHAN (mis-wired) → wire |
| **P0** | `EdrOverviewPage` capability flags + Device Trajectory target | EDR | Detections + Process Tree pages already implemented and routed | hardcoded `available: false`, links to legacy `/edr/trajectory` | NivXForge EDR | P0 above (else the cards open empty pages) | derive availability from the capability registry / a real probe instead of a literal; point at `/edr/device-trajectory` | low | ORPHAN → wire |
| **P1** | `apps/nivxray-xdr-response` (Response Engine) | **XDR** | registry · adapters · vendor adapters · executor · execution store · approvals · evidence forwarder | **not running**, `VITE_XDR_RESPONSE_URL` unset, base sink already holds 231 executions | NivXRay XDR (`/xdr/respond/*`) | supervisor program + env var + decision on whether it stays a separate deployable or is *landed* like the collector | deploy or land it; then bind Playbooks · Automation Rules · Approvals · Execute to it instead of browser-local stores | **medium** — it executes actions; approval + audit must be proven before any execute path is exposed | ORPHAN → wire (**owner decision needed: separate service vs landed**) |
| **P1** | Collector runtime reconciliation (`apps/nivxray-xdr-collector` ⇄ `routers/xdr_collector_landing`) | XDR | one code path, **two** state dirs and two outboxes | standalone :8055 running with 35 delivered / 3 dead-letter / 1 syslog connector; landed one reports `not_configured` / 0 | NivXRay XDR (Integration Control Center) | decide the single authoritative runtime + state dir | make the console read the runtime that actually collects, or point both at one `XDR_STATE_DIR`; reconcile with the native `xdr_collectors`/`xdr_data_sources` Mongo registry (**two registries, one concept**) | **medium** — this is the ingest boundary; a wrong merge could duplicate or drop envelopes | ORPHAN + DUPLICATE → decide, then wire |
| **P1** | Endpoint **Response** surface relocation | EDR | `REAL_ENDPOINT_VALIDATED` response-evidence UI (`EdrResponseBody.jsx`) + 41 KB of real command records | lives at `/xdr/admin/edr-response`; `/edr/response` is a stub | NivXForge EDR | none | project the existing surface into the EDR product (**reuse the component, do not re-implement**); keep an XDR admin view if the owner wants both | low | ORPHAN + ownership → wire |
| **P2** | `xdr/adopt/baseCapabilities.js` consumer paths (4 wrong routes) | XDR | verdict stage-2 · IOC intelligence · behaviour registry · mitigations — all reachable | consumers 404 → UI says "adapter not connected" | NivXRay XDR | none | correct the paths to the live routes (`/api/verdict/stage2/compute`, `/api/ioc/enrich`, `/api/behaviors/registry`, `/api/decode/mitigations/*`) | very low | ORPHAN by wrong path → wire |
| **P2** | `XdrDashboardPage` + `/api/xdr/dashboard/tiles` | XDR | implemented tile page, reachable API with real data | imported, **never routed** | NivXRay XDR (Control Center) | Y3.4 tile-framework decision | mount it, or fold it into the Y3.4 Control Center so the work is not duplicated | low | ORPHAN → wire (**sequence with Y3.4**) |
| **P2** | `/api/xdr/spread/*` (indicator spread + sightings) | SHARED | 5 routes, 181 watchlist + 421 sighting records | reachable, **zero** consumers; 2 routes return 400 | XDR (fleet spread) — the EDR trajectory already has a fleet-spread pivot | fix D-d first | give it a surface, or explicitly retire it; do **not** build a second spread engine for Y4 Fleet File Trajectory | low | ORPHAN → decide |
| **P3** | EDR administration relocation (`edr-enrollment` · `edr-response` · `edr-capability-truth`) | EDR | three working admin surfaces | hosted in the XDR admin console | NivXForge EDR | product-separation decision | expose them in the EDR product; keep or drop the XDR mirrors per owner | low | ownership → decide |
| **P3** | `/edr/*` unauthenticated deep link renders the **XDR** login | EDR | both logins exist | product identity leaks on session expiry | NivXForge EDR | none | make `Protected` product-aware | low | defect → wire |
| **—** | `backend/nivxforge/` · `l1_evidence` · `l2_investigation` · `workspace` · `reasoning` | LEGACY | duplicate investigation/CIO/verdict lineage | registered and partially imported by production paths | **none** | — | **DO NOT WIRE.** Superseded by `v2`/`edr_plane`. **DO NOT DELETE** — live imports exist | low | `LEGACY-DUPLICATE`, retained |
| **—** | `decoders` · `rc5_*` · `lab` · `finetune` · `die` · `learner` · `training` · `deck` · `documents` · `lolbas-export` … (**181 routes / 35 lineages, none with a product consumer**) | LEGACY | earlier malware-analysis / decoder-laboratory lineage | registered and reachable | **none** | — | **DO NOT WIRE.** *"Earlier malware-analysis/decoder laboratory lineage superseded by the current NivXRay evidence-first XDR/investigation architecture and not a required XDR/EDR product runtime."* | — | `LEGACY-DUPLICATE / OUT-OF-PRODUCT` |

### Duplicates that must NEVER be created
Detection engine · verdict engine · case engine (`workspace_cases` is the
only one) · incident store · evidence store · observation store · trajectory
renderer · correlation engine · collector framework · response state
machine · auth engine.

---

## 5 · STOP

The audit is complete for the ordered stages
`AUDIT → CLASSIFY → IDENTIFY LEGACY → IDENTIFY ORPHANS → IDENTIFY SHARED
ENGINES → IDENTIFY TRUE MISSING CAPABILITIES → BUILD PRIORITISED WIRING
WORKLIST`.

**Stopping here for approval.** No wiring, no route change, no ownership
change, no deletion, no new engine, no new API, no detection/response/UI
change was made. The regression gates were not re-run because nothing was
modified: `X1–X3/Y2 22/22` · `P0-F.13.5 25/25` · `Detection Attribution
12/12` · `tests/edr 330 pass (3 known pre-existing)` remain as recorded.

Companion document: **`/app/memory/MASTER_PARITY_MATRIX.md`** (MATRIX 1 —
Cisco XDR and Cisco Secure Endpoint/AMP observable parity).
