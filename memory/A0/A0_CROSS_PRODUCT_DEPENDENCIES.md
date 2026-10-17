# A0_CROSS_PRODUCT_DEPENDENCIES

Mode: READ-ONLY. Nothing was changed. Every row cites a file and line.

## Headline

**The coupling is asymmetric.** EDR barely depends on XDR; XDR depends on the
EDR plane for its endpoint telemetry. Any plan that treats the split as
symmetric will fail.

- EDR → XDR: **one** functional import across all 16 EDR routers.
- XDR → EDR: direct collection reads in three modules plus a shared query
  helper used by six.

## 1 · XDR → EDR (the load-bearing direction)

| Source file/function | Target | Why used | Risk if removed | Existing tests | Proposed boundary |
|---|---|---|---|---|---|
| `routers/xdr_search.py:31` `from services.edr import device_identity` | EDR identity plane | resolve device → endpoint identity in hunting | hunting cannot name endpoints | `test_xdr_search*`, `test_b8_scope_authorized_tenants_contract.py` | `GET /edr/v1/endpoints/resolve` |
| `routers/xdr_search.py:32` `endpoint_predicate` | EDR endpoint query contract | builds tenant-scoped endpoint filters | **tenant scoping of endpoint queries is lost** — security-relevant | same | contract must carry tenant scope explicitly |
| `routers/xdr_search.py:148,156` `sync_collection("edr_raw_events").find(...)` | `edr_raw_events` | raw event lookup behind search results | hunting returns no raw evidence | `test_xdr_search*` | `POST /edr/v1/raw-events/query` |
| `routers/xdr_search.py:305-328` | `edr_endpoints/v2_shadow_observations`, `edr_raw_events.derivations[DETECTION_MATCHED]` | detections surfaced in XDR search | detection pivots disappear | — | detections contract |
| `routers/xdr_search.py:133,179,229,239,260` | `/edr/device-trajectory`, `/edr/process-tree`, `/edr/network` hrefs | cross-product pivot links | links break once origins split | `productOrigins.js` unit tests | must resolve through `productHref()` |
| `services/incident_provenance.py:19,142,144` `RAW = "edr_raw_events"`, `db_sync[RAW].find_one(...)` | `edr_raw_events` | trace an incident back to its raw observation | **evidence provenance chain breaks** | `test_d11_ingest_provenance.py`, `test_xdr_round23_5_provenance_lockin.py` | provenance contract returning raw-row attestation |
| `services/evidence_bridge.py:46,99` `OBSERVATION_COLLECTION = "v2_shadow_observations"` | EDR observations | observation → evidence bridge | evidence cannot cite observations | `test_provenance_graph_and_adapter_contract.py` | observation contract |
| `services/evidence_bridge.py:5,108` | documented join `edr_raw_events.raw_id ↔ xdr_canonical_events._id` | canonical join key | the join that makes XDR evidence verifiable | same | key must be preserved across any API boundary |
| `detection_content/xdr_edr_adapter.py` (used by `routers/xdr_cortex_wizard.py:47`) | EDR detection content | maps EDR content into XDR | content mapping lost | `test_xdr_content_pipeline.py` | versioned content adapter |
| `routers/xdr_collectors.py:180` | `"edr"` protocol entry, `implementation: SCAFFOLD` | third-party EDR source type | — | `test_xdr_data_sources_collectors.py` | this is where third-party EDR ingest belongs |

### Conceptual-only (no database access) — do not over-report these

| File | Evidence | Reality |
|---|---|---|
| `services/entity_resolution.py:5,196` | mentions `edr_plane` contracts and `edr_endpoints.endpoint_id` in docstrings; **`grep "sync_collection\|db\["` returns nothing** | documentation + contract alignment only |
| `services/session_context.py:24,30` | reads `workspace_cases`; EDR text is a tenant cross-check note | no EDR read |

### Shared helper, pulled in by both planes

`services/edr/endpoint_query.py` (`endpoint_predicate`, `ENDPOINT_KEYED_STORES`)
is imported by `routers/xdr_search.py`, `edr_plane/response.py:30`,
`edr_plane/detection_replay.py:59`, `edr_plane/trajectory_window.py:41`,
`edr_plane/canonical_index_contract.py:36`,
`edr_trajectory/production_adapter.py:48`. It encodes **tenant-scoped endpoint
predicates**, so it is simultaneously the most reused helper and a security
control. It must not be duplicated into two drifting copies.

## 2 · EDR → XDR (thin)

| Source | Target | Why | Risk if removed | Tests | Proposed boundary |
|---|---|---|---|---|---|
| `routers/edr_session.py:31` `from routers.xdr_audit_log import emit_audit`; `:44` `sync_collection("xdr_audit_log")`; `:74` | `xdr_audit_log` | EDR session events land on the append-only, signed audit chain | **audit continuity lost** — a release blocker, not a nicety | `test_xdr_round41_timeline_replay.py`, webhook audit-chain tests | shared audit service, or per-product chain with a verifiable linkage |

Import census across all 16 EDR routers (`grep -hoE "^from ... import"`):
`deps` 16, `routers.edr_tenancy` 14, `edr_plane` 12, `edr_plane.enrollment` 10,
`services.edr` 9, `services.dashboard_lenses` 2 — and `routers.xdr_audit_log` 1.

## 3 · Shared platform dependencies (all three products)

| Dependency | Evidence | Consequence for separation |
|---|---|---|
| One FastAPI process | `server.py`, 173 `include_router` | split requires either a profile switch or separate apps |
| One MongoDB `DB_NAME` | `deps.py`, all collection access | separate databases break the XDR↔EDR joins above |
| One `users` collection / one JWT | `routers/auth.py`, `users` referenced 7× | separate products otherwise mean separate account universes |
| Tenancy in two places | `routers/xdr_rbac.py` + `routers/edr_tenancy.py` | contracts must stay aligned or tenant isolation drifts (A0.5 locks this) |
| One audit chain | `xdr_audit_log` used by XDR, EDR and webhooks | see EDR → XDR above |
| Response boundary | `routers/xdr_respond_boundary.py` → `apps/nivxray-xdr-response` | **already a clean, credential-separated service boundary — use it as the template** |

## 4 · NivXMachines coupling

| Coupling | Evidence | Separation cost |
|---|---|---|
| API namespace | `/analyze`, `/decode`, `/die`, `/ai`, `/cases`, `/batch`, `/behavioral`, `/documents`, `/benchmark`, `/corrections` — **disjoint** from `/api/xdr/*` and `/edr/*` | none |
| Frontend | `frontend/` is a separate codebase, byte-identical to `/app/frontend`; deliberately unmerged (owner decision 2026-09-08) | none |
| Console reference | `components/WorkspaceLaunch.jsx` degrades to `NOT_CONFIGURED` when `REACT_APP_WORKSPACE_URL` is unset | none |
| Backend process + DB + `users` | shares `server.py`, `DB_NAME`, auth | the only real work |
| Shared collections | `workspace_cases` is read by `services/session_context.py:24` and `services/evidence_bridge.py:262` — **XDR investigation reads Workspace cases** | must be contracted or re-owned |

> `workspace_cases` is the one genuine XDR ↔ NivXMachines data coupling, and it
> is easy to miss because the name does not look product-owned.

## 5 · Dependency-removal order implied by the evidence

1. NivXMachines — process/DB/identity only, no cross-plane joins except
   `workspace_cases`.
2. EDR standalone — one audit import to contract.
3. XDR without EDR — three collection reads plus the shared tenant-scoped
   query helper and the provenance join. **This is the real work.**

No dependency was modified in this task.
