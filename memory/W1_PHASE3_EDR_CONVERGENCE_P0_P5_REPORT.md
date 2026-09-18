# P0–P5 · EDR TENANT CONVERGENCE — IMPLEMENTATION REPORT (candidate/preview only)

Implemented on candidate/preview. **No production republish. No production data
mutation. No W1 collector, API key, endpoint, token or Sysmon telemetry. W1
Phase 3 remains paused.** Candidate `HEAD e7195597` (pre-commit; the platform
commits per step).

Preview backend restarted and healthy: `GET /api/health → 200`.
Production untouched: still `publish 100 / build 8833215`.

---

## 1 · EXACT FILES CHANGED

```
 backend/routers/edr_tenancy.py                          NEW  (P0 · the authority)
 backend/tests/test_edr_route_tenant_authority.py        NEW  (P5 · R4 gate)
 backend/routers/edr.py                                  155 +/-
 backend/routers/edr_response.py                          54 +/-
 backend/routers/edr_wave0.py                             13 +/-
 backend/services/edr/file_trajectory.py                  36 +/-
 backend/services/session_context.py                      22 +/-
 backend/services/dashboard_lenses.py                     10 +/-
 backend/tests/edr/test_iter107_p0_3_freshness_review.py    9 +/-  (conformance)
 backend/tests/edr/test_p0_f10_live_api.py                  4 +/-  (conformance)
 backend/tests/edr/test_p0_f6_response_ui_backend.py        4 +/-  (conformance)
 backend/tests/edr/test_p0_f7_live_api.py                   4 +/-  (conformance)
 backend/tests/edr/test_wave0_api_smoke.py                  4 +/-  (conformance)
 backend/tests/edr/test_iteration_82_activation.py          3 +/-  (conformance)
 backend/tests/edr/test_p0_f13_5_detection_handoff.py       3 +/-  (conformance)
```
Test edits are **header conformance only** — each adds `X-Tenant-Id` to the
already-existing auth fixture. **No assertion was rewritten, relaxed, skipped
or deleted anywhere.**

### P0 · `routers/edr_tenancy.py`
- `edr_tenant(request)` — FastAPI dependency. `X-Tenant-Id` →
  `tenant_registry.authoritative(..., purpose="edr.control_plane")`.
  Missing → `TENANT_REQUIRED`; unregistered → `TENANT_NOT_FOUND`; non-ACTIVE →
  `TENANT_NOT_ACTIVE`. No new authority: the same call `edr_enrollment._tenant`
  already made.
- `sensor_tenant(tenant_id)` — SENSOR_SCOPED. Validates the tenant carried by
  the authenticated endpoint session. **Reads no header.**
- `edr_scope(tenant_id, user)` — intersects the resolved tenant with
  `resolve_tenant_scope(email)`. Returns the SAME scope shape every EDR query
  site already consumes, with `all_tenants=False, tenant_ids=[T]`. A
  cross-tenant principal naming `T` is scoped to `T`; a scoped principal naming
  a tenant it does not hold gets `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`.
  **Narrows only.**
- `ROUTE_CLASSIFICATION` — the §2 table as data, consumed by the R4 gate.

### P1 · `routers/edr_response.py` (write/response plane first)
Five analyst routes moved off `user.get("tenant_id") or "default"` onto
`Depends(edr_tenant)`. Three agent routes wrapped in `sensor_tenant(...)`.
`_canonical_endpoint_id` now receives the resolved tenant and
`edr_scope(...)` instead of the raw principal scope.

### P2 · `routers/edr.py` + `services/edr/device_identity.py`
- `_case_scope(user, tenant_id)` and `_is_cross_tenant` → renamed
  `_tenant_scope(user, tenant_id)`; both delegate to `edr_scope`.
- **`device_identity.py` needed NO change for R2.** `list_devices` already
  drops `UNATTRIBUTED_LEGACY_OBSERVATION` / `TENANT_CONFLICT_FAILED_CLOSED` /
  `TENANT_MISMATCH_FAILED_CLOSED` whenever `all_tenants` is False. Because
  `edr_scope` always returns `all_tenants=False`, R2 falls out of the existing
  attribution logic. `_attribute()` is untouched — it was already correct.

### P3 · remaining `edr.py` routes
- `_load(incident_id, tenant_id)` — incident lookup is tenant-partitioned;
  another tenant's incident returns the same `incident_not_found` as a
  non-existent id (existence is not disclosed).
- `file_trajectory.py` — `fleet_trajectory(..., tenant_id)` and
  `spread_index(tenant_id)` read the substrate within the tenant, plus a
  `tenant_scope` disclosure block stating why an unattributed substrate
  legitimately answers zero.
- `session_context.tenant_context(..., explicit_tenant)` — narrows the
  reported scope and the customer list; adds `basis=EXPLICIT_REQUEST_TENANT`.
- `edr.py:548` `"default"` retired.

### P4 · `routers/edr_wave0.py`
`_tenant()` (`users["customer"] or "default"`) **deleted**. `/raw-events/stats`
and `/raw-events/replay-candidates` use `Depends(edr_tenant)`. The eight
PRODUCT_METADATA routes are unchanged and keep `get_current_user` only.
**No router-level dependency was added anywhere.**

### P5 · gate + R5
`tests/test_edr_route_tenant_authority.py` (new). `dashboard_lenses.py:183` —
a user holding neither `tenant_ids` nor `tenant_id` now gets an **empty**
tenant list instead of `["default"]`.

---

## 2 · ROUTE CLASSIFICATION AFTER IMPLEMENTATION

Verified against the live route table by
`test_every_live_edr_operation_is_explicitly_classified` (passing).

```
TENANT_SCOPED      21   explicit X-Tenant-Id -> registry
SENSOR_SCOPED       3   tenant from the authenticated endpoint session
PRODUCT_METADATA    8   tenant-independent product truth
------------------ ---
subtotal (approved) 32
+ SENSOR_SCOPED      5   pre-existing agent surface: enroll, session,
                         heartbeat, telemetry, whoami
+ TENANT_SCOPED      5   pre-existing edr_enrollment admin plane (already
                         B5-converged; now classified so the gate covers it)
+ PRODUCT_METADATA   1   /api/edr/enrollment/rejections (global alarm feed)
================== ===
TOTAL CLASSIFIED    43   = every live /api/edr operation
```
The 32 you approved are unchanged. The extra 11 are operations that already
existed and already had correct authority; classifying them was required
because the completeness clause fails on **any** unclassified `/api/edr`
operation. No behaviour was changed on those 11.

---

## 3 · TEST COUNTS AND RESULTS

Every number below is `pytest` on this candidate against preview.

| suite | before | after | delta |
|---|---|---|---|
| **`tests/test_edr_route_tenant_authority.py`** (new R4 gate) | — | **152 passed / 0 failed** | new |
| `tests/edr/` (30 files) | 348 passed / 23 failed | 339 passed / 32 failed | **+9 new**, all stale-by-design (§7) |
| tenant / RBAC / audit / response / isolation core set (14 files) | 163 passed / 48 failed+errors | 163 passed / 48 failed+errors | **0 regression — identical lists** |
| `tests/test_b4b5_tenant_registry_authority.py` | 29 passed / 1 failed | 29 passed / 1 failed | 0 regression |

The core-set comparison was produced by stashing the change, restarting the
backend, re-running, and diffing the sorted FAILED/ERROR lists. `comm` returns
**empty in both directions** — no test that passed before fails now, in the
whole tenant/RBAC/audit/response/isolation surface.

`test_b4b5_...::test_b3_ingest_actor_is_never_the_client_claim` — pre-existing
and **not caused by this work**: it drives `ten_x`, pins no enforcement
fixture, and `backend/.env` carries `NIVX_TENANT_REGISTRY_ENFORCE=true` from
the preview rehearsal. `NIVX_TENANT_REGISTRY_ENFORCE=false pytest -k
b3_ingest_actor` → **1 passed**. Verified with the change stashed: still fails.
One-line hermetic fix (add the existing `relaxed` fixture) identified but
**not applied** — out of approved scope and unrelated.

---

## 4 · PROOF GATE H IS FIXED (candidate/preview, live)

`GET /api/edr/endpoints`, authenticated cross-tenant admin:

| `X-Tenant-Id` | HTTP | code |
|---|---|---|
| *absent* | **403** | `TENANT_REQUIRED` — "there is no default tenant" |
| `ten_does_not_exist` | **403** | `TENANT_NOT_FOUND` |
| `ten_813aa316…` (ARCHIVED) | **403** | `TENANT_NOT_ACTIVE` — `state 'ARCHIVED'` |
| `default` (registered · ACTIVE) | **200** | rows, `d21-default`, attributed |

Compare with production today: 200 with no header, and 200 with a header that
was never read.

The gate also proves the header **cannot be silently ignored**, per route:
`test_supplied_tenant_changes_the_outcome` asserts three DIFFERENT bodies for
valid / absent / unknown tenant across all 19 readable TENANT_SCOPED
operations. That is the assertion whose absence let Gate H ship.

**R2 proof** — `test_endpoints_projection_is_confined_to_the_named_tenant`:
every returned row must satisfy `tenant_attribution.startswith("ATTRIBUTED")`
**and** `tenant_id == <named tenant>`. An `ENG-42`-shaped unowned row under an
explicit tenant now fails the suite. Passing.

---

## 5 · PROOF SENSOR_SCOPED STILL WORKS WITHOUT AN ANALYST HEADER

`test_sensor_routes_do_not_demand_an_analyst_tenant_header` — all 8 agent
operations, called with no `X-Tenant-Id`: asserts the returned code is
**never** `TENANT_REQUIRED`, and the refusal is the sensor-credential refusal
(401/403/422). Passing for all 8.

Enrolment/telemetry suites green: `test_p0_a2_enrollment.py`,
`test_p0_f5_response_identity.py`, `test_p0_f10_isolation.py` — 97 passed, 4
failed, and all 4 failures are in `test_p0_a2_adversarial_live.py` and appear
verbatim in the pre-change baseline.

---

## 6 · PROOF PRODUCT_METADATA REMAINS TENANT-INDEPENDENT

`test_product_metadata_needs_no_tenant_and_carries_none` — for each of the 9
PRODUCT_METADATA operations: no header must not yield `TENANT_REQUIRED`, and
the response body must be **byte-identical** with no header, with tenant A,
and with tenant B. If any metadata route ever varies by tenant it is tenant
data and the test says so. Passing. `test_product_metadata_still_requires_
authentication` confirms anonymous is still 401/403.

**Response semantics unchanged.** Only the tenant argument changed. Approval
(`resp.request_action`), permission, `command_id` idempotency, audit records,
`AuthenticatedEndpoint` service authentication and `resp.verify` as the sole
path to VERIFIED are untouched, and `test_p0_f6_response_ui_backend.py`
(shape, id lookup, endpoint filter, verified-command proof) plus
`test_p0_f10_live_api.py` (policy read, versioned write, missing
verification_target refusal) are **green after adding only the header**.
`ACCEPTED != EXECUTED != CONTAINED != VERIFIED` holds. The R4 gate never
drives a POST/PUT with a valid tenant, so the suite creates no command, no
policy, no token and no endpoint.

---

## 7 · CALLERS NOW BROKEN BY OMITTING EXPLICIT TENANT CONTEXT

### 7a · FRONTEND — real, not fixed, NOT authorized in P0–P5
`apps/nivxray-xdr/src/nivxforge/edrApi.js` is the NivXForge EDR console client
and sends **no** `X-Tenant-Id` (e.g. `api.get("/edr/endpoints")` line 54;
`/edr/detections`, `/edr/endpoint-detections`, `/edr/process-tree`,
`/edr/telemetry/freshness` likewise). Every EDR console surface that consumes
it will return **403 TENANT_REQUIRED** until the client attaches the selected
tenant. The XDR admin components already do this correctly
(`CollectorsBody.jsx`, `ApiKeysBody.jsx`, `collectorApi.js`).

Affected surfaces: EDR Overview, Detections, Process Tree, Device Trajectory,
Endpoints, Telemetry Freshness, Linked XDR Incidents, Campaign Story,
Response. Plus the previously-reported hardcoded `tenant_id=default` in
`XdrInvestigationWorkspacePage.jsx:179` and `SecurityStateTab.jsx:48-54`.

**No frontend file was touched.** This needs its own owner authorisation.

### 7b · TESTS — 9 stale-by-design assertions, deliberately left RED
Not weakened, not rewritten. Each is now asserting the OLD contract.

- `test_iteration_82_activation.py` — 7 tests expect
  `{WKS-01, FILE-SRV-01, SRV-DC01, FIN-07, ENG-42, HR-11, WKS-07}` from
  `/api/edr/endpoints`. Those 7 hosts are `UNATTRIBUTED_LEGACY_OBSERVATION`,
  so under an explicit tenant they are correctly withheld. **This is R2
  working**, and it is the same host family as the production `ENG-42` finding.
  Options: point the test at a tenant that actually owns endpoints, or assert
  the unattributed set only via the cross-tenant path. **Owner decision.**
- `test_iter107_...::TestWindowHonesty::test_evidence_outside_window` — same
  cause.
- `test_p0_f13_5::test_unresolvable_endpoint_fails_closed` — calls the handler
  directly with a synthetic principal `a@b.c` that has no `users` record.
  Under R5 that principal now holds **no** tenant, so naming `default` is
  refused `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`. Previously the `["default"]`
  fallback let it through. **This is R5 working.** Fix is to give the fixture a
  real principal. **Owner decision.**

These 9 are the honest cost of the contract. I did not make them pass.

---

## 8 · MIGRATION — NONE PERFORMED, NONE REQUIRED

- `"default"`-keyed `edr_commands` and `isolation_policy` documents:
  **preserved byte-for-byte as historical evidence.** No migration,
  relabelling, adoption, deletion, and they are **not reachable** through the
  new authoritative tenant path.
- Canonical evidence, `v2_shadow_observations` (incl. `ENG-42`), detection
  logic, response execution semantics, `ten_*`/`org_*` ids, `ep_*` /
  `edr_endpoints`, `edr_raw_events`, API keys, collectors, enrolment tokens:
  **unchanged.** R2 is a read-time filter.
- OpenAPI path count **795 → 795**: no route added, removed or renamed.

## 9 · INVARIANTS, EACH WITH ITS ASSERTION

| invariant | proven by |
|---|---|
| missing explicit tenant → `TENANT_REQUIRED` | `test_missing_explicit_tenant_is_refused_tenant_required` × 21 |
| unknown tenant → `TENANT_NOT_FOUND` | `test_unregistered_tenant_is_refused_tenant_not_found` × 21 |
| non-ACTIVE tenant → `TENANT_NOT_ACTIVE` | `test_non_active_tenant_is_refused_tenant_not_active` × 21 |
| cross-tenant role ≠ implicit tenant | `test_cross_tenant_admin_still_needs_an_explicit_tenant` |
| explicit tenant narrows, never widens | `test_cross_tenant_admin_naming_a_tenant_is_narrowed_to_it`, `test_scoped_principal_cannot_name_a_tenant_it_does_not_hold` |
| header never silently ignored | `test_supplied_tenant_changes_the_outcome` × 19 |
| unattributed legacy ≠ requested tenant | `test_endpoints_projection_is_confined_to_the_named_tenant`, `test_list_devices_under_explicit_tenant_never_returns_unowned_evidence` |
| evidence narrowed, never destroyed | `test_cross_tenant_projection_is_unchanged_without_an_explicit_tenant` |
| SENSOR_SCOPED needs no analyst header | `test_sensor_routes_do_not_demand_an_analyst_tenant_header` × 8 |
| PRODUCT_METADATA tenant-independent | `test_product_metadata_needs_no_tenant_and_carries_none` × 9 |
| no surviving `"default"` tenancy | `test_no_edr_router_resolves_tenancy_to_the_literal_default`, `test_authorisation_path_no_longer_invents_a_default_tenant` |
| new route failed-closed by default | `test_every_live_edr_operation_is_explicitly_classified` |

## 10 · KNOWN REMAINING `"default"` LITERAL (reported, not touched)
`services/session_context.authorised_incident` labels an incident's tenant
`doc.get("tenant_id") or doc.get("user_email") or "default"`. It is a display
label on an already-authorised document, not a tenancy resolution, and it was
outside the approved R5 scope (`dashboard_lenses:183`). Flagged for a later
decision.

## 11 · STATUS
```
P0  DONE   shared authority + classification, zero intended behaviour change
P1  DONE   response/write plane converged (5 "default" sites retired)
P2  DONE   /api/edr/endpoints + R2 read filtering · GATE H FIXED on candidate
P3  DONE   remaining 13 edr.py routes + edr.py:548
P4  DONE   2 wave0 tenant routes + _tenant() deleted; 8 metadata untouched
P5  DONE   R4 gate (152 passed) + R5 authorisation-path default removed
P6  NOT AUTHORIZED - not attempted
```
No production republish. No production data mutation. No W1 activity.
STOP for owner review.
