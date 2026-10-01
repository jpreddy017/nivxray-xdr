# S2-MINI · ENGINE-DEPTH READ AUTHORIZATION — 2026-06-21

**Status: DONE · PROVEN.** Backend only, 3 routes, +12/−4 lines in `backend/v2`
plus one new authority module. No frontend change. No engine redesign. S3 not
started.

Proofs: `test_reports/s2mini_live_proof.txt` (**37 PASS · 0 FAIL**, real JWTs) ·
`test_reports/s2mini_focused_tests.txt` (**19 passed in 25 s**).

## ENGINE READS REQUIRED

Read directly from the Individual Incident workspace — `XdrIncidentDetailPage`
mounts `EngineDepth` (collapsed) → lazy `XdrInvestigationWorkspacePage`, which
calls, with `caseId = incident.id`:

| # | read | used by EngineDepth panel | was |
|---|------|---------------------------|-----|
| 1 | `GET /api/v2/cases/{case_id}/investigation?limit&profile` | verdict + security_state · story + process · graph (IKG) | `require_admin` |
| 2 | `GET /api/v2/cases/{case_id}/trajectory/device?limit` | device trajectory (timeline tab) | `require_admin` |
| 3 | `GET /api/v2/cases/{case_id}/artifacts?limit` | extracted artifacts (evidence tab) | `require_admin` |

Two further calls the same component makes were examined and **left alone**:
- `GET /api/v2/security-state/{case_id}?tenant_id=` — **already correct** (B6):
  the router requires `incidents.read` **and** resolves the tenant through
  `authorize_tenant`, so the query `tenant_id` is a *request*, not authority.
- `GET /api/edr/process-tree?incident_id=` — EDR plane, not `/v2/cases/*`.

## AUTHORIZATION CHANGE

`require_admin` → `Depends(engine_case_read)` on those **three reads only**
(new `backend/v2/case_authz.py`):

    authenticated principal
      → cross-tenant (admin) role      ⇒ unchanged access, basis
                                         `CROSS_TENANT_ROLE`
      → otherwise: the `case_id` must BE an incident this principal is
        authorized for, resolved by the ONE incident authority
        (`routers.incidents.authorized_incident` → server-resolved tenant
        scope) ⇒ basis `INCIDENT_TENANT_AUTHORITY`
      → anything else ⇒ 404, existence never disclosed

No new authorization model, no new tenant resolver, no client-presented
identity accepted. `/api/v2/cases` list, create, delete, observation ingest,
artifact create/custody/link, and the engine-only negative-explainability route
(`…/investigation/explain/{pattern_id}`) all remain **admin-only**.

## INCIDENT ↔ ENGINE ASSOCIATION AUTHORITY

The mapping problem was respected, not papered over:
- `v2_cases` documents carry **no tenant field at all** (keys: `name`,
  `status`, `tags`, `created_at`, `created_by`, `event_count`,
  `entity_count`). The engine case therefore **cannot** be a tenant authority
  — the incident record is.
- Measured in the preview store: **154** distinct `v2_shadow_observations.case_id`
  values, of which **87** are `workspace_cases` ids. So association is real for
  some incidents and absent for others — it is never assumed.
- A non-admin principal can only ever address `case_id == its own incident id`.
  An engine-native / golden / foreign case id is simply not an incident of that
  tenant → 404. **Nothing is reshaped, guessed or matched by resemblance, and
  no substitute case is ever attached.**
- New additive `engine_association` block on all three responses, so an
  authorized incident with no engine evidence **says so** instead of returning
  an empty projection that reads as "no activity":
  `{state: ASSOCIATED|NOT_ASSOCIATED, case_id, read_from:
  "v2_shadow_observations.case_id", reason, authority}`.

## TENANT ISOLATION PROOF (live, real JWTs, no overrides — 37 PASS · 0 FAIL)

Per read (×3): anonymous → **403** · own-tenant analyst → **200** with
`ASSOCIATED` + `INCIDENT_TENANT_AUTHORITY` · cross-tenant analyst → **404** ·
admin → **200** · engine-native case `case_dfir_bumblebee_akira_2026`: admin
**200**, analyst **404** · `?tenant_id=`, `?customer=`, `X-Tenant-Id`,
`X-Principal-Id` → **404** (a fabricated identity cannot elevate).
Plus: an authorized-but-unassociated incident → `200 NOT_ASSOCIATED` with a
reason · analyst cannot create / list / delete an engine case, ingest an
observation, or call negative explainability (**403** each) · admin registry
access unchanged (**200**).

## FOCUSED TEST RESULTS

- `backend/tests/test_s2mini_engine_depth_authz.py` — **19 passed in 25 s**
  (no sleeps, no polling). Fixture is prefix-scoped, seeds its own user records
  (because `resolve_tenant_scope` reads the principal's own record), owns
  exactly ONE dependency-override key, and tears down on success and failure.
  Verified afterwards: **0** fixture documents in `nivxray_ci_local` and
  `test_database`.
- `tests/test_v2_r11_endpoints.py`, `tests/test_v2_trajectory.py` — pass.
- `tests/test_v2_isolation.py`, `tests/test_v2_phase2.py` — 3 failures, proven
  **pre-existing** (`git stash` on the pre-S2 tree fails the same tests, 4
  failed / 19 passed). Not absorbed, not baseline-reset.
- No full backend regression run (not required; nothing in the focused set
  pointed at wider impact).

## FILES CHANGED

New: `backend/v2/case_authz.py` · `backend/tests/test_s2mini_engine_depth_authz.py` ·
`scripts/s2_mini_engine_depth_live_proof.py`.
Changed (+12/−4): `backend/v2/routers/investigation.py` ·
`backend/v2/routers/trajectory.py` · `backend/v2/routers/artifacts.py`.

## RESIDUALS

1. **P0 SECURITY RESIDUAL (recorded, untouched, owner decision)** —
   `GET /api/xdr/incidents/{id}/response-executions` still accepts an optional
   **client-supplied `tenant_id`** and queries by `invoker.context.incident_id`
   with no server-resolved tenant predicate. Different root cause from S1/S2.
2. **Engine fragility, pre-existing, NOT fixed:** `v2/shadow/irg.py:119` raises
   `KeyError` when a frame has no parseable `ts` (the enricher indexes
   `entity_first_seen[iid]` that the timing pass skipped) → HTTP 500. Found
   because the first fixture observation had no `ts`; the fixture now carries
   the real CEM shape. Out of S2-mini scope.
3. `engine_association` is served but **not yet rendered** — surfacing
   `NOT_ASSOCIATED` in the incident UI belongs to S3-A.
4. Engine-native cases (37 golden fixtures with no incident and no tenant)
   remain admin-only by design. Giving them a tenant is a data-ownership
   decision, not an authorization one.
