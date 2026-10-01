# B5/B7 EDR TENANT CONVERGENCE — CLASSIFICATION + PATCH/TEST PLAN (PLAN ONLY)

Plan only. Nothing implemented. No production mutation. No republish.
W1 Phase 3 remains paused. Owner approval required before any edit.

Record corrections accepted and locked:
- **Gate H** raw request was `GET /api/edr/endpoints` (not the enrolment
  route). `routers/edr.py:630` is confirmed as the affected route.
- **Gate F** raw request was `GET /api/security-state/streaming/status` → 404.
  The deployed route is `/api/v2/security-state/streaming/status` with a
  **required** `tenant_id` query parameter. **Gate F = NOT YET TESTED**
  (wrong test path). It is **not** a product defect and **not** BLOCKED.
  The earlier "absent from OpenAPI" conclusion is withdrawn.

---

## 1 · ROUTE CLASSIFICATION — ALL 32 EDR ROUTES

Three classes, not two. The agent/sensor routes need their own class: their
tenant comes from the **authenticated endpoint session**, never from a caller
header, so applying a header dependency to them would be wrong.

- **TENANT_SCOPED** — returns or mutates tenant evidence/state. Requires an
  explicit registered ACTIVE tenant. Missing → `TENANT_REQUIRED`.
- **SENSOR_SCOPED** — authenticated *endpoint* principal. Tenant is taken from
  `AuthenticatedEndpoint.tenant_id`, then validated against the registry
  (exactly as `edr_enrollment._agent_tenant()` already does). A caller-supplied
  tenant must never be read here.
- **PRODUCT_METADATA** — product-level truth that is identical for every
  tenant and contains no tenant data. Authentication still required; explicit
  tenant not required.

### 1a · `routers/edr.py` — 14 routes · all TENANT_SCOPED
| # | route | function | current scope | class | rationale |
|---|---|---|---|---|---|
| 1 | GET `/detections` | `list_detections:408` | `get_current_user` only | TENANT_SCOPED | returns detections = tenant evidence; no scope call at all |
| 2 | GET `/endpoint-detections` | `list_endpoint_detections:423` | `resolve_tenant_scope` | TENANT_SCOPED | per-endpoint detections |
| 3 | GET `/process-tree` | `get_process_tree:510` | `_is_cross_tenant` | TENANT_SCOPED | process lineage from observations |
| 4 | GET `/campaign-story` | `campaign_story:536` | `get_current_user` + **`"default"` at :548** | TENANT_SCOPED | narrative over tenant incidents; hardcoded default |
| 5 | GET `/observation-narrative` | `observation_narrative:556` | `_is_cross_tenant` | TENANT_SCOPED | observation evidence |
| 6 | GET `/file-trajectory` | `file_trajectory:584` | `get_current_user` only | TENANT_SCOPED | fleet-wide artefact spread |
| 7 | GET `/fleet-spread-index` | `fleet_spread_index:598` | **none — no scope argument at all** | TENANT_SCOPED | most exposed read in the sweep |
| 8 | GET `/telemetry/freshness` | `telemetry_freshness:610` | `resolve_tenant_scope` | TENANT_SCOPED | per-tenant sensor delivery state |
| 9 | GET `/endpoints` | `list_endpoints:630` | `_case_scope`+`_is_cross_tenant` | TENANT_SCOPED | **the Gate H failure** |
| 10 | GET `/endpoints/{id}/trajectory` | `endpoint_trajectory_window:785` | `_is_cross_tenant` | TENANT_SCOPED | per-device evidence |
| 11 | GET `/device-trajectory` | `get_device_trajectory:874` | `_case_scope`+`_is_cross_tenant` | TENANT_SCOPED | per-device evidence |
| 12 | GET `/context` | `edr_entry_context:1116` | `_is_cross_tenant` | TENANT_SCOPED | resolves the active customer; tenant is the answer |
| 13 | GET `/endpoints/{id}/linked-incidents` | `linked_incidents:1224` | both | TENANT_SCOPED | incident linkage |
| 14 | GET `/endpoints/{id}/trajectory/focus` | `trajectory_focus:1305` | `_is_cross_tenant` | TENANT_SCOPED | per-device evidence |

`grep -c tenant_registry routers/edr.py` → **0**. Enforcement cannot reach any
of these 14.

### 1b · `routers/edr_response.py` — 8 routes · 5 TENANT_SCOPED + 3 SENSOR_SCOPED
| # | route | function | current tenant source | class |
|---|---|---|---|---|
| 15 | POST `/edr/response/actions` | `request_action:54` | **`user.get("tenant_id") or "default"` :68** | TENANT_SCOPED · **write/response** |
| 16 | GET `/edr/response/actions` | `list_actions:107` | **`… or "default"` :130** | TENANT_SCOPED |
| 17 | GET `/edr/response/actions/{command_id}` | `get_action:137` | **`… or "default"` :144** | TENANT_SCOPED |
| 18 | GET `/edr/response/isolation-policy` | `read_isolation_policy:159` | **`… or "default"` :163** | TENANT_SCOPED |
| 19 | PUT `/edr/response/isolation-policy` | `write_isolation_policy:166` | **`… or "default"` :171** | TENANT_SCOPED · **write** |
| 20 | GET `/edr/agent/commands` | `poll_commands:183` | `who.tenant_id` (session) | SENSOR_SCOPED |
| 21 | POST `/edr/agent/command-result` | `command_result:193` | `who.tenant_id` | SENSOR_SCOPED |
| 22 | POST `/edr/agent/command-verification` | `command_verification:206` | `who.tenant_id` | SENSOR_SCOPED |

**New P0 finding, more severe than Gate H.** The five analyst response routes
resolve tenancy as `user.get("tenant_id") or "default"`. No code writes
`tenant_id` onto a user document on the platform-user path, so in practice
**isolation policy reads/writes and response command records are keyed to the
literal string `"default"`** — the exact defect class B5 closed in
`edr_enrollment._tenant()`, still live on the **write/response** plane.
Consequence: a containment action can be recorded against, and an isolation
policy written into, a tenant that does not exist in the registry.
This is why R3's priority on `edr_response.py` is correct.

### 1c · `routers/edr_wave0.py` — 10 routes · 8 PRODUCT_METADATA + 2 TENANT_SCOPED
| # | route | function | class | rationale |
|---|---|---|---|---|
| 23 | GET `/capabilities` | `list_capabilities:32` | PRODUCT_METADATA | serves `INVENTORY`, graded in source; identical for all tenants |
| 24 | GET `/capabilities/summary` | `capability_summary:57` | PRODUCT_METADATA | derived from `INVENTORY` |
| 25 | GET `/capabilities/{id}` | `get_capability:63` | PRODUCT_METADATA | static registry lookup |
| 26 | GET `/sensors` | `list_sensors:79` | PRODUCT_METADATA | `SENSOR_REGISTRY`, source-defined |
| 27 | GET `/contracts` | `list_contracts:94` | PRODUCT_METADATA | schema manifest + epistemic states |
| 28 | GET `/contracts/{name}/schema` | `contract_schema:107` | PRODUCT_METADATA | schema export |
| 29 | GET `/filter-taxonomy` | `filter_taxonomy:120` | PRODUCT_METADATA | baseline status |
| 30 | GET `/detection-rule-bindings` | `detection_rule_bindings:132` | PRODUCT_METADATA | rule-library binding report, not tenant data |
| 31 | GET `/raw-events/stats` | `raw_event_stats:147` | **TENANT_SCOPED** | `raw.stats(_db, tenant_id=_tenant(user))` |
| 32 | GET `/raw-events/replay-candidates` | `replay_candidates:153` | **TENANT_SCOPED** | returns byte-preserved raw tenant events |

`edr_wave0.py:29` — `_tenant()` returns `(user).get("customer") or "default"`:
the **identical** `users["customer"]` → `"default"` defect B5 fixed in the
enrolment plane, still live for routes 31–32.

### 1d · Totals
```
TENANT_SCOPED     21   (14 edr.py + 5 edr_response.py + 2 edr_wave0.py)
SENSOR_SCOPED      3   (edr_response.py agent surface)
PRODUCT_METADATA   8   (edr_wave0.py)
TOTAL             32
```
Surviving `"default"` literals to retire: `edr_response.py` ×5,
`edr_wave0.py:29`, `edr.py:548`, `dashboard_lenses.py:183`. **8 sites.**

---

## 2 · EXACT FILES AND FUNCTIONS TO CHANGE

**R0 (new, enabling) — one shared dependency.**
New `backend/routers/edr_tenancy.py` (mirrors `edr_enrollment._tenant`,
nothing new invented):
- `edr_tenant(request) -> str` — FastAPI dependency; reads `X-Tenant-Id`,
  calls `tenant_registry.authoritative(..., purpose="edr.<route>")`, maps
  `TenantRegistryError` → `HTTPException(e.http, e.detail())`.
- `edr_scope(tenant_id, user) -> dict` — intersects the resolved tenant with
  `resolve_tenant_scope(user.email)`. Returns the narrowed scope or raises
  `403 TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`. **Narrows only; never widens.**
- `ROUTE_CLASSIFICATION: dict[(method, path)] -> "TENANT_SCOPED" | "SENSOR_SCOPED" | "PRODUCT_METADATA"` — the §1 table as data, consumed by the R4 test.

**R1 — close Gate H.** `routers/edr.py`
- `list_endpoints:630` — add `request: Request`, `tenant = Depends(edr_tenant)`;
  pass the narrowed scope into `_case_scope` and `dir_svc.list_devices`.
- `_case_scope:37` and `_is_cross_tenant:57` — accept an optional resolved
  `tenant_id` and intersect. Signatures extended, existing call sites keep
  working; no behaviour change until a route passes a tenant.
- `services/edr/device_identity.list_devices:176` — accepts the narrowed scope
  it is already given; **no change needed to the attribution logic** (`_attribute` is correct and stays untouched).

**R2 — unattributed evidence never attributed.** `services/edr/device_identity.py`
- `list_devices` — new keyword `explicit_tenant: str | None = None`. When set,
  exclude `UNATTRIBUTED_LEGACY_OBSERVATION`, `TENANT_CONFLICT_FAILED_CLOSED`,
  `TENANT_MISMATCH_FAILED_CLOSED` and keep only `tenant_id == explicit_tenant`.
  Default `None` preserves today's cross-tenant behaviour exactly.
- `routers/edr.py:700` merge block — carry `tenant_attribution` through
  unchanged (it already does).
- Unattributed rows stay reachable via an explicitly-named unattributed view
  (deferred to a separate, separately-approved change) so **evidence is never
  hidden, only never mis-attributed**. Nothing deleted, nothing rewritten.

**R3 — converge, response plane first.**
- `routers/edr_response.py` — routes 15–19: replace all five
  `user.get("tenant_id") or "default"` with `Depends(edr_tenant)`.
  `_canonical_endpoint_id:80` receives the resolved tenant (it already takes
  `tenant_id`).
  **Preserved verbatim, not touched:** `ActionBody` shape, `resp.request_action`
  approval/permission path, `AuthenticatedEndpoint` service authentication,
  idempotency via `command_id`, audit records, and
  `resp.verify` as the only path to VERIFIED. The chain
  *user → authoritative identity → explicit tenant → permission → exact-action
  approval → adapter/dispatch → endpoint → execution result → independent
  verification* gains one narrowing step at "explicit tenant" and loses
  nothing. **ACCEPTED ≠ EXECUTED ≠ CONTAINED ≠ VERIFIED is untouched.**
- Routes 20–22 (SENSOR_SCOPED) — keep `who.tenant_id`; add the registry
  validation only, via the existing `_agent_tenant()` pattern. **No header is
  read on the sensor path.**
- `routers/edr.py` — remaining 13 TENANT_SCOPED routes, plus retire `"default"`
  at `:548`.
- `routers/edr_wave0.py` — routes 31–32 use `Depends(edr_tenant)`; delete
  `_tenant():29`. Routes 23–30 keep `get_current_user` only and are recorded
  as PRODUCT_METADATA in `ROUTE_CLASSIFICATION`. **No router-level dependency
  is added anywhere.**

**R4 — mandatory regression gate.** New
`backend/tests/test_edr_route_tenant_authority.py`:
1. **Coverage completeness** — walk `app.routes`, select every `/api/edr/*`
   operation, and fail if any is missing from `ROUTE_CLASSIFICATION`. A new EDR
   route is therefore failed-closed by default until explicitly classified.
2. For every `TENANT_SCOPED` route, with enforcement on:
   no `X-Tenant-Id` → **`TENANT_REQUIRED`**; unregistered → **`TENANT_NOT_FOUND`**;
   non-ACTIVE → `TENANT_NOT_ACTIVE`; registered+ACTIVE → proceeds **and the
   response contains no other tenant's rows**.
3. **Header must never be silently ignored** — for each TENANT_SCOPED route,
   two registered tenants A and B must produce different (or disjoint) results,
   and a garbage header must never return the same body as no header.
4. **Cross-tenant role ≠ implicit tenant** — a cross-tenant principal with no
   `X-Tenant-Id` is refused `TENANT_REQUIRED` on every TENANT_SCOPED route.
5. `SENSOR_SCOPED` — a caller-supplied `X-Tenant-Id` is ignored *by design* and
   an endpoint session bound to an unregistered tenant is refused.
6. `PRODUCT_METADATA` — succeeds without a tenant, and its body is byte-equal
   under two different tenants (proves it carries no tenant data).
7. **R2 unit test** — `list_devices(explicit_tenant=T)` never returns
   `UNATTRIBUTED_*` / `*_FAILED_CLOSED`; with `explicit_tenant=None` the
   cross-tenant projection is unchanged.

Updated: `tests/test_b4b5_tenant_registry_authority.py` gains a note that its
three EDR assertions cover the enrolment plane only, and defers route coverage
to the new file. `tests/edr/test_iteration_82_activation.py:42` calls
`/api/edr/endpoints` with no tenant header and will need `X-Tenant-Id` added —
identified in advance so it is a deliberate update, not a surprise failure.

**R5 — retire the authorisation-path default.**
`services/dashboard_lenses.resolve_tenant_scope:183` — a user with no
`tenant_id`/`tenant_ids` returns an honest empty scope instead of
`["default"]`. **No data migration**; this only changes a query predicate.

---

## 3 · MIGRATION CONFIRMATION

**Confirmed: nothing requires migration.** No change in R1–R5 writes,
rewrites, renames, backfills or deletes anything.

| asset | migration needed | why |
|---|---|---|
| canonical evidence / `xdr_canonical_evidence` | **No** | not read or written by any of these routes |
| `v2_shadow_observations` (incl. `ENG-42`) | **No** | R2 changes a read-time filter only; documents untouched |
| detection logic / rules / `detection_content` | **No** | not in scope; `/detection-rule-bindings` stays PRODUCT_METADATA |
| response execution semantics | **No** | approval, permission, dispatch, idempotency, audit, verification all unchanged; one narrowing step added |
| existing `edr_commands` / `isolation_policy` docs keyed `"default"` | **No migration proposed** | they become unreachable by the new explicit-tenant path. Deliberate: they are records of the defect and are **evidence**. Any adoption/relabelling is a **separate owner decision**, not part of this patch |
| tenant IDs (`ten_*`) / organization IDs (`org_*`) | **No** | never rewritten; registry is the authority |
| endpoint IDs (`ep_*`) / `edr_endpoints` | **No** | identity preserved; only read predicates change |
| `edr_raw_events` | **No** | routes 31–32 change the tenant predicate only |
| API keys / collectors / enrolment tokens | **No** | untouched |
| frontend | **No code change in this patch** | UI must start sending `X-Tenant-Id`; tracked separately with the known hardcoded `default` in `SecurityStateTab.jsx` / `XdrInvestigationWorkspacePage.jsx:179` |

**Behaviour changes that are intended and must be acknowledged before
approval:** any caller of a TENANT_SCOPED EDR route that does not send
`X-Tenant-Id` starts receiving `403 TENANT_REQUIRED`. That includes the current
EDR console screens and `tests/edr/test_iteration_82_activation.py`. This is
the B7 Option A contract working, not a regression — but it is a visible
change and is the reason this is a plan, not a patch.

---

## 4 · MINIMUM PATCH SEQUENCE (response/write authority first)

| step | scope | gate before proceeding |
|---|---|---|
| **P0** | R0 — `routers/edr_tenancy.py` + `ROUTE_CLASSIFICATION` (no route wired) | unit tests green; zero runtime behaviour change |
| **P1** | R3a — `edr_response.py` routes 15–19 (**write/response authority**) + registry validation on 20–22 | R4 clauses 2–5 green for those 8; response chain regression proves approval/idempotency/audit/verification unchanged |
| **P2** | R1 + R2 — `/api/edr/endpoints` and `device_identity.list_devices` | **Gate H re-run passes**; R2 unit test green |
| **P3** | R3b — remaining 13 `edr.py` TENANT_SCOPED routes + retire `edr.py:548` | R4 full suite green |
| **P4** | R3c — `edr_wave0.py` 31–32 + delete `_tenant():29`; record 23–30 as PRODUCT_METADATA | R4 clause 6 green |
| **P5** | R4 coverage gate made mandatory; R5 `dashboard_lenses:183` | full backend suite; no new failures beyond the one known stale EDR test |
| **P6** | preview deploy → full A–I re-run under enforcement → owner review → production republish decision | owner authorisation |

W1 Phase 3 resumes only after P6 acceptance. No step mutates production data.

---

## 5 · CORRECTED GATE F PROBE — OWNER-SIDE ONLY (agent will not execute)

Correct contract: `GET /api/v2/security-state/streaming/status` with
**required query parameter `tenant_id`**. The route is fail-closed by
`dependencies=[require_permission("incidents.read"), _authorized_tenant]`
(`security_state/routers/router.py:89`), and `_authorized_tenant:65` resolves
through `routers.xdr_rbac.authorize_tenant(..., purpose="security_state")`,
which calls `tenant_registry.authoritative()` first — so an unregistered
tenant is refused **before** any RBAC decision.

Read-only. Two GETs. Creates nothing. `$tok` never printed.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if (-not $tok) { Write-Host 'ABORT: $tok is not set.'; return }

$A = 'https://nivxray.nivxforge.com'
$T = 'ten_e759b7288598bd882e3dcac49d'
$H = @{ Authorization = "Bearer $tok" }

function Show-Fail($label, $err) {
  $code = $null; try { $code = $err.Exception.Response.StatusCode.value__ } catch {}
  $body = $null; try { $body = $err.ErrorDetails.Message } catch {}
  if (-not $body) { $body = $err.Exception.Message }
  "{0} :: HTTP {1} :: {2}" -f $label, $code, ($body -replace '\s+',' ')
}

Write-Host "--- F1  authoritative tenant (expect 200, tenant_id echoed) ---"
try {
  $r = Invoke-RestMethod -Method Get -Headers $H `
        -Uri "$A/api/v2/security-state/streaming/status?tenant_id=$T"
  "F1 http        : 200"
  "F1 tenant_id   : $($r.tenant_id)        (expect $T)"
  "F1 transport   : $($r.transport)"
  "F1 shadow_mode : $($r.shadow_mode)"
} catch { Write-Host (Show-Fail 'F1 UNEXPECTED FAILURE' $_) }

Write-Host "`n--- F2  'default' must be refused (expect 403 TENANT_NOT_FOUND) ---"
try {
  $x = Invoke-RestMethod -Method Get -Headers $H `
        -Uri "$A/api/v2/security-state/streaming/status?tenant_id=default"
  "F2 UNEXPECTED 200 - FAILURE: $($x | ConvertTo-Json -Compress -Depth 4)"
} catch { Write-Host (Show-Fail 'F2 refused' $_) }

Write-Host "`n--- END GATE F ---"
```

PASS = F1 HTTP 200 with `tenant_id` exactly `ten_e759b7288598bd882e3dcac49d`,
and F2 refused **403 with code `TENANT_NOT_FOUND`** (a bare 403 without that
code is NOT a pass — it would mean RBAC refused before the registry did).
Omitting `tenant_id` entirely yields `422` from FastAPI validation, which is a
schema refusal, not an authority refusal — so it is deliberately **not** part
of Gate F.

**Gate I remains NOT RUN** and unchanged, per the hard stop.

---

## 6 · STATUS

```
Gate H   FAIL   root cause confirmed - routers/edr.py:630 has no tenant authority
Gate F   NOT YET TESTED - wrong path used; correct probe supplied above
Gate I   NOT RUN
Sweep    32 routes classified: 21 TENANT_SCOPED / 3 SENSOR_SCOPED / 8 PRODUCT_METADATA
NEW P0   edr_response.py keys response actions + isolation policy to literal "default" (5 sites)
NEW P0   edr_wave0.py:29 repeats the users["customer"] -> "default" defect (2 routes)
Default  8 surviving "default" literals identified for retirement
Migration  NONE required for any asset
```
Nothing implemented. Awaiting owner approval of the classification and the
P0–P6 sequence.
