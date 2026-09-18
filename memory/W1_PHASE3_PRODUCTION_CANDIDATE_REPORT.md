# PRODUCTION CANDIDATE REPORT — COLLECTOR DEFAULT CLOSURE COMPLETE

**NOT REPUBLISHED. Awaiting owner approval.**
Production remains `publish 100 / build 8833215`. No production data mutation.
No collector, API key, connector or enrolment token created. No W1 telemetry.
No Tenant Picker. No Unattributed Evidence View. No historical unattributed
evidence modified. W1 Phase 3 still paused.

---

## 1 · WHAT THE CLOSURE ACTUALLY FOUND

You asked me to close `collectorApi.js:77,85`. Tracing those two call sites
through to the server found the same implicit default **on the server side of
the collector plane**, which is the plane W1 is about to use. Three sites, all
the B5 defect class:

| site | was | consequence |
|---|---|---|
| `apps/nivxray-xdr-collector/routes/connectors.py:111` | `x_tenant_id or "default"` | **`POST /connectors` with no header PERSISTED a connector under an unregistered tenant** — collector creation inferring tenancy |
| `apps/nivxray-xdr-collector/routes/preflight.py:70` | `x_tenant_id or "preflight"` | a synthetic envelope labelled with the invented tenant `"preflight"` was injected into the **real ingest pipeline** |
| `apps/nivxray-xdr-collector/framework/identity.py:18` | `NIVX_TENANT_ID or "default"` | a mis-deployed collector labelled its **telemetry** `default` instead of failing closed (`delivery.py:110`) |

These routes are mounted into the core at `/api/xdr/collector/*` by
`routers/xdr_collector_landing.attach_collector_landing`, so all three were
live in production. Your instinct was right, and the client-side default was
the visible edge of it — closing only the client would have left the server
inferring tenancy for any other caller.

## 2 · CHANGES (7 files, narrow, no API redesign, no UI)

**Client — `apps/nivxray-xdr/`**
- `xdr/admin/collectorApi.js` — `tenantId = "default"` removed from
  `ingestPreflight` and `createConnector`. New `requireTenant()` resolves
  `tenantId → activeTenant()` and otherwise throws **`NO_TENANT_CONTEXT`**.
  The module's own axios instance gets the same one-place header interceptor
  as `lib/api.js`, so the collector reads carry the selected tenant too and no
  call site can forget it.
- `xdr/admin/IntegrationsBody.jsx:473`, `xdr/design/_WizardLegacyBridge.jsx:30`
  — the connector-wizard tenant field was pre-filled with the literal
  `"default"`; it now starts from `activeTenant()` and is empty when nothing is
  selected, so the form cannot submit an invented tenant.

**Server — `apps/nivxray-xdr-collector/`**
- `routes/connectors.py` — `_tenant()` resolves through
  `services.tenant_registry.authoritative(purpose="xdr.collector.connectors")`
  when mounted in the core; absent → `TENANT_REQUIRED`, unregistered →
  `TENANT_NOT_FOUND`, non-ACTIVE → `TENANT_NOT_ACTIVE`. In a standalone
  deployment (no core on the path) it refuses an absent tenant rather than
  substituting one.
- `routes/preflight.py` — new `_preflight_tenant()`, same contract, and the
  tenant is now resolved **before** the runtime/configuration check, so an
  unauthorised probe cannot even learn whether ingest is configured.
  (First pass put it after; the live probe returned `200 not_configured` and
  exposed the ordering, which is why authority now precedes capability.)
- `framework/identity.tenant_id()` — returns `""` when `NIVX_TENANT_ID` is
  unset. The core then refuses the batch with `TENANT_REQUIRED` instead of the
  collector self-labelling as `default`. Telemetry never establishes tenancy.

**Requirements you set, each met:** no hardcoded `"default"` · no hardcoded
`ten_*` · missing tenant → explicit refusal / `NO_TENANT_CONTEXT` · selected
tenant → explicit authoritative tenant · collector/API-key creation never
creates or infers a tenant. No collector API was redesigned; no UI added.

## 3 · LIVE VERIFICATION ON PREVIEW (read-only + refused negatives)

```
GET  /api/xdr/collector/connectors        no tenant   403 TENANT_REQUIRED
GET  /api/xdr/collector/connectors        unknown     403 TENANT_NOT_FOUND
GET  /api/xdr/collector/connectors        ARCHIVED    403 TENANT_NOT_ACTIVE
GET  /api/xdr/collector/connectors        default     200 {"connectors":[],"count":0}
POST /api/xdr/collector/connectors        no tenant   403 TENANT_REQUIRED
POST /api/xdr/collector/connectors        unknown     403 TENANT_NOT_FOUND
POST /api/xdr/collector/ingest-preflight  no tenant   403 TENANT_REQUIRED
POST /api/xdr/collector/ingest-preflight  unknown     403 TENANT_NOT_FOUND
POST /api/xdr/collector/ingest-preflight  ARCHIVED    403 TENANT_NOT_ACTIVE
```
Every POST was refused, so **nothing was created**: connectors still `count 0`,
tenant registry still `enforcing True, count 5` — unchanged across the probes.
No preflight envelope was delivered (all refused before delivery).

## 4 · TESTS

| suite | result |
|---|---|
| `apps/nivxray-xdr-collector/tests` (12 files) | **105 passed / 0 failed** (was 103 passed / 1 failed) |
| `tests/test_edr_route_tenant_authority.py` + `test_b4b5_...` + `test_d14_tenant_authority.py` | **258 passed / 0 failed** |
| `tests/edr/` (30 files) | **22 failed · 0 new vs the 23-failure baseline** |
| tenant·RBAC·audit·response·isolation (13 files) | **48 — identical list, 0 regression** |
| `yarn build` on `apps/nivxray-xdr` | **exit 0, clean** |

Two tests added (not weakened): `test_preflight_without_a_tenant_is_refused`
and `test_preflight_tenant_is_checked_before_configuration`. One conformance
edit: `test_preflight_reports_not_configured_when_ingest_missing` now sends
`X-Tenant-Id: acme`, exactly as its already-passing sibling did.

**P6 tenant invariants re-confirmed after the closure** — no regression to
`TENANT_REQUIRED` / `TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE`,
cross-tenant ≠ implicit tenant, narrow-only authority, header never ignored,
unattributed ≠ requested tenant, SENSOR_SCOPED without analyst header,
PRODUCT_METADATA tenant-independence.

## 5 · PRODUCTION CANDIDATE IDENTITY

```
Current committed HEAD          0fc9be8a
Last pre-implementation commit  e7195597
Uncommitted (this closure)      7 files, +142 / -14
```

Cumulative candidate diff, `e7195597 → working tree` — **27 files,
+1145 / -183**:

```
 backend/routers/edr_tenancy.py                      166 ++  NEW
 backend/tests/test_edr_route_tenant_authority.py    419 ++  NEW
 apps/nivxray-xdr/src/lib/tenant.js                   48 ++  NEW
 backend/routers/edr.py                              155
 backend/routers/edr_response.py                      54
 backend/routers/edr_wave0.py                         13
 backend/services/edr/file_trajectory.py              36
 backend/services/session_context.py                  22
 backend/services/dashboard_lenses.py                 10
 apps/nivxray-xdr/src/lib/api.js                      11
 apps/nivxray-xdr/src/xdr/admin/collectorApi.js       44
 apps/nivxray-xdr/src/xdr/admin/IntegrationsBody.jsx   3
 apps/nivxray-xdr/src/xdr/design/_WizardLegacyBridge.jsx 3
 apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx 28
 apps/nivxray-xdr-collector/routes/connectors.py      26
 apps/nivxray-xdr-collector/routes/preflight.py       32
 apps/nivxray-xdr-collector/framework/identity.py     13
 frontend/src/v2/pages/SecurityStateTab.jsx           20
 + 9 test files (conformance / reinterpretation)
```
Backend `/api/*` path count unchanged at **795** — no route added, removed or
renamed anywhere in this candidate.

## 6 · WHAT CHANGES FOR OPERATORS IF THIS IS PUBLISHED

Intended and visible, not a regression:
- Every tenant-scoped EDR and collector operation requires `X-Tenant-Id`.
  The XDR console now attaches the selected tenant automatically (one
  interceptor per axios instance); a session with **no** selected tenant gets
  honest `TENANT_REQUIRED` / `NO_TENANT_CONTEXT` instead of silently reading
  `default`.
- The tenant is selected via `?tenant=<ten_*>` or the persisted
  `nvx_tenant`. There is **no picker UI yet** (deliberately deferred), so the
  first production action after republish should be to confirm the console
  carries the authoritative tenant.
- A collector deployed without `NIVX_TENANT_ID` now fails closed at ingest
  rather than sending telemetry labelled `default`. **Relevant to W1: the
  Windows forwarder must have `NIVX_TENANT_ID` set to the authoritative
  tenant.**

## 7 · KNOWN REMAINING, BY YOUR DECISION
- `session_context.authorised_incident` `... or "default"` — display label,
  left alone.
- No HTTP route returns unattributed legacy evidence (Unattributed Evidence
  View deferred). Evidence preserved, service-layer readable, never
  mis-attributed.
- Tenant Picker deferred.
- Browser validation of the EDR console requires a Vercel preview deploy; the
  production build is clean but the console was not driven in a browser here.

## 8 · STATUS
```
P0-P5 backend convergence        DONE
frontend tenant contract         DONE
collector plane default closure  DONE  (client + 3 server-side sites)
P6 preview A-I                   ALL PASS
regression                       0 new failures anywhere
production candidate             READY
--- AWAITING OWNER APPROVAL TO REPUBLISH ---
production republish             NOT PERFORMED
production A-I                   NOT PERFORMED
W1 5-event integration           PAUSED
```
