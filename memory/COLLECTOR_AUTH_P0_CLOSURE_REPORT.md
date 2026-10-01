# COLLECTOR AUTH P0 — CLOSURE REPORT (CANDIDATE / PREVIEW ONLY)

**NOT REPUBLISHED.** Production remains publish 100 / build `a55ec13`.
No production collector, connector, API key, endpoint or enrolment token.
No Sysmon telemetry. No ingestion semantics, DSM, detection rule, evidence
schema, endpoint credential or response semantics touched. No new identity,
tenant, role, permission or approval authority. **W1 REMAINS HELD.**

One bounded security closure: authentication + route-classification guard +
infrastructure-hostname removal.

---

## 1 · THE CONTRACT NOW IMPLEMENTED

```
AUTHENTICATION  ->  PERMISSION  ->  TENANT AUTHORITY  ->  CAPABILITY
```
One dependency, attached at `include_router` time to all seven collector
routers plus the landing echo, driving off the route classification:

| refusal | code |
|---|---|
| undeclared route | 403 `COLLECTOR_ROUTE_UNCLASSIFIED` |
| no credential | 403 `ACCESS_DENIED` / `unauthenticated` |
| authenticated, lacks `collectors.*` | 403 `ACCESS_DENIED` |
| missing tenant (HUMAN_CONTROL) | 403 `TENANT_REQUIRED` |
| unknown tenant | 403 `TENANT_NOT_FOUND` |
| non-ACTIVE tenant | 403 `TENANT_NOT_ACTIVE` |
| TEST_PLANE without the deployment flag | 403 `TEST_PLANE_DISABLED` |

A valid `ten_*` can never satisfy the authentication step — asserted per
operation, not assumed.

## 2 · ROUTE / PERMISSION MATRIX (22 operations · as approved)

| operation (mount-relative) | class | permission |
|---|---|---|
| `GET /connectors` | HUMAN_CONTROL | `collectors.read` |
| `POST /connectors` | HUMAN_CONTROL | `collectors.create` |
| `GET /connectors/{cid}` | HUMAN_CONTROL | `collectors.read` |
| `PATCH /connectors/{cid}` | HUMAN_CONTROL | `collectors.update` |
| `DELETE /connectors/{cid}` | HUMAN_CONTROL | `collectors.delete` |
| `POST /connectors/{cid}/test` | HUMAN_CONTROL | `collectors.test` |
| `POST /connectors/{cid}/start` | HUMAN_CONTROL | `collectors.enable` |
| `POST /connectors/{cid}/stop` | HUMAN_CONTROL | `collectors.disable` |
| `GET /collectors` · `GET /collectors/{collector_id}` | HUMAN_CONTROL | `collectors.read` |
| `GET /outbox` · `GET /outbox/{rid}` · `GET /outbox/health` | HUMAN_CONTROL | `collectors.read` |
| `POST /outbox/{rid}/replay` · `POST /outbox/drain-once` | HUMAN_CONTROL | `collectors.update` |
| `GET /data-sources` | HUMAN_CONTROL | `collectors.read` |
| `POST /ingest-preflight` | HUMAN_CONTROL | `collectors.test` |
| `POST /connectors/{cid}/inject` | TEST_PLANE | `collectors.test` + `X-Debug-Inject: 1` + `NIVX_COLLECTOR_TEST_PLANE=1` |
| `POST /webhooks/{secret_id}` | MACHINE | **none — per-connector HMAC, unchanged** |
| `GET /source-types` · `GET /telemetry-health` · `GET /landing` | PRODUCT_METADATA | `collectors.read` |

Totals: **HUMAN_CONTROL 17 · MACHINE 1 · TEST_PLANE 1 · PRODUCT_METADATA 3 = 22**,
exactly the classification you accepted. No new permission string, no role
change: `collectors` already defined `read/create/update/delete/test/enable/
disable`.

**One explicit note, not a silent choice:** the accepted counts place
`GET /telemetry-health` in PRODUCT_METADATA (authenticated + `collectors.read`,
tenant-independent). It returns per-transport process health, not tenant
evidence. If you prefer it tightened to HUMAN_CONTROL + explicit tenant, that
is a one-line change to the classification map and the test table follows
automatically.

## 3 · CANDIDATE DIFF (9 files · 3 new)

| file | change |
|---|---|
| `apps/nivxray-xdr-collector/framework/route_classification.py` | **NEW** · the closed-set classification + permission map, keyed on `(method, mount-relative path)` so it is identical for the landed and standalone mounts |
| `backend/routers/collector_authz.py` | **NEW** · `collector_guard`: classification → `require_permission` → `tenant_registry.authoritative` → TEST_PLANE flag. Reuse only |
| `apps/nivxray-xdr-collector/framework/authz.py` | **NEW** · import shim. Landed → the real guard. Standalone → **fails closed** (`COLLECTOR_AUTH_UNAVAILABLE`), MACHINE webhook still reachable by classification |
| `backend/routers/xdr_collector_landing.py` | records the mount prefix; attaches `dependencies=[Depends(collector_guard)]` to all 7 routers **and** the landing echo. The webhook router is guarded too — the guard passes MACHINE through, so nothing is unguarded by omission |
| `apps/nivxray-xdr-collector/main.py` | the same guard on the standalone mount |
| `apps/nivxray-xdr-collector/routes/collectors.py` | **hostname leak closed**: `host` (`socket.gethostname()`) and `runtime` (`python-<patch>`) removed for ALL callers |
| `apps/nivxray-xdr/src/xdr/admin/collectorApi.js` | attaches the EXISTING session bearer (`nvx_token`, the same token `lib/api.js` uses) in the one interceptor that already attaches the tenant. No new credential invented |
| `backend/tests/test_collector_plane_auth.py` | **NEW** · 112 assertions, table-driven off the live contract |
| `apps/nivxray-xdr-collector/tests/test_routes.py`, `test_preflight.py` | standalone fail-closed asserted; the pre-existing runtime/transport tests declare a guard override explicitly instead of relying on anonymity |

Route semantics were **not** rewritten: `_tenant()` / `_preflight_tenant()`,
the webhook HMAC path, and the `X-Debug-Inject` check all remain exactly as
accepted. Authentication was added in front of them.

## 4 · TEST RESULTS

```
backend/tests/test_collector_plane_auth.py                 112 passed
apps/nivxray-xdr-collector/tests (14 files)                107 passed   (was 105)
regression · test_edr_route_tenant_authority
          + test_b4b5_tenant_registry_authority
          + test_d14_tenant_authority                      258 passed
yarn build · apps/nivxray-xdr                              exit 0
OpenAPI paths                                              795 (unchanged)
collector operations in the live contract                  22 (unchanged)
```

Clauses actually asserted (not claimed):
- **Coverage gate** — every live `/api/xdr/collector/*` operation must be
  declared; an undeclared one fails the suite AND is refused at runtime. Stale
  entries also fail. Permissions must be `collectors.*`; only the webhook may
  be MACHINE.
- **Anonymous refusal** on all 21 non-webhook operations, including every
  mutating one, with the connector inventory asserted **unchanged** afterwards.
- **Ladder order** — anonymous + a real ACTIVE tenant is refused for
  authentication and never answers `TENANT_*`.
- **Authenticated-but-unauthorised** principal (`analyst@default.com`) refused
  on all 21.
- **Tenant authority preserved** — `TENANT_REQUIRED` / `TENANT_NOT_FOUND` /
  `TENANT_NOT_ACTIVE` per HUMAN_CONTROL read, and 200 for the authorised
  principal naming the authoritative tenant.
- **Webhook unchanged** — anonymous `POST /webhooks/{id}` reaches its own
  connector lookup (`404 webhook_not_configured`), proving no JWT was put in
  front of the HMAC contract.
- **Machine principal** — unknown `X-XDR-API-Key` refused; JWT + key together
  refused as ambiguous.
- **`inject`** — refused anonymously, refused without the debug header, and
  refused for an authorised admin because `NIVX_COLLECTOR_TEST_PLANE` is not
  set on this deployment.
- **Standalone shim fails closed** — `COLLECTOR_AUTH_UNAVAILABLE` on the
  control plane, webhook still reachable.
- **No infrastructure disclosure** — the response carries no `host`/`runtime`
  key, no `gethostname()` value and no `python-3.*` string.

No test was weakened to make the new contract pass. The two standalone test
files now declare a guard override in one place (the standalone app has no
authentication authority to satisfy) and the fail-closed contract they used to
depend on implicitly is asserted explicitly.

## 5 · PREVIEW ACCEPTANCE (browser, authenticated)

- Anonymous `GET /api/xdr/collector/collectors` → **403 `ACCESS_DENIED`
  `collectors.read` / unauthenticated** (was 200 with a pod hostname).
- Admin session with **no tenant selected** → the surface now renders the real
  refusal and offers an in-product remedy (see §8), not `[object Object]`.
- Admin session with a tenant selected from the registry dropdown →
  `collector/connectors` + `collector/outbox/health` return **200** with the
  bearer attached; panel shows the honest `NO INTEGRATIONS CONFIGURED` /
  `NOT_CONFIGURED` state.

## 6 · WHAT THIS DOES AND DOES NOT CHANGE

Production today: `unauthenticated + explicit authoritative tenant`.
This candidate: `authenticated -> authorized -> explicitly tenant-scoped ->
permitted operation` — the state required before W1.

Nine anonymously-mutating operations (create/patch/delete/test/start/stop/
inject/replay/drain) and nine anonymous leaks (connector topology, per-connector
config, collector runtime + pod hostname, data sources, outbox envelope
contents, ingest configuration state, telemetry blind-spot map) are closed in
the candidate. They remain open in production until a republish you authorize
separately.

## 7 · STATUS
```
implementation        DONE (candidate/preview only)
files changed         11 (3 new)
tests                 112 + 107 + 258 passed · build exit 0 · OpenAPI 795
production republish  NOT PERFORMED - awaiting separate owner approval
W1                    HELD (no collector, no ingest key, no Sysmon)
```
STOP for owner review.

---

## 8 · FINAL CANDIDATE ADDENDUM — OPERATOR-FACING CLOSURE (owner decision)

Folded into THIS candidate. No second deployment cycle. Scope kept local to
`IntegrationControlCenter`; no shared frontend refactor, no Tenant Management,
no organization administration, no UI redesign, no onboarding work.
`telemetry-health` stays PRODUCT_METADATA + `collectors.read`, tenant-independent,
as approved.

### 8.1 · Why the page `Refresh` button did nothing (root cause)
`XdrAdminPage.jsx:258` increments `refreshNonce` and calls `load()`. For the
Integrations section `load()` only fetches `/admin/osint/services` and sets
`populated`; the surface itself is `IntegrationControlCenter`, which fetched on
MOUNT only. The component never unmounts, so the nonce reached nothing — the
button re-fetched a projection the panel does not render. Sibling bodies
(`EdrEnrollmentBody`, `EdrResponseBody`) already received `refreshNonce`; this
one did not. Fixed by passing the nonce and re-running the loader on change.
The in-band `Refresh` was additionally suppressed unless `state === "ready"`,
so in the failure state there was no working refresh at all; it is now
available whenever the collector runtime is configured.

### 8.2 · `[object Object]`
`load()` stored the STRUCTURED refusal (`{code, reason}`) and `ErrorSection`
rendered `String(message)`. A new local `formatRefusal()` renders
`CODE — reason` plus a one-line remedy. Verified in a real session:

```
TENANT_REQUIRED — no tenant named for xdr.collector: the authoritative tenant
must be presented explicitly; there is no default tenant
Select the authoritative tenant above — there is no default tenant.
```

### 8.3 · Minimal tenant selector (`TenantBar`)
In the Integrations header. Options come from the authoritative registry as the
AUTHENTICATED PRINCIPAL sees it (`GET /api/xdr/tenants`, which needs a session
and no tenant header, so there is no chicken-and-egg), filtered to `ACTIVE`,
labelled by `display_name` — **the operator never types an opaque `ten_*` id**.
Selecting one persists the existing `nvx_tenant` context via the existing
`setActiveTenant` and re-runs the projection. No tenant id, slug, organization
id or customer name is hardcoded anywhere in the client; the browser does not
decide which tenants exist or whether one is ACTIVE. With nothing selected the
surface stays fail-closed and states why.

`"default"` is no longer used by this suite or by the UI demonstration. The
backend suite now DISCOVERS a registered ACTIVE tenant (and a non-ACTIVE one)
from the registry instead of hardcoding anything.

**One honest observation:** the PREVIEW registry still contains legacy-adopted
ACTIVE entries (`Preview Runtime (legacy default)`, `Preview Live Sources`,
`p0f-keyauth-*`), so the dropdown lists them — the selector reflects registry
truth rather than hiding it, and that is preview data, not a reintroduction of
the default model. `Smoke Validation` is ARCHIVED and is correctly excluded.
In production the dropdown will show the single ACTIVE tenant by its display
name.

### 8.4 · Verified in a real browser session (no DevTools, no localStorage edit)
```
no tenant selected      -> 403 TENANT_REQUIRED, rendered as text + remedy
tenant dropdown         -> populated from GET /api/xdr/tenants (ACTIVE only)
select a tenant         -> panel loads · roster + evidence health · 0 errors
page-level Refresh      -> reloads the surface · 0 errors (previously inert)
```
Retests after the addendum: `test_collector_plane_auth.py` **112 passed** ·
`yarn build` **exit 0**.

Files added by the addendum: `IntegrationControlCenter.jsx` (formatter,
`TenantBar`, nonce handling), `XdrAdminPage.jsx` (one prop),
`tests/test_collector_plane_auth.py` (registry-discovered tenants).

**STILL NOT REPUBLISHED. W1 HELD.**

