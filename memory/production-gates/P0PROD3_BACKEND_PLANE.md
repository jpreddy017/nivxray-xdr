# P0-PROD-3 · PRODUCTION EDR BACKEND PLANE

Gate: **P0-PROD-3 — make the current proven EDR backend/control/agent plane
deployable and correctly served by the real production backend.**
Date: 2026-06
Status: **PASS** · Production Sync readiness: **GO** (deployment step only)

Nothing was deployed. No production database was contacted or modified. No
production secret was generated, installed or read. No tenant was created.
All production observations below are **read-only, unauthenticated HTTP**.

---

## 1 · ROOT CAUSE OF THE STALE/MISSING PRODUCTION EDR PLANE

**The production backend is running an OLDER BUILD of this same
application. There is no code, environment, product-scope or routing
defect to fix.**

Evidence — the deployed OpenAPI schema versus source:

| | Source (preview process) | Production (`nivxray.nivxforge.com`) |
|---|---|---|
| Total routes | **862** | **795** |
| Missing vs source | — | **67** (37 EDR + 30 XDR) |
| Present in production but absent from source | — | **0** |

Production is a **strict subset** of source. If a guard, scope flag or
environment switch were filtering the EDR plane, we would expect either
extra/renamed routes or a mismatched set — not a clean subset. Confirmed
by three independent checks:

1. `grep` for `PRODUCT_SCOPE`, `NIVX_PRODUCT`, `product_scope`, `SCOPE`
   in `server.py` / `deps.py` → **no matches**.
2. Every `api.include_router(...)` for an EDR router sits at module top
   level, never inside an `if` — asserted by
   `test_edr_router_registration_is_not_conditional`.
3. The routes present in production stop exactly where the older
   `server.py` registration block ended: `edr_wave0`, `edr_response`,
   `edr_projections`, `edr_enrollment` (partially) are served; everything
   registered after them — `edr_onboarding`, `edr_policies`, `edr_groups`,
   the policy agent, `edr_exclusions`, `edr_events`, `edr_connector`,
   `edr_audit`, `edr_saved_views`, `edr_findings` — is absent.

**Therefore the remedy is a REPUBLISH of the backend, plus the production
configuration in §8. It is not a code change.**

(Commit dating could not corroborate this independently: the platform's
history is compacted and most `include_router` introductions carry the
same commit date. The OpenAPI subset proof stands on its own.)

---

## 2 · ROUTE MATRIX — SOURCE vs PREVIEW vs PRODUCTION

Method: source/preview from the live preview `/openapi.json`; production
from `https://nivxray.nivxforge.com/api/openapi.json` plus unauthenticated
HTTP probes (`404` = absent, `401/403/422` = present and correctly
refusing).

### 2.1 · Served by production today (present, auth-refusing)

`/api/edr/agent/enroll` (422) · `/api/edr/agent/session` (422) ·
`/api/edr/agent/heartbeat` (401) · `/api/edr/agent/telemetry` (401) ·
`/api/edr/agent/whoami` (401) · `/api/edr/agent/commands` (401) ·
`/api/edr/agent/command-result` (401) ·
`/api/edr/agent/command-verification` (401) ·
`/api/edr/enrollment/tokens` (403) · `/api/edr/enrollment/endpoints` (403) ·
`/api/edr/enrollment/rejections` (403) · `/api/edr/endpoints` (403) ·
`/api/edr/detections` (403) · `/api/edr/endpoint-detections` (403) ·
`/api/edr/device-trajectory` (403) · `/api/edr/file-trajectory` (403) ·
`/api/edr/process-tree` (403) · `/api/edr/campaign-story` (403) ·
`/api/edr/context` (403) · `/api/edr/observation-narrative` (403) ·
`/api/edr/fleet-spread-index` (403) · `/api/edr/telemetry/freshness` (403) ·
`/api/edr/response/*` (403) · `/api/edr/wave0/*` (403)

### 2.2 · NOT DEPLOYED (present in source, `404` in production)

| Plane | Routes absent from production |
|---|---|
| Policy | `/api/edr/policies`, `/policies/{id}`, `/policies/{id}/assign`, `/policies/{id}/versions`, `/policies/audit`, `/policies/deployment`, `/api/edr/groups`, `/api/edr/agent/policy`, `/api/edr/agent/policy-ack` |
| Exclusions | `/api/edr/exclusions`, `/exclusions/sets`, `/exclusions/taxonomy`, `/exclusions/{id}/approval`, `/exclusions/{id}/revoke`, `/exclusions/enforcement-proof`, `/api/edr/agent/exclusion-enforcement` |
| Findings (P0-C) | `/api/edr/findings`, `/findings/{id}`, `/findings/evaluation-state`, `/findings/taxonomy` |
| Events | `/api/edr/events`, `/events/facets`, `/events/{raw_id}` |
| Audit | `/api/edr/audit`, `/api/edr/audit/facets` |
| Onboarding | `/api/edr/onboarding/computers`, `/computers/{id}`, `/packages`, `/packages/{id}/file/{name}` |
| Connector | `/api/edr/connector/releases`, `/releases/{id}`, `/releases/{id}/artifact/{name}`, `/connector/deployments` |
| Control plane | `/api/edr/endpoint-commands`, `/api/edr/saved-views`, `/saved-views/{id}` |
| **P0-PROD-2** | `/api/edr/enrollment/tokens/{token_id}/revoke` (new this session) |

Also NOT DEPLOYED on the XDR side (30 routes), including the ones the
current console calls: `/api/xdr/rbac/me/effective`,
`/api/xdr/scope/authorized`, `/api/xdr/scope/select`,
`/api/xdr/windows/configuration`, plus `/api/xdr/events/*`,
`/api/xdr/ingest/routing/retained-raw*`, `/api/xdr/ingest/delivery/receipts`,
`/api/xdr/rbac/users/{id}/*`, `/api/xdr/windows/*`,
`/api/incidents/{id}/pivots`, `/api/incidents/{id}/canonical-evidence`.

### 2.3 · Classification of every required capability

| # | Capability | Source | Production today | After republish |
|---|---|---|---|---|
| 1 | endpoint enrolment | AVAILABLE | partial (token revoke NOT DEPLOYED) | AVAILABLE |
| 2 | endpoint/agent identity | AVAILABLE | AVAILABLE | AVAILABLE |
| 3 | agent session/auth | AVAILABLE | AVAILABLE | AVAILABLE |
| 4 | heartbeat | AVAILABLE | AVAILABLE | AVAILABLE |
| 5 | telemetry ingestion | AVAILABLE | AVAILABLE | AVAILABLE |
| 6 | endpoint inventory | AVAILABLE | partial (onboarding NOT DEPLOYED) | AVAILABLE |
| 7 | policy | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 8 | policy fetch/ACK | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 9 | exclusions | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 10 | durable findings | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 11 | evaluation state / negative explainability | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 12 | detections/events | AVAILABLE | partial (`/events*` NOT DEPLOYED) | AVAILABLE |
| 13 | trajectory | AVAILABLE | AVAILABLE | AVAILABLE |
| 14 | EDR audit | AVAILABLE | **NOT DEPLOYED** | AVAILABLE |
| 15 | non-destructive control plane | AVAILABLE | partial | AVAILABLE |
| — | destructive response | AVAILABLE | registered but **REQUIRES P0-PROD-4** | REQUIRES P0-PROD-4 |
| — | background/replica jobs | AVAILABLE | **REQUIRES P0-PROD-6** | REQUIRES P0-PROD-6 |

Nothing required is **NOT IMPLEMENTED**.

---

## 3 · EXACT FILES CHANGED

| File | Change | Why it was necessary |
|---|---|---|
| `backend/security/secret_policy.py` | Added `MANDATORY_PRODUCTION_CONFIG` (`EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_AGENT_SESSION_TTL_SECONDS`) and enforced it in `assert_production_ready()` — absent, blank, non-integer or non-positive now refuses to serve. | The enrolment store reads these with `os.environ[...]` at use time. Missing in production, the plane started happily and then **500-ed at the first enrolment**: a production incident disguised as a configuration omission. Boot-time refusal is the fail-closed behaviour the gate requires. |
| `backend/tests/test_p0prod3_backend_plane.py` | **NEW.** 16 focused tests (route inventory, unconditional wiring, production-mode start, fail-closed configuration, preview-vs-production key separation, fresh-empty-database behaviour, response fail-closed). | Gate proof. |

**No EDR behaviour, route, contract or authority logic was changed.** No
router was added, removed or re-registered. No frontend change.

---

## 4 · PRODUCTION ROUTER / APPLICATION WIRING

```
SOURCE IMPLEMENTED   → 77 EDR routes in routers/edr*.py
PRODUCTION BUILD     → single backend package; no per-environment build
ROUTER REGISTERED    → api.include_router(...) at module top level,
                       unconditional, for all 14 EDR routers
AUTHORITY ENFORCED   → console routes: Depends(get_current_user) + edr_tenant
                       agent routes:   session identity only (no user)
ROUTE SERVED         → verified in a real production-mode process (§7)
```

Startup wiring verified present in `server.py`: `validate_config()` →
`assert_production_ready()` → `init_database()` → index creation for raw
events, enrolment (**which now also creates the new
`edr_enrollment_audit` indexes**), rejections, response, policy,
exclusions, saved views, fabric evaluation state.

No Preview-only wiring exists: there is one application, one registration
block, one startup path.

---

## 5 · PRODUCT SCOPE

There is **no product-scope mechanism** in the backend — no
`PRODUCT_SCOPE`, no `NIVX_PRODUCT`, no EDR/XDR enable flag. One FastAPI
app serves both the NivXRay XDR and NivXForge EDR planes under `/api/*`.

Consequence, stated plainly: **it is not possible for deploying XDR to
remove EDR routes, or vice versa.** The required production configuration
is therefore "deploy the one backend"; there is no scope variable to set.
The two consoles are separate static front ends (Vercel) pointing at the
same API origin.

---

## 6 · TENANT AUTHORITY AND P0-PROD-2 INTEGRATION

Unchanged and re-proven:

- Console EDR tenant comes from `X-Tenant-Id` resolved through
  `services/tenant_registry.authoritative(...)`; the old
  `users["customer"] → "default"` fallback is gone (B5).
- The agent surface treats the presented tenant as a **claim to be
  matched**, never as authority: the token/credential is tenant-scoped, a
  wrong tenant simply fails to match, and on the telemetry leg the tenant
  is an **output** of `resolve_session()`.
- Enrolment **cannot create tenancy**; an unregistered tenant is
  indistinguishable from a bad token (one generic 401), so no enumeration
  oracle exists.
- P0-PROD-2 endpoint identity carries no console authority — re-verified
  live: a valid session token returns `401` on `/api/edr/audit`,
  `/api/auth/me`, `/api/edr/enrollment/*` and `/api/edr/response/actions`.

No default-tenant fallback, client-authoritative tenant selection or
cross-tenant read path was introduced.

---

## 7 · PRODUCTION BUILD / START PROOF (no production secrets)

`test_application_starts_in_production_mode_with_the_edr_plane` runs a
**separate process** with `NIVX_DEPLOYMENT_ENV=production` and a complete
set of clearly-labelled **non-production test secrets**, calls
`validate_config()` (which invokes `assert_production_ready()`), imports
the app, and asserts that all 49 enumerated required EDR routes are
present in that process. **PASS.**

Fail-closed proofs (against `assert_production_ready()` with the
environment patched in-process):

| Condition | Result |
|---|---|
| `EDR_AUTH_PEPPER` absent / blank / `changeme` | refuses, names the variable, **prints no value** |
| `EDR_ENROLLMENT_TOKEN_TTL_SECONDS` absent / `""` / `0` / `-1` / `not-a-number` | refuses |
| `EDR_AGENT_SESSION_TTL_SECONDS` same | refuses |
| `VERCEL_TOKEN` present in the app runtime | refuses |
| complete production-shaped environment | `enforced: true` |

An honest note recorded in the test itself: **a subprocess cannot prove
absence in this pod**, because `deps` calls
`load_dotenv(backend/.env)` on import and this pod's `.env` supplies the
EDR settings. Absence is therefore proven against the policy function
that `validate_config()` calls, with no dotenv reload. The positive start
proof remains a real subprocess.

---

## 8 · REQUIRED PRODUCTION SECRETS AND SETTINGS

Mandatory (production refuses to serve without them):

| Name | Purpose | Note |
|---|---|---|
| `JWT_SECRET` | operator session authenticity | |
| `EDR_AUTH_PEPPER` | endpoint credential/token digests | **GENERATE FRESH FOR PRODUCTION.** Must NOT be copied from preview — a copied pepper would make preview-issued endpoint credentials verifiable in production. Proven distinct-by-construction: the same secret digests differently under two peppers. |
| `XDR_AUDIT_MASTER_SECRET` | tamper-evident audit chain | |
| `XDR_SECRETS_MASTER` | connector/webhook secret envelope | |
| `NIVXRAY_SIGNING_SECRET` | evidence bundle signatures | |
| `XDR_ROOT_KEY` | credential vault root key | |
| `EDR_ENROLLMENT_TOKEN_TTL_SECONDS` | enrolment token TTL | **NEW boot requirement**; positive integer (900 recommended) |
| `EDR_AGENT_SESSION_TTL_SECONDS` | agent session TTL | **NEW boot requirement**; positive integer (300 recommended) |
| `NIVX_DEPLOYMENT_ENV=production` | declares the environment | set **after** the secrets exist, or the process correctly refuses |
| `MONGO_URL`, `DB_NAME`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `EMERGENT_LLM_KEY` | platform baseline | `ADMIN_PASSWORD` should be a fresh production value |

Must NOT be present in the production application runtime:
`VERCEL_TOKEN`, `TEST_ANALYST_NIVXLIVE_PASSWORD`.

Optional / deliberately absent: `XDR_RESPONSE_SERVICE_URL` — leave it
**unset** in production (see §10).

**No real production secret was generated or installed during this gate.**

---

## 9 · FRESH PRODUCTION DATABASE BEHAVIOUR

Proven against brand-new, throwaway databases (created and dropped in the
test):

- `store.ensure_indexes()` succeeds on an empty database — clean
  initialisation, **no migration**.
- `list_endpoints` → `[]`, `get_endpoint` → `None`, `list_tokens` → `[]`,
  and every enrolment collection has **zero** documents. Nothing is
  seeded; no synthetic tenant, endpoint, event or finding appears.
- A guessed token against a fresh database fails closed and creates
  nothing.
- Enrolment cannot create tenancy, so a legitimate production tenant must
  be registered by an authorised principal before any endpoint can enrol.

**Preview → production migration is NOT required and must not happen.**
Preview token/credential digests are peppered with the preview
`EDR_AUTH_PEPPER`; copying them would either be unverifiable or grant
preview endpoints production standing. Fresh endpoints enrol with
production-minted tokens.

Truthfulness: an empty production fleet is **EMPTY / NOT YET OBSERVED**,
never "verified clean". This is already the platform's semantics —
`sensor_state=ENROLLED_NEVER_REPORTED`, `BLIND_NO_DELIVERY`,
`NOT_EVALUATED != CLEAN` — and nothing in this gate weakened it.

**Per the directive, no production tenant was registered or modified.**
The requirement is documented, not executed.

---

## 10 · BLOCKED PENDING P0-PROD-4 (destructive response)

Registered so it can refuse **visibly**, not silently missing:
`/api/edr/response/actions` (GET/POST), `/response/actions/{command_id}`,
`/response/isolation-policy` (GET/PUT), `/api/edr/agent/commands`,
`/agent/command-result`, `/agent/command-verification`.

Fail-closed mechanism verified: `edr_plane/authority.py` reads
`XDR_RESPONSE_SERVICE_URL` from the environment with **no default and no
`localhost` anywhere in the module**; unconfigured yields
`503 RESPONSE_AUTHORITY_NOT_CONFIGURED` — "no response authority is
configured, so no destructive action can be authorised" — with the
honesty note "no command was recorded, authorised, dispatched or
executed".

**P0-PROD-4 dependencies:** eliminate the `localhost:8056` response
service coupling; give the response authority a private, non-public,
production-reachable address; prove approval → dispatch → execution →
independent verification end to end. Until then, **leave
`XDR_RESPONSE_SERVICE_URL` unset in production** — absence is refusal, and
refusal is correct. Nothing was weakened to make a route return 200.

---

## 11 · BLOCKED PENDING P0-PROD-6 (replica safety)

In-process background loops started at backend startup, which would run
in **every** replica (production has 2): nightly benchmark, LOLBAS
refresh, confusion-matrix prewarm, FileStore retention sweeper. Also
replica-sensitive: the collector's in-process delivery worker (separate
service, not in the backend deployment).

These are **BLOCKED PENDING P0-PROD-6** — duplicate-prone work must not be
enabled by this gate. None of them is required for any synchronous EDR
route to serve correctly, so the EDR plane is deployable with them still
gated. `.emergent/crons.yml` remains absent; no scheduled work was added.

---

## 12 · FRONTEND / BACKEND API CONTRACT

Console: `/app/apps/nivxray-xdr` (Vite) → **Vercel**, not the Emergent
frontend build (`/app/frontend` is a different CRA app with zero
`/xdr/*` or `/edr/*` routes).

Environment inputs: `REACT_APP_NIVXRAY_API_URL` (API origin),
`REACT_APP_WORKSPACE_URL`, `REACT_APP_XDR_URL`, `REACT_APP_EDR_URL`.
`apps/nivxray-xdr/scripts/verify-production-build.js` already **fails a
production build** that contains `preview.emergentagent.com`,
`localhost:8001` or `127.0.0.1:8001` — so the preview origin currently in
`.env` cannot silently ship.

EDR routes the console actually calls (11): `/api/edr/endpoints`,
`/endpoints/{id}/trajectory`, `/endpoints/{id}/linked-incidents`,
`/api/edr/enrollment/endpoints`, `/api/edr/device-trajectory`,
`/api/edr/file-trajectory` *(via trajectory views)*,
`/api/edr/process-tree`, `/api/edr/campaign-story`, `/api/edr/context`,
`/api/edr/telemetry/freshness`, `/api/edr/response/actions`,
`/api/edr/endpoint-commands`, `/api/edr/wave0/capabilities`.

**Contract blockers against production TODAY (all resolved by the
republish, none requiring a code change):**

| Route the console calls | Production today |
|---|---|
| `/api/edr/endpoint-commands` | 404 |
| `/api/xdr/rbac/me/effective` | 404 |
| `/api/xdr/scope/authorized` | 404 |
| `/api/xdr/scope/select` | 404 |
| `/api/xdr/windows/configuration` | 404 |

No stale route names were found (0 console routes absent from source). No
UI work was performed and none is required for the contract.

---

## 13 · FOCUSED TEST RESULTS

```
tests/test_p0prod3_backend_plane.py                16 passed
tests/test_p0prod1_secret_policy.py                28 passed
tests/edr/test_p0prod2_enrollment_hardening.py     25 passed
tests/edr/test_p0_a2_enrollment.py                 29 passed
                                                  ---------
                                                   82 passed (+16) 
```

**NEW REGRESSIONS: NONE.** No whole-suite rerun was performed (the change
surface is one production-configuration list plus a new test file). The
frozen baseline `BASELINE_PYTEST_PRE_P0PROD2.json` was not touched, no
unrelated failure was investigated, and no harness sweep was run.

---

## 14 · EXACT PRODUCTION SYNC PREREQUISITES

In order, at the deployment step (not now):

1. Generate a **fresh** production `EDR_AUTH_PEPPER` and a fresh
   `ADMIN_PASSWORD`; confirm the other five mandatory secrets exist in the
   deployment's secret store. **Never copy a preview value.**
2. Set `EDR_ENROLLMENT_TOKEN_TTL_SECONDS=900` and
   `EDR_AGENT_SESSION_TTL_SECONDS=300`.
3. Ensure `VERCEL_TOKEN` and `TEST_ANALYST_NIVXLIVE_PASSWORD` are **absent**
   from the backend runtime.
4. Leave `XDR_RESPONSE_SERVICE_URL` **unset** (destructive response stays
   fail-closed until P0-PROD-4).
5. Set `NIVX_DEPLOYMENT_ENV=production` **last** — order matters; declaring
   production before the secrets exist correctly refuses to serve.
6. **Republish the Emergent backend.** This is the actual fix for §1.
7. Verify production: `/api/openapi.json` route count ≈ source (862), and
   the §2.2 planes return `401/403` instead of `404`; `/api/health` 200.
8. Register the production tenant with an authorised principal (documented
   here, deliberately not executed).
9. Build/deploy the two Vercel consoles from `apps/nivxray-xdr` with
   `REACT_APP_NIVXRAY_API_URL` = the production API origin; the build
   verifier will reject a preview origin.
10. Verify console → production API connectivity, including the five §12
    routes.
11. Only then: real endpoint enrolment (P0-PROD-2 token), telemetry,
    detection. Destructive response remains disabled pending P0-PROD-4;
    duplicate-prone background jobs remain disabled pending P0-PROD-6.

---

## 15 · ROLLBACK CONSIDERATIONS

- **Backend**: the republish is additive — 67 routes appear, 0 disappear,
  and no schema or data shape changes. Rolling back to the current
  production build restores exactly today's behaviour; the only loss is
  the new planes.
- **New collection**: `edr_enrollment_audit` is created empty by
  `ensure_indexes`. An older build simply never writes or reads it; no
  rollback action is needed.
- **New boot requirement**: the two TTL settings are now mandatory in
  production. If they are ever removed, the process refuses to start —
  which is the intended direction, but it means a config rollback that
  drops them will take the service down rather than degrade it. Keep them
  in the secret/config store.
- **Consoles**: Vercel deployments are independently revertible to the
  prior build and are decoupled from the backend republish.
- **Fresh data**: no migration is performed, so there is no data rollback
  surface. Enrolments made after the republish remain valid across a
  backend rollback only if `EDR_AUTH_PEPPER` is unchanged — do not rotate
  the pepper as part of a rollback.

---

## 16 · FINAL OUTPUT

```
P0-PROD-3 STATUS:                            PASS

ROOT CAUSE OF STALE/MISSING PRODUCTION EDR PLANE:
  The production backend runs an OLDER BUILD of the same application.
  Production serves 795 of 862 source routes, a strict subset with ZERO
  routes removed or renamed; EDR routers are registered unconditionally
  and no product-scope/environment guard exists. Remedy = REPUBLISH +
  production configuration, not a code change.

EDR ENROLLMENT PLANE:                        READY
EDR AGENT PLANE:                             READY
EDR TELEMETRY PLANE:                         READY
EDR POLICY PLANE:                            READY (source+wiring; NOT DEPLOYED until republish)
EDR EXCLUSION PLANE:                         READY (source+wiring; NOT DEPLOYED until republish)
EDR FINDINGS PLANE:                          READY (source+wiring; NOT DEPLOYED until republish)
EDR AUDIT PLANE:                             READY (source+wiring; NOT DEPLOYED until republish)
TENANT ISOLATION:                            PASS
PRODUCTION BUILD/START PROOF:                PASS (production mode, non-production test secrets)
FRONTEND/API CONTRACT:                       READY after republish — 5 routes 404 today:
                                             /api/edr/endpoint-commands,
                                             /api/xdr/rbac/me/effective,
                                             /api/xdr/scope/authorized,
                                             /api/xdr/scope/select,
                                             /api/xdr/windows/configuration
P0-PROD-4 DEPENDENCIES:                      remove localhost:8056 coupling; private
                                             production response-authority address;
                                             approval→dispatch→execution→independent
                                             verification proof. Keep
                                             XDR_RESPONSE_SERVICE_URL unset until then.
P0-PROD-6 DEPENDENCIES:                      nightly benchmark loop, LOLBAS refresh loop,
                                             confusion-matrix prewarm, FileStore retention
                                             sweeper (all in-process, run in every replica);
                                             collector in-process delivery worker.
NEW REGRESSIONS:                             NONE
PRODUCTION DB:                               NOT MODIFIED
PRODUCTION DEPLOYMENT:                       NOT PERFORMED
VERCEL:                                      NOT DEPLOYED
PRODUCTION SYNC READINESS:                   GO

EVIDENCE: /app/memory/production-gates/P0PROD3_BACKEND_PLANE.md
```

**STOPPING FOR OWNER REVIEW.** No further gate started. Nothing
republished. Nothing deployed.
