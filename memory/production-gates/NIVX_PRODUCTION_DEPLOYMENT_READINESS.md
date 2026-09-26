# NIVX PRODUCTION DEPLOYMENT READINESS — AUDIT (READ-ONLY)

Owner directive *AUTHORIZE PRODUCTION DEPLOYMENT READINESS AUDIT ONLY*,
2026-09-26. Nothing was deployed, no production configuration was
changed, no database was migrated, no agent was touched, P0-D was not
resumed. The only writes made were two build artefacts
(`apps/nivxray-xdr/dist`, `frontend/build`) produced to verify that the
production builds compile.

**P0-INFRA-1 is reclassified as instructed: PREVIEW PLATFORM LIMITATION /
NOT AN APPLICATION DEFECT.** No application logic was changed to
compensate for it.

## VERDICT

# NOT READY — and the reason is bigger than a checklist

Two discoveries change the shape of the decision:

1. **A production deployment already exists and is LIVE.** The Emergent
   deployment `greeting-app-5782` serves `https://nivxray.nivxforge.com`
   (health 200), and two Vercel consoles are live at
   `https://xdr.nivxforge.com` (built 2026-09-18) and
   `https://edr.nivxforge.com` (built 2026-09-09), both pointing at that
   API origin. So "deploying" is **not** a first deployment: support's
   "first deploy migrates the preview database" note does **not** apply
   here, and the production database already exists independently.
2. **The Emergent deployment does not contain the console you review.**
   The deployed frontend is `/app/frontend` (CRA/craco) — proven by the
   platform's own build log in
   `deployer-agent-docs/RCA_8f382dd8….MD` ("Step #8 frontend-build-push
   … `frontend/src/pages/DocumentsPage.jsx`"). That app has **zero
   `/xdr/*` or `/edr/*` routes** (`grep -c` = 0) and its catch-all sends
   every unknown path to `/`. The NivXForge/NivXRay console you actually
   use lives in `/app/apps/nivxray-xdr` (Vite) and is deployed to
   **Vercel**, not Emergent.

And the production backend is far behind this preview:

| Route | Production | Preview |
|---|---|---|
| `/api/health` | 200 | 200 |
| `/api/edr/telemetry/freshness` | 403 (exists) | 403 |
| `/api/edr/response/actions` | 403 (exists) | 403 |
| `/api/edr/policies` | **404 absent** | 403 |
| `/api/edr/exclusions` | **404 absent** | 403 |
| `/api/edr/findings` (P0-C) | **404 absent** | 403 |
| `/api/edr/agent/policy` | **404 absent** | 401 |

So today production has **no exclusion plane (Gate 7 / P0-B), no durable
findings plane (P0-C), and no agent plane at all** — a NivXForge sensor
cannot even enrol against it. Redeploying the backend would fix the code
gap; it would not, by itself, give you the console, the agents or the
response authority.

---

## 1 · TOPOLOGY

### Current (preview pod, one container, supervisor)

| Component | Process | Port | Startup | Stateful | Emergent deploy? |
|---|---|---|---|---|---|
| Console (XDR/EDR) | `yarn dev` (Vite) in `/app/apps/nivxray-xdr` | 3000 | supervisor | no | **NO — not the directory Emergent builds** |
| Workspace UI | `/app/frontend` (CRA) — **not running in preview** | — | — | no | YES (this is what Emergent builds) |
| Backend | `uvicorn server:app --reload` | 8001 | supervisor | no | YES |
| MongoDB | `mongod --bind_ip_all` | 27017 | supervisor | **YES** | YES (managed Atlas in prod) |
| Redis | **none** — no runtime Redis anywhere | — | — | — | n/a |
| nginx | `nginx-code-proxy` (code-server only) | 8010/8080 | supervisor | no | platform-provided |
| NivXForge Linux sensor | `scripts/nivxforge_sensor_supervise.py` → `agents/nivxforge-linux/nivxforge_sensor.py run --api …` | — (outbound only) | supervisor | **YES** (`.state`) | **NO — belongs on the endpoint** |
| XDR collector | `uvicorn main:app` in `apps/nivxray-xdr-collector` | 8055 | supervisor | **YES** (`.state`) | **NO** (landed copy exists in-backend) |
| XDR response engine | `uvicorn main:app` in `apps/nivxray-xdr-response` | 8056 | supervisor | **YES** (`data/`) | **NO** — but see §4, EDR authority depends on it |
| Background loops | in-process `asyncio.create_task`: nightly benchmark, LOLBAS refresh, confusion prewarm, FileStore retention sweeper | — | backend startup | writes Mongo | YES (runs in **every replica** — prod has 2) |
| Scheduled jobs | `webhook-crond` (platform); `/app/.emergent/crons.yml` **absent** → no app cron defined | — | supervisor | no | platform |
| Queues | none (no broker; delivery worker is in-process in the collector) | — | — | — | n/a |

### Target

```
Protected Windows/Linux endpoint
  └─ NivXForge sensor (installed on the host)
       └─ TLS → https://<prod-backend>/api/edr/agent/*      (device-credential session)
             → tenant validation → raw event (immutable)
             → canonical evidence → XDR detection → DURABLE FINDING (P0-C)

Analyst browser
  └─ https://edr.nivxforge.com  (static console, Vercel or Emergent)
       └─ HTTPS + Bearer JWT + X-Tenant-Id → https://<prod-backend>/api/*
             → identity → tenant → permission → APPROVAL (response authority)
             → dispatch → endpoint executes → result → independent verification

Response authority (apps/nivxray-xdr-response)
  └─ reachable ONLY from the backend, private network / same pod — never public
```

---

## 2 · LOCALHOST / PREVIEW COUPLING (file · line)

| Evidence | Effect in production |
|---|---|
| `/etc/supervisor/conf.d/nivxforge_sensor.conf` → `NIVXFORGE_SENSOR_API="http://localhost:8001"`, `NIVXFORGE_SENSOR_TENANT="default"` | the preview sensor reports to the in-pod backend. **Preview-only shortcut** |
| `scripts/nivxforge_sensor_supervise.py:99-100` → `os.environ.get("NIVXFORGE_SENSOR_API", "http://localhost:8001")`, tenant default `"default"` | the only hardcoded localhost in the sensor path — in the **wrapper**, not the sensor |
| `scripts/nivxforge_sensor_supervise.py:73-83` → bootstraps enrolment with `ADMIN_EMAIL` / `ADMIN_PASSWORD` from `backend/.env` | **must never ship to a real endpoint**: a protected host would hold operator credentials. Production enrolment must use a one-time enrolment token only |
| `/etc/supervisor/conf.d/xdr_collector.conf` → `NIVX_INGEST_URL="http://localhost:8001/api/xdr/ingest/telemetry"`, `NIVX_TENANT_ID="nivx-live"`, `NIVX_COLLECTOR_ID="col_6551885c766a458ab315"` | collector → localhost backend, with a **hardcoded tenant and collector id** |
| `/etc/supervisor/conf.d/xdr_response.conf` → `NIVX_BASE_URL="http://localhost:8001"`, `NIVX_RESPONSE_EVIDENCE_URL="http://localhost:8001/api/xdr/response-evidence"`, `NIVX_RESPOND_CORS_ORIGINS="*"` | response engine → localhost backend; CORS `*` on a service that must not be public |
| `backend/.env` → `XDR_RESPONSE_SERVICE_URL=http://localhost:8056` | **the EDR response authority target** (see §4) |
| `backend/.env` → `MONGO_URL="mongodb://localhost:27017"`, `DB_NAME="test_database"` | platform-managed in deployment; note the database is literally named `test_database` |
| `apps/nivxray-xdr/.env:2` → `REACT_APP_NIVXRAY_API_URL=https://greeting-app-5782.preview.emergentagent.com` | **a preview origin in the console's build input**. Guarded: `apps/nivxray-xdr/scripts/verify-production-build.js:15,97-98` fails a production build that contains `preview.emergentagent.com`, `localhost:8001` or `127.0.0.1:8001` |
| `apps/nivxray-xdr/.env.example:1` | same preview origin used as the documented example |
| `/etc/supervisor/conf.d/supervisord.conf` (backend) → `APP_URL="https://630704a1-….preview.emergentagent.com"` | preview identity injected by the platform |

**Sensor code itself is clean**: `agents/nivxforge-linux/nivxforge_sensor.py:1259,1263` and
`agents/nivxforge-windows/nivxforge_sensor.py` make `--api` **required**
with no default, and use `urllib.request` with default TLS verification
(no `ssl._create_unverified_context` anywhere). The Windows installer
already takes `-BackendUrl` and refuses to run without it
(`Install-NivXForgeSensor.ps1:107,135,144`). So the localhost coupling is
**deployment configuration, not agent code** — exactly as you suspected.

---

## 3 · ENVIRONMENT / SECRETS (names only — no values printed)

The backend reads **121 distinct environment names**. Security-relevant
set:

| Name | Class | Preview | Production requirement |
|---|---|---|---|
| `MONGO_URL`, `DB_NAME` | REQUIRED · SECRET | set | platform-provided; note `DB_NAME=test_database` |
| `JWT_SECRET`, `JWT_EXPIRE_HOURS` | REQUIRED · SECRET | set | **must be a different value in prod** |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_FORCE_PASSWORD_CHANGE` | REQUIRED · SECRET | set | **must be rotated**; the preview password is in `/app/memory/test_credentials.md` |
| `EDR_AUTH_PEPPER` | REQUIRED · SECRET | set | device-credential hashing — a different pepper means **preview credentials cannot verify in prod** (correct, but plan re-enrolment) |
| `EDR_ENROLLMENT_TOKEN_TTL_SECONDS`, `EDR_AGENT_SESSION_TTL_SECONDS` | REQUIRED | set | carry over |
| `XDR_RESPONSE_SERVICE_URL`, `_TIMEOUT` | REQUIRED for response | set → `localhost:8056` | **must point at a real response authority, privately** |
| `CORS_ORIGINS` | REQUIRED | `*` | with `*` the server **forces `allow_credentials=False`** (`backend/security/cors.py`). Auth is Bearer-from-`localStorage`, no cookies (`apps/nivxray-xdr/src/lib/api.js:30`), so `*` works — but an explicit allow-list of the console origins is the correct production setting |
| `NIVX_TENANT_REGISTRY_ENFORCE` | REQUIRED | `true` | keep `true` |
| `XDR_AUDIT_MASTER_SECRET` | **SECRET · MISSING** | unset | `routers/xdr_audit_log.py:55` falls back to the literal `"xdr-audit-master-do-not-use-in-prod"` → **the per-tenant audit HMAC chain is forgeable by anyone with the source** |
| `XDR_SECRETS_MASTER` | **SECRET · MISSING** | unset | `routers/xdr_secrets.py:54-70` falls back to a deterministic dev key → **stored connector secrets are decryptable from source** |
| `XDR_ROOT_KEY` | SECRET · MISSING | unset | credential vault `EnvRootKeyProvider` raises `KeyError` without it (fails closed) |
| `NIVXRAY_SIGNING_SECRET` | SECRET · MISSING | unset | `v2/report/bundle.py:43-47` falls back to a fixed-salt derivation → **exported evidence bundle signatures are reproducible by a third party** |
| `EMERGENT_LLM_KEY`, `VT_API_KEY`, `OTX_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY`, `ABUSE_CH_AUTH_KEY`, `HYBRID_ANALYSIS_API_KEY` | OPTIONAL · SECRET | set | feature-scoped; enrichment degrades honestly without them |
| `VERCEL_TOKEN` | **SECRET · PREVIEW_ONLY** | set in `backend/.env` | a deploy credential sitting in the app's runtime env — **must not exist in the production backend** |
| `TEST_ANALYST_NIVXLIVE_PASSWORD` | PREVIEW_ONLY | set | test-harness credential; must not ship |
| `NIVX_ENGINE*`, `NIVX_FLAG_*`, `IUE_*`, `RC5_DIAG_ENABLED` | OPTIONAL | set | review each flag's prod value deliberately |
| Console build: `REACT_APP_NIVXRAY_API_URL` / `XDR_PROD_API_ORIGIN`, `NIVX_PRODUCT_SCOPE` | PRODUCTION_ONLY | n/a | `NIVX_PRODUCT_SCOPE` is **not cosmetic**: without it one host renders both products (`scripts/refuse-root-deployment.sh`) |

No Redis configuration is needed — the runtime uses none.

---

## 4 · SECURITY BOUNDARY

The EDR surface is already classified in code
(`routers/edr_tenancy.py`): **60 TENANT_SCOPED · 16 PRODUCT_METADATA ·
11 SENSOR_SCOPED**, and 308 live authority tests hold the line.

| Exposure | What belongs there |
|---|---|
| **PUBLIC** | `/api/health`, `/api/health/deep` (liveness/readiness only) · `/api/auth/login` · the static console bundle |
| **AUTHENTICATED PUBLIC** | the whole console API: `/api/edr/*` (60 tenant-scoped reads/writes) and `/api/xdr/*` — JWT + `X-Tenant-Id` + tenant authority + RBAC |
| **SERVICE-TO-SERVICE (internet-reachable, device-authenticated)** | `/api/edr/agent/*` — the 11 SENSOR_SCOPED routes. Sensors on real endpoints must reach these over TLS with a device credential, never with operator credentials · `/api/xdr/ingest/telemetry` (scoped API key carrying `collectors.enroll`) |
| **INTERNAL ONLY — must never be public** | the response authority `apps/nivxray-xdr-response` (:8056) and the standalone collector (:8055). Both currently run with `allow_origins="*"`; the collector's standalone guard **fails closed** (`framework/authz.py` → `COLLECTOR_AUTH_UNAVAILABLE`) but the response engine has **no authentication dependency of its own** — it is safe only because nothing outside the pod can reach it |

**The single most important boundary fact:** `edr_plane/authority.py:90-181`
resolves the authoritative action catalogue and every approval from
`XDR_RESPONSE_SERVICE_URL`. With no reachable response authority it
raises `RESPONSE_AUTHORITY_NOT_CONFIGURED` / `RESPONSE_AUTHORITY_UNAVAILABLE`
(503) and **fails closed — "no command was recorded, authorised,
dispatched or executed"**. That is correct behaviour and it means a
deployment without a private response authority has a **console where
every response action returns 503**. Do not "fix" that by exposing
:8056 publicly; it has no identity, no RBAC and no tenant registry of
its own.

---

## 5 · ENDPOINT AGENT ARCHITECTURE — what must change

Almost nothing in the agents; everything in how they are configured.

1. **Nothing to change in the sensors' transport**: `--api` is already
   required, TLS verification is on by default, and the Windows
   installer already parameterises `-BackendUrl`.
2. **Replace the preview bootstrap.** `scripts/nivxforge_sensor_supervise.py`
   logs in as the operator and mints its own enrolment token. A
   production install must receive a **one-time enrolment token** issued
   from the console; the host must never hold `ADMIN_*` credentials.
3. **Tenant must be explicit per install** — today it defaults to
   `"default"` in the wrapper.
4. **Deploy the agent plane first.** `/api/edr/agent/policy` is **404 in
   production**: no sensor can enrol or report there until the current
   backend is redeployed.
5. **Pepper continuity**: device credentials are hashed with
   `EDR_AUTH_PEPPER`. A production pepper (correctly) invalidates the
   preview credentials — plan re-enrolment rather than migration.
6. **Response path needs the authority reachable privately** (§4) plus
   the endpoint-side verification the sensor already performs
   (`_verify_isolation`, `_verify_command`).
7. **Egress reality check**: sensors need outbound 443 to the production
   host; nothing inbound to the endpoint.

---

## 6 · DATABASE MIGRATION SAFETY

**Correction to the premise:** production already exists, so a redeploy
does **not** migrate this preview database. The risk is only real if a
*new* deployment is created. If one is, this is what would travel:

Preview DB `test_database` — **167 collections · 1 508 685 documents**.
Largest: `xdr_cortex_scheduler_audit` 285 174 · `xdr_vault_audit` 230 437 ·
`edr_raw_events` 224 394 · `v2_shadow_observations` 224 199 ·
`xdr_canonical_evidence` 221 336 · `iocs` 128 551.

**MUST NOT become production data:**

| Finding | Evidence |
|---|---|
| **284 of 290 `default` endpoint registrations are synthetic** | hostnames `LAB-ENV` ×98, `LAB-ADV-01` ×93, `LAB-REVKILL` ×93, plus `E2E-WIN-*`, `REHEARSAL-*`. Only `LAB-LINUX-01` (this container) is real. A prod console would show ~290 fake computers |
| **93 tenants in the registry**, most throwaway | `smoke-validation` (ARCHIVED), `p0f-keyauth-test`, `p0f-keyauth-other`, `p08-*`, `gate-*`, `rbac-enf-*`, `a05-*` |
| **321 `edr_agent_credentials` for tenant `default`** | one per re-enrolment of the same preview box |
| **Test operator accounts** | `*@nivxray.test`, `*@nivxray.gate`, `*@example.com`, `analyst@default.com`, `analyst@nivx-live.com` — plus `admin@nivxray.com` whose password is in `/app/memory/test_credentials.md` |
| **27 collectors in `default` + 63 in `p08-*` test tenants** | `xdr_collectors`; the preview collector id `col_6551885c766a458ab315` is hardcoded in supervisor |
| **Test-tenant rows in the new P0-C collections** | `edr_findings`: 16 in `default`, 1 in `p0f-7d821ed9`; `edr_finding_evaluations`: 2 938 in `default`, 4 rows across `p0b-*`/`p0f-*` |
| **`xdr_response_executions`: 4 rows with `tenant_id: null`, 2 in tenant `acme`** | untenanted response/audit history |
| **`edr_raw_events` / `xdr_canonical_evidence` are rehearsal telemetry** | 224 k events from one container, not a customer estate |
| **Empty in preview, must be seeded deliberately in prod** | `tenant_registry` (0), `api_keys` (0), `edr_enrollment_tokens` (0) |

Nothing was deleted or modified. **Recommendation: never migrate this
database.** Stand production up with a deliberately seeded tenant
registry and admin, and let real endpoints populate evidence.

---

## 7 · BUILD / ROUTING / CORS

| Check | Result |
|---|---|
| Console production build (`apps/nivxray-xdr`, Vite) | **PASS** — `✓ built in 4.75s`, exit 0, 40+ code-split chunks incl. `EdrDeviceTrajectoryPage`, `XdrIncidentDetailPage` |
| Workspace production build (`/app/frontend`, craco — what Emergent builds) | **PASS** — exit 0 in 59 s |
| Guarded production build | `scripts/vercel-build.sh` + `verify-production-build.js` enforce: no preview origin, no `localhost:8001`, `REACT_APP_PRODUCT_SCOPE` present. **Not exercised in this audit** (it needs the production env vars) |
| Backend startup | clean; `Application startup complete`, all routers mounted; the only startup warning is a **pre-existing legacy index conflict** on `edr_raw_events` (P0-C's own indexes are created in their own guarded block and log `EDR findings + evaluation-state indexes ensured`) |
| `/api/*` | 200/401/403 as classified, both preview and prod |
| SPA deep links — Vercel consoles | **OK**: `vercel.json` rewrites `/(.*) → /index.html`, plus host-based `/ → /xdr` and `/ → /edr` redirects (confirmed live: both hosts answer **307**) |
| SPA deep links — Emergent deployment | **Serves index.html for any path** (platform nginx, per the RCA), **but the deployed app has no `/xdr/*` or `/edr/*` routes** and its catch-all is `<Route path="*" → Navigate to "/">`. So `/xdr/control-center`, `/edr/computers` and `/edr/computers/<id>/trajectory` would **load the Workspace app and bounce to `/`** — not 404, which is worse: it looks alive |
| CORS | `CORS_ORIGINS="*"` → wildcard with `allow_credentials` **forced off** (`security/cors.py`). Safe because auth is a Bearer token from `localStorage`, not cookies |
| Cookies / sessions | none used for auth → no SameSite/cross-site issues |
| WebSocket / SSE | none for the console; `StreamingResponse` is used only for file/report downloads |
| Health | `/api/health` (liveness) and `/api/health/deep` (Mongo + LLM key + disk) both present |

---

## 8 · PRODUCTION DATA TRUTH (P0-C invariant under deployment)

The invariant holds by construction, and deployment does not weaken it:

* The finding plane never infers "clean" from an empty collection. State
  comes from `edr_finding_evaluations`, written only at a real evaluation
  attempt, and **evidence with no row reads `NOT_EVALUATED ·
  NO_EVALUATION_RECORDED`** (`edr_plane/fabric/evaluation_state.py`).
* A fresh production database therefore reports *nothing evaluated*, not
  *nothing wrong* — which is exactly what it must say until a real sensor
  reports.
* `EVALUATION_FAILED` and `EVALUATION_SUPPRESSED_BY_EXCLUSION` remain
  separate from `EVALUATED_NO_FINDING`; every response carries
  `truth_semantics` and `local_behavioral_engine_present: false`.
* **Migrated vs new telemetry stays distinguishable**: findings are
  content-addressed on the tenant, and carry `created_at`, `first_seen`,
  `last_seen`, `detection_source` and resolvable `evidence_refs`. If data
  were ever migrated, a provenance marker on the migrated rows would
  still be needed to avoid a prod console presenting rehearsal evidence
  as production evidence — one more reason not to migrate.
* Production has **2 replicas**: the finding write path is idempotent
  (content-addressed upsert, write-once analytic fields), so concurrent
  replicas cannot duplicate or rewrite a finding. The in-process
  background loops (nightly benchmark, retention sweeper) **would run in
  both replicas** — not a data-truth risk, but duplicated work.

---

## 9 · BLOCKERS AND WHAT MUST CHANGE

### Deployment blockers (must close before the console is usable in prod)

| # | Blocker | Why |
|---|---|---|
| B1 | **Emergent deploys `/app/frontend`, which has no `/xdr/*` or `/edr/*` routes** | the console you review would not exist at the deployed URL; deep links silently bounce to `/` |
| B2 | **Production backend is missing the EDR control plane** (`/policies`, `/exclusions`, `/findings`, `/agent/*` all 404) | no exclusions, no durable findings, and **no sensor can enrol** |
| B3 | **No response authority in a deployment** (`XDR_RESPONSE_SERVICE_URL → localhost:8056`) | every destructive action fails closed with 503; must be deployed privately, never public |
| B4 | **Dev fallback secrets** — `XDR_AUDIT_MASTER_SECRET`, `XDR_SECRETS_MASTER`, `NIVXRAY_SIGNING_SECRET` unset | audit-chain HMAC, connector-secret envelope and evidence-bundle signatures are all derivable from source ("do-not-use-in-prod" is the literal fallback) |
| B5 | **`VERCEL_TOKEN` and test credentials live in `backend/.env`** | a deploy credential and harness passwords must not exist in a production runtime |
| B6 | **tier_0 repeats the outage you just saw** | the platform's own RCAs show 250 m CPU / 512 Mi caused 520/524 and liveness-kill restarts on this exact app. Tier_1+ is a prerequisite, not an optimisation |
| B7 | **Agent bootstrap uses operator credentials** | `nivxforge_sensor_supervise.py` must not be the production install path |
| B8 | **Never migrate `test_database`** | ~290 synthetic endpoints, 93 test tenants, 321 stale credentials, test operator accounts |

### Required pre-deployment changes (for a later, authorised slice)

1. Decide the console's production home: keep the two Vercel projects
   (already correct, guarded and live) **or** make the Emergent
   deployment build `apps/nivxray-xdr`. Do not deploy `/app/frontend`
   expecting the EDR console.
2. Redeploy the backend so the EDR control plane and agent plane exist in
   production (B2), with tier_1+ (B6).
3. Stand up the response authority privately and point
   `XDR_RESPONSE_SERVICE_URL` at it (B3).
4. Generate and set the four missing secrets; rotate `JWT_SECRET`,
   `ADMIN_PASSWORD` and `EDR_AUTH_PEPPER`; remove `VERCEL_TOKEN` and the
   test credential from the production env (B4, B5).
5. Set `CORS_ORIGINS` to the explicit console origins.
6. Seed the production tenant registry and admin deliberately; do not
   migrate (B8).
7. Replace the sensor bootstrap with one-time-token enrolment and an
   explicit tenant per install (B7).

### Required post-deployment validation

`/api/health` and `/api/health/deep` · login → tenant selection ·
`/api/edr/findings/taxonomy` returns `implemented_detection_sources =
[XDR_PLATFORM_DETERMINISTIC_DETECTION]` and
`local_behavioral_engine_present: false` ·
`/api/edr/findings/evaluation-state` reports **NOT_EVALUATED ·
NO_EVALUATION_RECORDED** for a fresh estate (never "clean") · deep-link
navigation to `/xdr/control-center`, `/edr/computers`,
`/edr/computers/<id>/trajectory` · a real endpoint enrols with a one-time
token and produces raw event → canonical evidence → detection → durable
finding · a destructive action is refused without an authoritative
approval and succeeds only with one · cross-tenant reads refused ·
15-minute availability probe against the deployed origin.

---

## FINAL CLASSIFICATION

**NOT READY.** Eight blockers, four of them security-relevant (B3–B5,
B7). None of them are defects in NivXForge itself: they are the
deployment topology, the production secret set, and the fact that the
live production build predates the entire EDR control plane. The agents
are in better shape than expected — `--api` is already required and TLS
verified, so the localhost coupling is configuration, exactly as you
said.
