# PRODUCTION SYNC · BACKEND

Owner authorisation: *OWNER REVIEW — P0-PROD-3 ACCEPTED / CLOSED ·
AUTHORIZE CONTROLLED PRODUCTION SYNC* (2026-06).

Status: **PHASE 1 COMPLETE · PHASE 2 (REPUBLISH) NOT PERFORMED — BLOCKED
ON TWO OWNER-ONLY ACTIONS.** No production secret was generated, read or
installed. No production database was contacted or modified. No tenant was
created. No Vercel deployment was touched. No real endpoint was enrolled.

No plaintext secret value appears anywhere in this document.

---

## 0 · WHY PHASE 2 STOPPED — STATED FIRST

The republish itself is **not an action this agent can perform**, and the
production configuration is **not something this agent can set**. Both are
deliberate platform boundaries, confirmed with platform support:

> "The Emergent agent has **full access to the preview pod** but has **NO
> access to the deployment pod**. To change your deployed app you must open
> **Manage Publishes** (Republish button) and click **Re-publish changes**."
> Production secrets live in **Manage Publishes → Secrets**, are
> **completely separate** from preview, and **only take effect after a
> redeploy**.

So Phase 1 was executed in full, including one **required code enablement**
(§2) without which the owner would have been unable to configure production
at all, and the republish now waits on the owner.

Two blocking owner actions, in order:

1. **Set the six production secret values** in Manage Publishes → Secrets
   (names in §1; values never in chat, never in code, never here).
2. **Click Re-publish changes.** Then run the one-command verification in
   §7 — or say the word and this agent will run it and report.

---

## 1 · AUTHORITATIVE PRODUCTION CONFIGURATION CHECKLIST

Derived from current source, not from memory. Three sources of truth were
read: `deps._REQUIRED_ENV` (fail-fast at boot for every environment),
`secret_policy.MANDATORY_PRODUCTION_SECRETS`,
`secret_policy.MANDATORY_PRODUCTION_CONFIG`, plus a repository scan for
direct `os.environ["…"]` subscripts (which raise rather than default).
That scan found only `MONGO_URL`, `DB_NAME`, `EMERGENT_LLM_KEY` and the two
EDR TTLs — all already covered. **The list below is complete.**

### 1.1 · Must be FRESH, production-only values (set in Secrets tab)

| # | Name | Purpose | Note |
|---|---|---|---|
| 1 | `JWT_SECRET` | operator session authenticity | fresh |
| 2 | `EDR_AUTH_PEPPER` | endpoint credential + enrolment-token digests | **fresh — NEVER copy preview.** A copied pepper would make preview-issued endpoint credentials verifiable in production |
| 3 | `XDR_AUDIT_MASTER_SECRET` | tamper-evident audit chain | fresh |
| 4 | `XDR_SECRETS_MASTER` | connector/webhook secret envelope | fresh |
| 5 | `NIVXRAY_SIGNING_SECRET` | evidence bundle signatures | fresh |
| 6 | `XDR_ROOT_KEY` | credential vault root key | fresh |
| 7 | `ADMIN_PASSWORD` | seeded admin | fresh production value (the old leaked value may still sit in the deployment secret store — see `test_credentials.md`) |

Strength guidance: ≥ 32 bytes of CSPRNG output, e.g.
`python3 -c "import secrets;print(secrets.token_urlsafe(48))"` run on the
owner's own machine. Each value must be **independent** — do not derive one
from another.

### 1.2 · Must be explicitly configured (non-secret, but boot-blocking)

| Name | Value | Why it is now mandatory |
|---|---|---|
| `EDR_ENROLLMENT_TOKEN_TTL_SECONDS` | `900` | P0-PROD-3: the enrolment store reads it with `os.environ[...]`. Absent, the plane used to boot fine and then **500 at the first enrolment**. It now refuses at boot. |
| `EDR_AGENT_SESSION_TTL_SECONDS` | `300` | same, for the agent session exchange |
| `NIVX_DEPLOYMENT_ENV` | `production` | **set LAST** (see §1.4) |
| `XDR_RESPONSE_SERVICE_URL` | **empty** | must NOT carry preview's `http://localhost:8056`. Empty = `503 RESPONSE_AUTHORITY_NOT_CONFIGURED` = correct fail-closed state until P0-PROD-4 |

### 1.3 · Must be ABSENT from the production backend runtime

`VERCEL_TOKEN`, `TEST_ANALYST_NIVXLIVE_PASSWORD`. Production refuses to
serve if either is present — a deploy token is a privilege the application
has no business holding. Neither exists in `backend/.env` (asserted by
test).

### 1.4 · ORDER MATTERS

```
1. set the seven §1.1 values            (Secrets tab)
2. set the four §1.2 settings           (Secrets tab; XDR_RESPONSE_SERVICE_URL empty)
3. confirm §1.3 names are absent
4. set NIVX_DEPLOYMENT_ENV=production   ← LAST
5. Re-publish changes
6. run §7 verification
```

Declaring `production` before the secrets exist makes the process refuse to
serve — correctly, but it would take the currently-live backend down at the
next deploy. **Secrets first, environment declaration last.** Note that a
Secrets-tab edit only takes effect on redeploy, so steps 1–4 can be done in
one sitting and published once.

Platform-managed and not to be touched: `MONGO_URL`, `DB_NAME`,
`CORS_ORIGINS`, `REACT_APP_BACKEND_URL` (re-derived on every deploy).

---

## 2 · REQUIRED CODE ENABLEMENT (the only change made in this phase)

**Problem discovered in Phase 1.** Platform support confirmed: *"To add a
NEW secret key you must ask the agent to add it to the `.env` file in code
first, then republish. You cannot add brand-new keys directly in the UI."*

P0-PROD-1 had (correctly) **removed** `XDR_AUDIT_MASTER_SECRET`,
`XDR_SECRETS_MASTER`, `NIVXRAY_SIGNING_SECRET` and `XDR_ROOT_KEY` from
`backend/.env`. Consequence: those four key names **did not exist in the
deployment's Secrets tab**, so the owner could not have configured them —
and a republish with `NIVX_DEPLOYMENT_ENV=production` would have refused to
boot with no way to fix it from the UI.

**Change made:** the four names were added to `backend/.env` with the
explicit value

```
PLACEHOLDER-SET-REAL-VALUE-IN-PRODUCTION-SECRETS-TAB
```

This is safe in both directions, by design:

- **Production**: the value matches `_PLACEHOLDER_TOKENS`, so
  `assert_production_ready()` **refuses to serve**. Exposure creates no
  weak default — it creates a configurable slot that must be filled.
  Proven by `test_placeholder_values_are_refused_in_production`.
- **Preview**: a placeholder is treated as "not configured", exactly as
  absence was, so preview continues to derive purpose-separated
  instance-local keys. Verified after a backend restart: `basis =
  DERIVED_INSTANCE_LOCAL` for all four, `/api/health` 200, P0-PROD-1 suite
  28/28 green.

A regression test now locks the rule:
`test_every_mandatory_production_key_is_exposed_for_configuration` fails if
any mandatory production key name is missing from `backend/.env` — because
an unexposed key is an unconfigurable key.

Files changed in this phase:

| File | Change |
|---|---|
| `backend/.env` | four mandatory key NAMES exposed with placeholder values (no secret added) |
| `backend/tests/test_p0prod3_backend_plane.py` | +2 tests (18 total): configurability lock, placeholder refusal |
| `scripts/verify_production_sync.py` | **NEW** — read-only post-republish verifier (§7) |

No application logic, route, authority or EDR behaviour was changed.

---

## 3 · PRODUCTION RESOURCE STATE

**UNKNOWN to this agent** — resources live in the deployment pod, which the
agent cannot read. Not inferred from preview, and the historical `tier_0`
observation is deliberately **not** reused.

Owner can read the true values at **Manage Publishes → Resources**
(current tier and credits/month). Platform defaults per support:
**containers launch with 2 replicas**, KEDA autoscaling per tier; on
Starter only one pod ever runs; on Launch, KEDA scales to one pod when
traffic drops below the activation threshold.

Judgement, as instructed: **sizing is not a reason to block the sync.**
There is no evidence current resources cannot boot or run the proven
backend — the same image already runs there today. One consequence to
record, not to fix here: **2 replicas is exactly the condition P0-PROD-6
exists for** (§9).

---

## 4 · ROLLBACK POINT

| Item | Value |
|---|---|
| Current production build / deployment ID | **UNKNOWN to this agent** — read it from Manage Publishes → Overview (top entry: date/time, deployment ID, commit hash) **before** republishing |
| Current production behaviour (measured, read-only) | 795 routes served, `/api/health` 200, EDR policy/exclusions/findings/audit/events absent (404) |
| Target build | preview `HEAD` = commit `f345a705` on branch `feature/rc2-alignment` (contains P0-PROD-1, P0-PROD-2, P0-PROD-3) |
| Rollback mechanism | Manage Publishes → Overview → rollback icon (↺) on a previous version → confirm. 1–3 minutes, zero downtime, skips the build (reuses the previous image). **Up to the 3 most recent successful deployments** are eligible |
| Rollback target | the deployment currently at the top of Overview — **record its ID before publishing** |

Rollback safety for this specific change (from the P0-PROD-3 analysis): the
republish is **additive** — 67 routes appear, 0 disappear, no schema or data
shape changes. Two cautions: (a) the new `edr_enrollment_audit` collection
is simply unused by an older build; (b) the two EDR TTL settings are now
boot-mandatory, so a config rollback that *removes* them would refuse to
start rather than degrade — keep them in the secret store. **Do not rotate
`EDR_AUTH_PEPPER` as part of a rollback**, or endpoints enrolled after the
republish lose their credentials.

---

## 5 · DATABASE SAFETY

- **No migration was performed and none is required.** Startup performs
  index creation only (`ensure_indexes` for raw events, enrolment — which
  now also creates the empty `edr_enrollment_audit` — rejections, response,
  policy, exclusions, saved views, fabric evaluation state). A fresh,
  empty database initialises cleanly; proven in P0-PROD-3 against
  throwaway databases.
- Platform-confirmed: **"On redeploy the production database is NOT
  touched"** — the same `MONGO_URL`/database continues to be used. Preview
  (`localhost:27017`, `test_database`) and production (Atlas) are separate
  instances.
- Nothing was copied from preview: no synthetic tenants, LAB endpoints,
  agent credentials, enrolment tokens, findings, test operators, incidents
  or telemetry.
- The deployment-agent scan independently confirmed **no destructive
  startup operation** (`delete_many` / `drop_collection` / `drop_database`)
  in any startup path.

**No DB mutation beyond normal application initialisation is required.** If
that ever changes, it stops for owner review first.

---

## 6 · PRODUCTION TENANT — READ-ONLY FINDING, NO MUTATION

Enrolment **cannot create tenancy** (by design), so a legitimate production
tenant must exist before any real endpoint enrols. Inspecting production
tenant state requires an authenticated production session, which this agent
does not hold and did not attempt.

Required operation, documented and **deliberately not performed**: an
authorised production principal registers the real tenant through the
authoritative registry (the XDR tenant surface), then mints an enrolment
token for that tenant. **No arbitrary `"default"` tenant may be created to
make enrolment work** — that was the exact B5 defect already closed.

Until then, an unregistered production tenant makes every enrolment fail
closed with the generic `401` — which will look like a token problem if
this step is forgotten. **No real endpoint was enrolled.**

---

## 7 · POST-REPUBLISH VERIFICATION — ONE COMMAND, READY TO RUN

```bash
python3 /app/scripts/verify_production_sync.py \
    --prod https://nivxray.nivxforge.com \
    --source http://localhost:8001
```

Read-only: unauthenticated probes only, no body, no credential, no
database. It checks four things and exits non-zero on any failure:

1. `/api/health` = 200;
2. deployed OpenAPI route count vs source (**expect 862**, and **0**
   source routes missing);
3. all 30 previously-absent paths are **ROUTED** (`401/403/405/422/503`),
   not `404`;
4. protected management APIs still **refuse** unauthenticated callers (a
   `200` is reported as a FAILURE, not a success), and
   `POST /api/edr/response/actions` has not become open.

**Baseline captured now, BEFORE the republish** (so the improvement is
provable rather than asserted):

```
health                     200
source routes              862
production routes          795
missing in production       67
previously absent planes   30/30 STILL ABSENT (404)
authority                  enrolment/endpoints/response refuse (403); agent 401
destructive response       POST /api/edr/response/actions -> 403
RESULT                     PRODUCTION SYNC VERIFICATION: FAIL  (expected pre-republish)
```

---

## 8 · AUTHORITY AND RESPONSE VERIFICATION (current production, read-only)

| Check | Current production | Verdict |
|---|---|---|
| `/api/edr/enrollment/tokens` unauthenticated | 403 | refused |
| `/api/edr/enrollment/endpoints` unauthenticated | 403 | refused |
| `/api/edr/endpoints` unauthenticated | 403 | refused |
| `/api/edr/agent/whoami` without a session | 401 | refused |
| `POST /api/edr/response/actions` unauthenticated | 403 | refused |
| Endpoint session used against console APIs (preview, P0-PROD-2) | 401 on audit, auth/me, enrollment, response | no privilege escalation |
| Cross-tenant disclosure | **NOT MUTATION-TESTED in production** — proving it would require creating production test tenants, which the directive forbids. Proven in preview by the accepted suites | as instructed |

Destructive response: expected to remain `RESPONSE_AUTHORITY_NOT_CONFIGURED`
(503) once `XDR_RESPONSE_SERVICE_URL` is empty in production.
**`XDR_RESPONSE_SERVICE_URL` was NOT configured to remove that 503.** A
deliberate fail-closed refusal is the correct state until P0-PROD-4.

---

## 9 · REPLICA SAFETY (P0-PROD-6 NOT AUTHORISED)

Unchanged by this phase, and **nothing was enabled**. Background work
started in-process at backend startup therefore runs in **every replica**
(platform default: 2): nightly benchmark, LOLBAS refresh, confusion-matrix
prewarm, FileStore retention sweeper. The collector's in-process delivery
worker is a separate service, not part of this deployment.

These are **BLOCKED PENDING P0-PROD-6**. They are not required for any
synchronous EDR route to serve correctly, so the backend is deployable with
them still gated. **Honest caveat the owner should know before publishing:**
these loops already run today in production under the same startup path —
the republish does not newly enable them, but it does not fix them either.
`.emergent/crons.yml` remains absent; no scheduled work was added.

---

## 10 · DEPLOYMENT READINESS SCAN — ONE FINDING, DELIBERATELY NOT ACTIONED

The static deployment scan reported one BLOCKER: the preview supervisor
runs the frontend as `yarn dev` in `/app/apps/nivxray-xdr` rather than
`yarn start` in `/app/frontend`.

**Not actioned, on purpose.** That is the owner's intended preview setup —
`apps/nivxray-xdr` *is* the console under review, and rewriting the
supervisor entry would break the preview console for a backend-only
republish. It is also not a republish blocker: the platform builds
`/app/frontend` from its own build pipeline (proven in the earlier
readiness audit), and the real consoles are the two **Vercel** projects.
Recorded, not improvised on.

Everything else in that scan passed: no hardcoded secrets, no hardcoded
URLs outside `.env`, CORS permits the production origin, MongoDB only, no
`dotenv override=True`, no destructive startup operations, compilation
clean.

---

## 11 · VERCEL CONSOLE SYNC PLAN (PREPARED, NOT EXECUTED)

Both consoles build from **one** source directory and **one**
`vercel.json`; the product is selected per project by an environment
variable. This is load-bearing, not cosmetic: `src/productScope.js` +
`components/ProductScopeGuard.jsx` are the only thing stopping
`xdr.nivxforge.com/edr/...` from rendering EDR on the XDR host.

| | NivXRay XDR | NivXForge EDR |
|---|---|---|
| Root directory | `apps/nivxray-xdr` | `apps/nivxray-xdr` |
| Install | `yarn install --production=false` | same |
| Build | `bash scripts/vercel-build.sh` | same |
| Output | `dist` | `dist` |
| `NIVX_PRODUCT_SCOPE` | `xdr` (or unset — defaults to xdr) | **`edr`** (required) |
| `XDR_PROD_API_ORIGIN` | `https://nivxray.nivxforge.com` | same |
| Host | `xdr.nivxforge.com` | `edr.nivxforge.com` |
| Source | branch `feature/rc2-alignment`, commit `f345a705` | same |
| Currently deployed build | **UNKNOWN to this agent** (read from each Vercel project's Deployments tab) — prior audit observed XDR built 2026-09-18, EDR 2026-09-09 | same |

Optional, leave OFF for now: `NIVX_CROSS_PRODUCT_ORIGINS=1` (plus
`NIVX_XDR_ORIGIN` / `NIVX_EDR_ORIGIN` / `NIVX_WORKSPACE_ORIGIN`) — turn on
only once **both** hostnames are live and verified, or the build ships dead
links.

Guard rails already in the repo: `scripts/verify-production-build.js` fails
the build if the artifact contains `preview.emergentagent.com`,
`localhost:8001` or `127.0.0.1:8001`, and it refuses an unscoped build. So
the preview origin in `apps/nivxray-xdr/.env` **cannot** silently ship.

**Order: backend republish and §7 verification FIRST.** Pointing the latest
consoles at a stale backend is exactly how the five §12-of-P0-PROD-3 routes
would 404 in a user's face. **Stopping for owner review before either
Vercel production deployment is changed.**

---

## 12 · REMAINING BLOCKERS

| # | Blocker | Owner action |
|---|---|---|
| 1 | Seven production secret values unset (§1.1) | set in Manage Publishes → Secrets |
| 2 | Four production settings unset (§1.2), incl. `NIVX_DEPLOYMENT_ENV=production` **last** and `XDR_RESPONSE_SERVICE_URL` **empty** | same panel |
| 3 | Rollback target ID not recorded | read Overview before publishing |
| 4 | Republish cannot be triggered by the agent | click **Re-publish changes** |
| 5 | Production tenant registration (§6) | after republish, before any real enrolment |
| 6 | Destructive response | stays fail-closed until P0-PROD-4 |
| 7 | Replica-unsafe background loops (§9) | until P0-PROD-6 |

---

## 13 · PHASE 4 RESULT (as far as this phase reached)

```
PRE-DEPLOYMENT CONFIGURATION:     COMPLETE (authoritative checklist §1; enablement §2)
PRODUCTION BACKEND REPUBLISH:     NOT PERFORMED — agent has no deployment-pod access;
                                  requires owner to set secrets and click Re-publish
PRODUCTION HEALTH (current):      PASS (200) — stale build
SOURCE ROUTES:                    862
PRODUCTION ROUTES:                795
ROUTE PARITY:                     FAIL — 67 source routes absent (37 EDR, 30 XDR); 0 extra
EDR ENROLLMENT/AGENT:             AVAILABLE (token revoke route absent until republish)
EDR POLICY:                       BLOCKED (404 — pending republish)
EDR EXCLUSIONS:                   BLOCKED (404 — pending republish)
EDR FINDINGS:                     BLOCKED (404 — pending republish)
EDR AUDIT:                        BLOCKED (404 — pending republish)
EDR EVENTS:                       BLOCKED (404 — pending republish)
XDR CURRENT ROUTES:               missing: /api/xdr/rbac/me/effective,
                                  /api/xdr/scope/authorized, /api/xdr/scope/select,
                                  /api/xdr/windows/configuration (+26 more)
AUTHORITY:                        PASS (all reachable protected routes refuse)
TENANT ISOLATION:                 NOT MUTATION-TESTED in production (by directive);
                                  PASS in preview
DESTRUCTIVE RESPONSE:             FAIL-CLOSED (403 unauthenticated; 503 once
                                  XDR_RESPONSE_SERVICE_URL is empty in production)
PRODUCTION DB MIGRATION:          NOT PERFORMED
REAL ENDPOINT ENROLLMENT:         NOT PERFORMED
ROLLBACK REQUIRED:                NO (nothing was deployed)
FOCUSED TESTS:                    18 passed (P0-PROD-3 suite, +2 this phase);
                                  44 passed with the P0-PROD-1 suite
NEW REGRESSIONS:                  NONE
VERCEL:                           NOT DEPLOYED (plan prepared, §11)
```

**STOPPING FOR OWNER REVIEW.** The deployment is not manufactured green:
route parity is FAIL today and will stay FAIL until the republish happens.
