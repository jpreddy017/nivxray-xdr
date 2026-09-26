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

---

## 14 · PRE-REPUBLISH CLOSURE — OWNER-SUPPLIED PRODUCTION FACTS (2026-06)

Supersedes the UNKNOWN entries in §3 and §4. Supplied by the owner from
Manage Publishes; not inferred, not read by the agent.

### 14.1 · Deployment identity and rollback

| | Publish | Build id |
|---|---|---|
| **Current live** | **100** | **e075550** |
| Rollback target 1 | 99 | 3308216 |
| Rollback target 2 | 98 | 540d478 |

Two usable rollback targets exist → the "no usable rollback target" stop
condition is **not** triggered.

### 14.2 · Production resources

**Scale tier · 2 vCPU · 8 GB RAM · 450 credits/month.**

Sufficient to boot and run the proven backend (the same image already runs
there). Not a sync blocker. Replica count is autoscaled by the platform
(default 2) — which is exactly the condition P0-PROD-6 exists for (§9);
recorded, not turned into a project.

### 14.3 · Secrets panel state as inspected by the owner

Visible as **"Added, not live yet"** — these are the four names this phase
exposed in `backend/.env` (§2) plus the environment declaration, so the
enablement worked as intended:
`XDR_AUDIT_MASTER_SECRET`, `XDR_ROOT_KEY`, `XDR_SECRETS_MASTER`,
`NIVXRAY_SIGNING_SECRET`, `NIVX_DEPLOYMENT_ENV`.

**These four carry the `PLACEHOLDER-…` value from `backend/.env` and are
NOT production-ready.** Production refuses a placeholder, so publishing
with `NIVX_DEPLOYMENT_ENV=production` before the real values are entered
would correctly refuse to serve. Re-verified this run by
`test_placeholder_values_are_refused_in_production`.

Already present: `JWT_SECRET`, `ADMIN_PASSWORD`, `EDR_AUTH_PEPPER`,
`EDR_AGENT_SESSION_TTL_SECONDS`, `EDR_ENROLLMENT_TOKEN_TTL_SECONDS`.

### 14.4 · Three confirmed production configuration defects (owner action)

| Key | Current production state | Required | Why |
|---|---|---|---|
| `VERCEL_TOKEN` | **Live value present** | removed, or **set to empty** | a deployment-plane token is authority the application must never hold; production refuses to serve while it is populated |
| `TEST_ANALYST_NIVXLIVE_PASSWORD` | **Live value present** | removed, or **set to empty** | a test credential must not exist in a production runtime; production refuses to serve while it is populated |
| `XDR_RESPONSE_SERVICE_URL` | **Live value present** | **empty** | it would point production at a response authority that has not passed P0-PROD-4. Empty = `503 RESPONSE_AUTHORITY_NOT_CONFIGURED` = correct |

**No code change was required for any of the three** — current source
already fails closed on all of them. Two facts that matter for the UI:

1. **Emptying is sufficient.** The policy tests
   `(os.environ.get(name) or "").strip()`, so a blank value is treated as
   absent. Proven this run by
   `test_an_emptied_forbidden_credential_is_accepted`, which also asserts
   that a populated value is still refused **and that no value is ever
   printed in the refusal**.
2. **The agent cannot do it.** There is no supported mechanism for an
   agent without deployment-pod access to change a production secret.
   Nothing was performed; this is an owner action.

Neither forbidden secret's value was read, logged, tested against or
reproduced anywhere.

### 14.5 · Response safety re-verified with an empty authority

`test_production_is_ready_with_an_empty_response_authority`: production
readiness **passes** with `XDR_RESPONSE_SERVICE_URL` empty,
`authority._service_url()` is `None`, and the key is in neither mandatory
list — so an empty response authority can never block startup, and the
backend cannot silently fall back to a local executor or a second
authority. No response URL was invented to make a check green.

### 14.6 · Focused validation this run

```
tests/test_p0prod3_backend_plane.py            20 passed  (+2 this phase)
tests/test_p0prod1_secret_policy.py            28 passed
tests/edr/test_p0prod2_enrollment_hardening.py 25 passed
tests/edr/test_p0_a2_enrollment.py             29 passed
                                              ----------
                                              102 passed · 0 failed
preview backend /api/health                    200
source route inventory                         862
```

No full-suite run. No database work. No tenant. No endpoint. No Vercel.
No production mutation of any kind.

### 14.7 · Owner click sequence

```
Manage Publishes → Secrets
  1. XDR_AUDIT_MASTER_SECRET   ← fresh strong value (replace PLACEHOLDER)
  2. XDR_SECRETS_MASTER        ← fresh strong value (replace PLACEHOLDER)
  3. NIVXRAY_SIGNING_SECRET    ← fresh strong value (replace PLACEHOLDER)
  4. XDR_ROOT_KEY              ← fresh strong value (replace PLACEHOLDER)
  5. EDR_AUTH_PEPPER           ← fresh strong value (NEVER the preview one)
  6. JWT_SECRET                ← fresh strong value
  7. ADMIN_PASSWORD            ← fresh strong credential
  8. EDR_ENROLLMENT_TOKEN_TTL_SECONDS = 900
  9. EDR_AGENT_SESSION_TTL_SECONDS    = 300
 10. XDR_RESPONSE_SERVICE_URL         = (empty)
 11. VERCEL_TOKEN                     = (empty / removed)
 12. TEST_ANALYST_NIVXLIVE_PASSWORD   = (empty / removed)
 13. NIVX_DEPLOYMENT_ENV              = production      ← LAST
Manage Publishes → Overview → Re-publish changes
```

Rollback if anything fails: Overview → ↺ on **Publish 99 / 3308216**.
Do **not** rotate `EDR_AUTH_PEPPER` as part of a rollback.

### 14.8 · Post-republish verifier

```bash
python3 /app/scripts/verify_production_sync.py \
    --prod https://nivxray.nivxforge.com \
    --source http://localhost:8001
```

Target: `862 / 862`, missing `0`, health `200`, all previously-absent
planes ROUTED, every protected route still refusing, and
`POST /api/edr/response/actions` never `200`.

**STATUS: READY FOR OWNER REPUBLISH** once §14.4 and §14.7 are done.

---

## 15 · PLATFORM SECRET CONSTRAINT — POLICY FIX (2026-06)

### 15.1 · Root cause

`TEST_ANALYST_NIVXLIVE_PASSWORD` cannot be removed and the deployment UI
**refuses to save it blank** ("Couldn't save"). Yet
`assert_production_ready()` refused production purely because the key
*existed*. Those two facts together made production **unreachable by any
sequence of allowed operator actions** — a fail-closed check that cannot
be satisfied is not security, it is an outage.

The original rule was written for a key that a production path might
consume. Neither of these keys is such a key. Verified by scanning the
whole repository: the **only** references to
`TEST_ANALYST_NIVXLIVE_PASSWORD` outside the policy module and the test
suite are in `scripts/p0_3_sensor_recovery_proof.py` (a development proof
harness that never ships or runs in the deployment). `VERCEL_TOKEN` has
**zero** references anywhere outside the policy declaration itself.

### 15.2 · Exact policy change

`backend/security/secret_policy.py`

```
FORBIDDEN_IN_PRODUCTION = ()                  # hard refusal; mechanism intact
INERT_IN_PRODUCTION     = ("VERCEL_TOKEN",
                           "TEST_ANALYST_NIVXLIVE_PASSWORD")
```

An INERT key may be present, is **reported on every readiness report**
(`inert_present: [...]`, names only), and is **never consumed**.
Membership is not a promise — it is an assertion under test:

`test_inert_production_keys_have_no_production_consumer` scans **every**
`.py` file under `/app/backend` except `tests/` and the declaring module,
and fails if any of them so much as names an inert key. The moment
somebody wires a consumer, the build breaks and the key must return to
`FORBIDDEN_IN_PRODUCTION`.

The hard-refusal machinery is still tested — against a declared forbidden
name rather than against a key the platform makes unremovable
(`test_production_refuses_a_declared_forbidden_credential`,
`test_production_refuses_a_forbidden_runtime_credential`).

### 15.3 · Proof that the test credential cannot affect production

- Absent from `deps.py` (which owns `seed_admin`, password hashing and JWT
  issuance) and from `server.py`
  (`test_the_test_analyst_credential_has_no_production_effect`).
- Cannot create or authenticate a user, seed or reset an account, affect
  authorisation, be logged, or be returned by an API — there is no code
  path that reads it.
- Not present in `backend/.env`, so it cannot re-enter the runtime through
  configuration (asserted).
- Tests and the development harness may continue to use it **outside**
  production, unchanged.

### 15.4 · Nothing else was weakened

`test_a_mandatory_secret_is_still_refused_with_inert_keys_present` deletes
each mandatory secret in turn **while both inert keys hold live values**
and asserts production still refuses, naming the missing key. Placeholder
values are still refused. Live behaviour, simulated with a
production-declared environment:

```
enforced True   inert_present ['VERCEL_TOKEN', 'TEST_ANALYST_NIVXLIVE_PASSWORD']
XDR_ROOT_KEY = PLACEHOLDER-…  →  still refused
```

### 15.5 · `XDR_RESPONSE_SERVICE_URL` — NOT made inert, made STRICTER

The owner asked whether this key can actually be cleared in the UI.
**Assume it cannot** — it is a custom key in the same panel that just
refused an empty save. So the fail-closed guarantee was made independent
of the operator's ability to blank it, by **tightening** the rule rather
than relaxing it:

> Under `NIVX_DEPLOYMENT_ENV=production`, a **loopback** response
> authority (`localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`) is treated as
> **NOT CONFIGURED**.

A production backend cannot legitimately reach a response authority on its
own localhost, so a leftover `http://localhost:8056` is a stale preview
setting, not an authority — and honouring it would mean dialling whatever
owns that port. `None` yields `503 RESPONSE_AUTHORITY_NOT_CONFIGURED`,
which is the correct state until P0-PROD-4.

Applied in both readers: `edr_plane/authority.py` and
`routers/xdr_respond_boundary.py`. Preview is unchanged (localhost still
honoured there). A real private production authority, when P0-PROD-4
closes, is honoured normally. Five focused tests cover all three cases.

**Consequence: the owner no longer has to blank `XDR_RESPONSE_SERVICE_URL`
before republishing.** Leaving the stale localhost value is now safe. If
they prefer, they may still set it to any non-loopback placeholder host —
but no action is required.

### 15.6 · Files changed

| File | Change |
|---|---|
| `backend/security/secret_policy.py` | `FORBIDDEN_IN_PRODUCTION` → `()`; new `INERT_IN_PRODUCTION`; readiness report gains `inert_present` + `inert_note` |
| `backend/edr_plane/authority.py` | production loopback response authority = NOT CONFIGURED |
| `backend/routers/xdr_respond_boundary.py` | same rule, same wording |
| `backend/tests/test_p0prod3_backend_plane.py` | +9 tests (29 total) |
| `backend/tests/test_p0prod1_secret_policy.py` | refusal mechanism retargeted; new inert-key test; `.env` hygiene now covers both tuples; the literal-scan guard no longer scans itself |

No production DB, tenant, endpoint, Vercel deployment, response authority
or background worker was touched.

### 15.7 · Focused results

```
tests/test_p0prod3_backend_plane.py             29 passed
tests/test_p0prod1_secret_policy.py             29 passed
tests/edr/test_p0prod2_enrollment_hardening.py  25 passed
tests/edr/test_p0_a2_enrollment.py              29 passed
tests/edr/test_p0a_response_authority_live.py    8 passed
tests/test_a05_tenant_scope_contract.py         72 passed
preview backend /api/health                        200
```

No full-suite run. No new regressions.

### 15.8 · SECURITY NOTICE — DISCLOSED CREDENTIAL

The owner's screenshot revealed the **plaintext live value** of
`TEST_ANALYST_NIVXLIVE_PASSWORD` in chat. The value was not copied into
any file, test, log or command here, and must not be. It should be treated
as **disclosed and rotated** at the owner's convenience for the
`analyst@nivx-live` account. It confers nothing in production (§15.3), so
this is hygiene, not an incident — but it is a real disclosure and is
recorded as one.

### 15.9 · Verdict

**SAFE TO CONTINUE SECRET CONFIGURATION.** The two unremovable keys are no
longer a blocker; `XDR_RESPONSE_SERVICE_URL` no longer needs clearing. The
remaining owner actions are the genuine secrets: the four PLACEHOLDER
crypto keys, plus fresh `EDR_AUTH_PEPPER`, `JWT_SECRET`, `ADMIN_PASSWORD`,
the two TTL settings, and `NIVX_DEPLOYMENT_ENV=production` **last**.

---

## 16 · POST-REPUBLISH VERIFICATION — PASS (2026-06)

Deployment: **Publish 100 · build `4e76891`** (supersedes the pre-republish
live build `e075550`, which remains the rollback anchor).

Command (read-only, unauthenticated probes only, no database, no
credential):

```
python3 /app/scripts/verify_production_sync.py \
    --prod https://nivxray.nivxforge.com \
    --source http://localhost:8001
```

### 16.1 · Release gates

| Gate | Before | After | Verdict |
|---|---|---|---|
| `/api/health` | 200 | **200** | PASS |
| Source routes | 862 | **862** | — |
| Production routes | 795 | **862** | PASS |
| Missing routes | 67 | **0** | PASS |
| Unexpected routes in production only | 0 | **0** | PASS |

### 16.2 · Previously absent planes — all 29 probes now ROUTED

```
403  /api/edr/policies            403  /api/edr/exclusions
403  /api/edr/policies/audit      403  /api/edr/exclusions/sets
403  /api/edr/policies/deployment 403  /api/edr/exclusions/taxonomy
403  /api/edr/groups              403  /api/edr/exclusions/enforcement-proof
401  /api/edr/agent/policy        405  /api/edr/agent/exclusion-enforcement
405  /api/edr/agent/policy-ack
403  /api/edr/findings            403  /api/edr/audit
403  /api/edr/findings/evaluation-state
403  /api/edr/findings/taxonomy   403  /api/edr/audit/facets
403  /api/edr/events              403  /api/edr/events/facets
403  /api/edr/onboarding/computers
403  /api/edr/onboarding/packages
403  /api/edr/connector/releases  403  /api/edr/connector/deployments
403  /api/edr/saved-views         403  /api/edr/endpoint-commands
405  /api/edr/enrollment/tokens/{token_id}/revoke   ← P0-PROD-2, now live
403  /api/xdr/rbac/me/effective   403  /api/xdr/scope/authorized
405  /api/xdr/scope/select        403  /api/xdr/windows/configuration
```

`401/403` = deployed and protected. `405` = deployed, wrong verb for a
read-only probe (POST-only routes) — nothing disclosed. **No 404.**

### 16.3 · Authority

All ten protected management/agent routes refuse unauthenticated callers
(`403`, or `401` on the agent surface, `405` on POST-only heartbeat).
**Zero unauthenticated 2xx.** Routing was gained without loosening
authentication.

### 16.4 · Response authority

`POST /api/edr/response/actions` unauthenticated → **403**. Destructive
response is not reachable.

Honest limit: `403` proves authentication is enforced **before** the
authority check, so an unauthenticated probe cannot demonstrate the
`503 RESPONSE_AUTHORITY_NOT_CONFIGURED` state from outside. That state is
guaranteed by §15.5 (production treats a loopback authority as NOT
CONFIGURED) and its five focused tests, not by this probe. Proving 503
end-to-end would require an authenticated production analyst session,
which was deliberately not created.

### 16.5 · Inert keys / production mode

The production process **booted and is serving all 862 routes**, which is
only possible if `assert_production_ready()` passed. Since the owner set
`NIVX_DEPLOYMENT_ENV=production` while `VERCEL_TOKEN` and
`TEST_ANALYST_NIVXLIVE_PASSWORD` still hold live values (the platform will
not clear them), the successful boot **is** the proof that both are inert
and that the four PLACEHOLDER crypto keys were replaced with real values —
a placeholder or a missing mandatory secret would have refused startup.
Neither inert value was read, and neither is readable from outside.

### 16.6 · Safety confirmations

Production MongoDB not touched · no migration · no tenant created · no
endpoint enrolled · no Vercel deployment · no code, config or DB change
made during verification · P0-PROD-4 and P0-PROD-6 not started · no full
test suite run.

**PRODUCTION BACKEND SYNC: PASS.** Rollback not required. Next controlled
stage: **XDR + EDR console sync** (§11).

---

## 17 · CONSOLE SYNC — PRE-DEPLOY CHECK COMPLETE · BLOCKED ON OWNER (2026-06)

### 17.1 · Live console state (read-only)

| | XDR | EDR |
|---|---|---|
| Host | `xdr.nivxforge.com` → 307 → `/xdr` → **200** | `edr.nivxforge.com` → 307 → `/edr` → **200** |
| Deployed entry bundle | `/assets/index-dQhjKK0o.js` | `/assets/index-5e0IbMeq.js` |
| API origin baked in | `https://nivxray.nivxforge.com` | `https://nivxray.nivxforge.com` |
| Preview / localhost origin | **none** | **none** |

Both live consoles already target the production API — no stale preview
dependency. Both hostnames serve and the product-scope redirect works.

### 17.2 · The consoles are STALE relative to current source

Local production builds of current source (`feature/rc2-alignment`,
commit `f345a705`) produce:

| | local build entry | deployed entry | same? |
|---|---|---|---|
| XDR | `index-DWES00xC.js` | `index-dQhjKK0o.js` | **NO** |
| EDR | `index-Dyygw0sM.js` | `index-5e0IbMeq.js` | **NO** |

So a Vercel redeploy is genuinely required — this is not a cosmetic
refresh.

### 17.3 · Both scoped builds PASS locally, before any deploy

```
NIVX_PRODUCT_SCOPE=xdr bash scripts/vercel-build.sh
  ok · no unauthorised origin outside the allow-list
  ok · product scope declared "xdr" (/edr/* cannot render here)
  ok · landed collector base https://nivxray.nivxforge.com/api/xdr/collector
  XDR PRODUCTION BUILD GUARD · PASSED     (173 assets)

NIVX_PRODUCT_SCOPE=edr bash scripts/vercel-build.sh
  ok · product scope declared "edr" (/xdr/* cannot render here)
  EDR PRODUCTION BUILD GUARD · PASSED     (173 assets)
```

The new artifacts contain the routes that were 404 in production until
this republish — `edr/policies`, `edr/exclusions`, `edr/audit`,
`endpoint-commands`, `xdr/rbac/me/effective`, `xdr/scope/authorized`,
`xdr/windows/configuration` — so the redeploy is what finally lines the
console up with the 862-route backend.

Factual contract note, not a blocker and **no UI work performed**: neither
artifact references `/api/edr/findings`. The durable-findings API (P0-C) is
live in production but the current console does not consume it yet.

### 17.4 · Production API is ready for the consoles

`POST /api/auth/login` with a wrong password → **401 "Invalid
credentials"** (the authentication path is alive; no real credential was
used, and none is needed to prove this).

### 17.5 · BLOCKED — the agent cannot deploy Vercel

No Vercel credential exists in this environment (`VERCEL_TOKEN` is absent
from the agent runtime, deliberately — it is a deployment-plane authority
the application must never hold), and the Vercel projects are owned by the
owner's account. **Nothing was deployed.**

Minimum owner action:

```
Vercel → project "nivxray-xdr-production"  (host xdr.nivxforge.com)
  Settings → Environment Variables (Production):
      XDR_PROD_API_ORIGIN = https://nivxray.nivxforge.com
      NIVX_PRODUCT_SCOPE  = xdr        (or leave unset — default is xdr)
  Deployments → Redeploy (latest commit of feature/rc2-alignment)
      → UNCHECK "use existing build cache"

Vercel → EDR project                      (host edr.nivxforge.com)
  Settings → Environment Variables (Production):
      XDR_PROD_API_ORIGIN = https://nivxray.nivxforge.com
      NIVX_PRODUCT_SCOPE  = edr        ← REQUIRED, not cosmetic
  Deployments → Redeploy (same commit, no build cache)
```

Both projects must keep: Root Directory `apps/nivxray-xdr`, Build Command
`bash scripts/vercel-build.sh`, Output Directory `dist`, Install
`yarn install --production=false`.

Leave `NIVX_CROSS_PRODUCT_ORIGINS` **off** for now.

If `NIVX_PRODUCT_SCOPE` is missing on the EDR project the build **fails
loudly** (`FATAL: NIVX_PRODUCT_SCOPE must be 'xdr' or 'edr'`) rather than
shipping an unscoped artifact — the product boundary cannot silently
disappear.

### 17.6 · Post-deploy verification (say the word and I will run it)

Read-only, ~1 minute: fetch each host, extract the entry bundle hash,
confirm it matches the current source build, assert the only API origin in
the artifact is `https://nivxray.nivxforge.com` with no preview/localhost,
confirm the scope guard (`/edr/*` must not render on the XDR host and vice
versa), and confirm the console's API calls resolve against production
rather than 404.

```
CONSOLE SYNC: BLOCKED (owner Vercel action)
XDR build:          local PASS · deployed artifact STALE
EDR build:          local PASS · deployed artifact STALE
XDR URL:            https://xdr.nivxforge.com  (200)
EDR URL:            https://edr.nivxforge.com  (200)
Production API:     https://nivxray.nivxforge.com  (auth 401 on bad password)
EDR product scope:  NIVX_PRODUCT_SCOPE=edr required on the EDR project
Deployment:         NOT PERFORMED — no Vercel credential in this environment
Blocker:            owner must redeploy both Vercel projects (§17.5)
```
