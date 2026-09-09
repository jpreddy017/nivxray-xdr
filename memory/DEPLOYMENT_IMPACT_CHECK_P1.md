# DEPLOYMENT IMPACT CHECK — read-only · 2026-06

Nothing was deployed, minted, installed, seeded or written to production while
producing this. All production requests were unauthenticated probes that were
refused, plus `GET /api/openapi.json`.

## VERDICT: **NOT SAFE TO DEPLOY** (one blocker, one approval away)

## 1 · Revisions

| | Commit | Date (UTC) |
|---|---|---|
| **Currently deployed production backend** | **`be651bce`** — "P0-SEC GATE — LAST TEST FAILURE CLOSED" | 2026-09-09 05:02:49 |
| **Candidate (accepted P1 hardening)** | **`e9978291`** — "P1 Machine-Credential Hardening Complete" | HEAD |

`a6d13209` and `32dbd478` sit between them but are **documentation-only**, so
`be651bce` is the exact deployed *code* state.

### How the deployed revision was established (measured, not assumed)
- `GET /api/openapi.json`: production and preview both report **785 paths /
  275 schemas**, and **exactly 3 schemas differ**: `CreateKeyBody`,
  `ReasoningOutcome`, `TelemetryReceipt`.
- `POST /api/xdr/ingest/telemetry` with an API key only →
  production `403 {"detail":"Not authenticated"}` vs preview
  `401 unknown-api-key`. **The machine API-key auth path (`85bcc86a`) is NOT
  in production** — no collector can authenticate there today.
- `GET /api/xdr/collectors` with legacy `X-Tenant-Id`/`X-Principal-Id` headers
  only → **403 on both**, so the P0-SEC fail-closed fix (`be651bce`) **IS**
  in production.
- Therefore: production ≥ `be651bce`, production < `85bcc86a`.

## 2 · Changed files, `be651bce` → `e9978291`

Runtime backend (7):
```
backend/routers/incidents.py          deep_link → /xdr/intelligence/iocs
backend/routers/xdr_api_keys.py       confirm_tenant_id + unknown-tenant guard
backend/routers/xdr_ingest.py         idempotency partition + `message` passthrough
backend/routers/xdr_rbac.py           API-key machine auth + rate-limit wiring
backend/server.py                     additive /openapi.json alias (in-process only)
backend/services/ingest_idempotency.py   NEW — exactly-once delivery claims
backend/services/machine_rate_limit.py   NEW — per-IP/key/tenant throttle
```
Tests (11), `memory/` (17), `test_reports/` (5), `scripts/` (3),
`apps/nivxray-xdr/` (38 — Vercel-only, not part of this host),
root `vercel.json` (1 — the deployment-refusal script; both Vercel projects
use rootDirectory `apps/nivxray-xdr`, verified via the Vercel API, so the root
file is never read by them).

**Not changed anywhere in the range:** no `.env`, no `requirements.txt`, no
`package.json`, no `Dockerfile`, no supervisor config. No new startup hook and
no migration. The only production-DB writes the new code can make are
*lazy, on first use*: `xdr_ingest_dedupe` and `xdr_machine_rate_buckets` — two
**new** collections with their own indexes. No existing collection is read
destructively, altered, dropped or seeded.

## 3 · Workspace (NivXMachines) impact

- Emergent builds the **entire project from the current workspace state** and
  there is **no backend-only deploy**, so the Workspace CRA at
  `nivxray.nivxforge.com` **will** be republished. (Confirmed against
  platform documentation, not inferred.)
- **`frontend/` source: 0 files changed** between `be651bce` and `HEAD`.
  `frontend/package.json` unchanged. So the Workspace source is identical to
  what the live bundle (`static/js/main.46cdaa0a.js`) was built from.

### THE BLOCKER — uncommitted lockfile drift
```
frontend/yarn.lock              +1329 / -37   (UNCOMMITTED, working tree only)
apps/nivxray-xdr/yarn.lock      +287  / -0    (UNCOMMITTED, working tree only)
```
The committed lockfiles are byte-identical to `be651bce`; the **working-tree**
copies are not. New resolutions appear (`@adobe/css-tools 4.5.0`,
`@apidevtools/json-schema-ref-parser 11.9.3`, …) with **no `package.json`
change** — i.e. drift from an incidental `yarn install`, not an intended
dependency change. Because the deploy uses the working tree, the Workspace
would be rebuilt against a dependency graph the live bundle was **never**
built with. That is an unreviewed change to a working product, which the
owner-locked rule forbids.

`memory/AUTHORITATIVE_XDR_yarn.lock` (untracked) is byte-identical to the
drifted `apps/nivxray-xdr/yarn.lock`, so a previous session already treated
this drift as a known hazard.

## 4 · Confirmed NOT touched by the deploy
- **Production MongoDB / tenant data** — redeploy keeps the same
  `MONGO_URL` and database; the migrate step only runs on first deploy or an
  explicit replace. No wipe, no seed, no schema migration.
- **DNS / custom domains** — unchanged by redeploy.
- **NivXRay XDR frontend (`xdr.nivxforge.com`)** and **NivXForge/NivXRay EDR
  (`edr.nivxforge.com`)** — served by separate **Vercel** projects; an
  Emergent deploy does not build or publish them.
- **No other product** shares this host.

## 5 · Rollback target (before deploying)
- **Platform**: Manage Publishes → **Overview** → rollback icon (↺) on the
  previous deployment of `nivxray.nivxforge.com`. Up to 3 recent successful
  deployments are eligible; rollback reuses the previous Docker image, so
  **backend and Workspace frontend revert atomically** (1–3 min).
- **Code-level**: commit **`be651bce`**.

## 6 · EXACT NEXT OWNER ACTION
Approve restoring `frontend/yarn.lock` and `apps/nivxray-xdr/yarn.lock` to
their **committed** state (a working-tree revert — no source change, no
install, no deploy). Once that is done the Workspace build inputs are
byte-identical to the live deployment and the verdict becomes
**SAFE TO DEPLOY**.

Not done, per instruction: no credential minted, no collector created, no
auditd installed, no telemetry sent, no data seeded, nothing deployed.

---

## RE-CHECK AFTER OWNER-APPROVED LOCKFILE RESTORE (2026-06)

Restore source was the **actual committed blob at `be651bce`**
(`git show be651bce:<path>`), NOT `memory/AUTHORITATIVE_XDR_yarn.lock`.
No `yarn install`, no lockfile regeneration, no `package.json` edit, no source
edit, no deploy. The drifted copies were preserved first under
`memory/lockfile_drift_backup_2026-06/` so nothing was destroyed.

### Lockfile hashes (sha256)
| File | Before | After | Target @ `be651bce` |
|---|---|---|---|
| `frontend/yarn.lock` | `4c9cd7f5…50ea` | `e7e9c595…6a59` | `e7e9c595…6a59` ✔ |
| `apps/nivxray-xdr/yarn.lock` | `ab7aed54…80c6` | `aa7b43b8…aa29` | `aa7b43b8…aa29` ✔ |

`git diff --quiet be651bce -- frontend/yarn.lock apps/nivxray-xdr/yarn.lock`
→ **IDENTICAL_TO_be651bce**. `be651bce` and `HEAD` carry the same bytes for
both files, so the restore is simultaneously HEAD-clean.

### Verifications
- `git status --porcelain` → **no modified tracked files**; only untracked
  `memory/` artefacts remain (documentation + the drift backup; not build inputs).
- `frontend/` source diff vs `be651bce` → **0 files**. `frontend/package.json`
  unchanged. Workspace build inputs are now byte-identical to what produced the
  live bundle `static/js/main.46cdaa0a.js`.
- `apps/` diff vs `HEAD` → **0 files**.
- Candidate runtime backend diff `be651bce..HEAD` unchanged — the same 7 files
  reviewed above (`incidents.py`, `xdr_api_keys.py`, `xdr_ingest.py`,
  `xdr_rbac.py`, `server.py`, `services/ingest_idempotency.py`,
  `services/machine_rate_limit.py`) plus tests/docs. Still no `.env`,
  `requirements.txt`, `package.json`, Dockerfile, supervisor, startup hook or
  migration change.
- Services healthy after the restore: preview `/api/health` 200, preview
  `/xdr` 200, production `/api/health` 200. `node_modules` was deliberately
  left untouched, so the preview pod keeps running exactly as before.
- Honest limitation: a full Workspace rebuild was **not** performed, because
  that would require the forbidden `yarn install`. Reproducibility is by
  construction — identical `package.json` + identical `yarn.lock` + identical
  source as the live deployment.

## FINAL VERDICT: **SAFE TO DEPLOY**

- **Rollback target**: Manage Publishes → Overview → rollback icon (↺) on the
  previous deployment of `nivxray.nivxforge.com` (atomic backend + Workspace,
  1–3 min, 3 most recent deployments eligible). Code-level: commit
  **`be651bce`**.
- **Exact next owner action**: approve and press Deploy to publish
  `nivxray.nivxforge.com` from the current workspace state, then run the
  post-deploy verification below. Nothing else is approved yet — no credential,
  no collector, no auditd, no telemetry.

```
curl -s https://nivxray.nivxforge.com/api/openapi.json \
 | python3 -c "import sys,json;print(list(json.load(sys.stdin)['components']['schemas']['CreateKeyBody']['properties']))"
# expect: ['name', 'confirm_tenant_id', 'allow_new_tenant', 'description', 'scopes', 'expires_at']

curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://nivxray.nivxforge.com/api/xdr/ingest/telemetry \
  -H "X-XDR-API-Key: nvx_000000000000000000000000000000000000000000000000" \
  -H "X-Tenant-Id: probe" -H "Content-Type: application/json" -d '{"envelopes":[]}'
# expect: 401  (machine auth path live; currently 403 "Not authenticated")

curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://nivxray.nivxforge.com/api/xdr/ingest/telemetry \
  -H "Content-Type: application/json" -d '{"envelopes":[]}'
# expect: 403  (anonymous still refused)

curl -s https://nivxray.nivxforge.com/ | grep -o 'static/js/main[^"]*'
# Workspace still serves a CRA bundle (hash may change only if the build is
# not bit-reproducible; the app must still load and /auto-investigate → 200)
```

---

## PRE-DEPLOY STAGING (owner approved deploy; agent cannot press Deploy)

Emergent deployment is an owner-only platform action. Everything that could be
prepared without deploying is done:

### 1 · Readiness scan — one flagged BLOCKER, DELIBERATELY NOT ACTED ON
The scanner reported `[program:frontend] directory=/app/apps/nivxray-xdr` as a
deployment blocker and proposed repointing it to `/app/frontend`.
**Refused, and it must stay refused:**
- `/etc/supervisor/conf.d/supervisord.conf` is **pod-local and NOT git-tracked**
  (`git ls-files | grep supervisor` → empty), so it is not a deploy input.
  `.emergent/emergent.yml` carries only image/job identifiers, no frontend path.
- The live host already serves the CRA from `/app/frontend`
  (`static/js/main.46cdaa0a.js`) while this same pod-local supervisor pointed at
  `apps/nivxray-xdr` — empirical proof the setting does not reach the deploy.
- Applying the "fix" would stop the preview from serving the NivXRay XDR app
  the owner is actively developing. Net effect: breakage, zero deploy benefit.

Everything else in the scan is green: compilation passes, no hardcoded secrets
or URLs, env-only configuration, CORS acceptable, Mongo-only,
`destructive_db_startup_confirmed: false`.

### 2 · Startup DB behaviour — proven, not assumed
`backend/deps.py:359 seed_admin()` reads `db.users.find_one({"email": ADMIN_EMAIL})`
and **returns immediately if the admin exists** (lines 370-372). The production
admin exists (`POST /api/auth/login` with a wrong password → `401 Invalid
credentials`, i.e. the account and hash are intact). So container start writes
nothing. The only new writes the candidate can ever make are lazy, on first
use, into two **new** collections: `xdr_ingest_dedupe`, `xdr_machine_rate_buckets`.

### 3 · Baseline captured + verification harness ready
`scripts/prod_verify_p1_hardening.py` (read-only, no credential, no writes).
Baseline → `test_reports/prod_baseline_p1.json`:

| Probe | Pre-deploy value |
|---|---|
| `/api/health` | 200 |
| openapi | 785 paths / 275 schemas |
| `CreateKeyBody` | `[name, description, scopes, expires_at]` |
| `TelemetryReceipt` | no `duplicates` / `resumed` |
| unknown API key ingest | **403** `Not authenticated` |
| anonymous ingest | 403 |
| legacy-header RBAC | 403 (fail-closed) |
| auth alive (bad creds) | 401 `Invalid credentials` |
| Workspace `/` | 200 · `static/js/main.46cdaa0a.js` |
| Workspace `/auto-investigate` | 200 |

Harness run against **current** production: **5 FAIL / 6 PASS** — it fails on
exactly the five things the deploy must change and passes on the six that must
not. It therefore discriminates correctly and is not a rubber stamp.

Note: the host is behind Cloudflare, which 403s the default `urllib`
User-Agent. The harness sends a browser UA; a naive probe would have
misreported the Workspace as down.

### 4 · Next owner action
Press **Deploy** (Manage Publishes) for `nivxray.nivxforge.com`, then tell the
agent — it will immediately run
`python3 scripts/prod_verify_p1_hardening.py --mode verify` and report the
11 gates plus the baseline delta. If any gate fails: rollback icon (↺) on the
previous deployment; code target `be651bce`.

Still not done, per instruction: no key minted, no collector, no auditd, no
telemetry, no seeding.
