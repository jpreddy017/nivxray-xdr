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

---

## POST-DEPLOY VERIFICATION — 2026-06 · VERDICT: **PRODUCTION HARDENING PASS**

Deployed revision: **`e9978291`** (candidate promoted from `be651bce`).
Harness: `scripts/prod_verify_p1_hardening.py --mode verify` (read-only,
no credential, no writes). Full JSON: `test_reports/prod_baseline_p1.json`
holds the pre-deploy baseline for comparison.

### 11/11 gates PASS
| Gate | Before | After |
|---|---|---|
| `/api/health` 200 | 200 | **200** |
| `CreateKeyBody.confirm_tenant_id` | absent | **present** |
| `CreateKeyBody.allow_new_tenant` | absent | **present** |
| `TelemetryReceipt.duplicates` (idempotency live) | absent | **present** (+`resumed`) |
| unknown API key → 401 | **403** `Not authenticated` | **401** |
| unknown API key reason | — | **`unknown-api-key`**, `principal_kind: api_key` |
| anonymous ingest → 403 | 403 (generic) | **403** `ACCESS_DENIED / unauthenticated` |
| legacy-header RBAC fail-closed | 403 | **403** `collectors.read / unauthenticated` |
| production auth alive | 401 `Invalid credentials` | **401 `Invalid credentials`** |
| Workspace `/` 200 + CRA bundle | 200 | **200** |
| Workspace `/auto-investigate` 200 | 200 | **200** |

### Baseline delta
- API surface: **785 paths / 275 schemas → unchanged**. Only the 3 expected
  schemas gained fields (`CreateKeyBody`, `TelemetryReceipt`, `ReasoningOutcome`).
- Workspace CSS: `static/css/main.d85aa4cc.css` → **unchanged**.
- Workspace JS: `main.46cdaa0a.js` → **`main.f552a4b7.js`** (402,334 bytes, 200).

### Honest correction about that bundle hash
Earlier the impact check said restoring the lockfile would leave the Workspace
build inputs "byte-identical to what produced the live bundle". The JS hash
changed, so that statement was **too strong**: the previously live bundle was
most plausibly built while the drifted lockfile was in the workspace (CRA
content hashes track the dependency graph), or CRA is simply not bit-reproducible
across image builds. Either way the current state is the safer one — the bundle
now derives from the **committed** dependency declarations, i.e. it is
reproducible from git.

Verified the rebuilt Workspace actually works rather than merely returning 200:
`/` → 307 `/login`, React mounted (`#root` 4,319 chars), login terminal renders,
bundle contains the `auto-investigate` route and the correct API origin
`https://nivxray.nivxforge.com`. (`/static/js/main.46cdaa0a.js` still answers
200 only because of the SPA catch-all rewrite, not because the old asset survives.)

### Rate-limit behaviour — proven WITHOUT loading production
Headers are emitted on 429 and on success, so a 401 cannot show them. The
positive proof is structural: `_throttle("ip", …)` runs **before** the key is
even shape-checked, and a limiter that could not reach Mongo returns
**503 `RATE_LIMITER_UNAVAILABLE`** (fail closed). Three consecutive unknown-key
probes each returned **401**, so the IP window was consumed successfully on every
one — the limiter is live and healthy. Forcing a real 429 would require ~600
requests/minute against production ingest; deliberately not done.

### No production data / tenant mutation
- `seed_admin()` returns early for an existing admin (`deps.py:370-372`); the
  production admin exists (bad-password login → 401 `Invalid credentials`).
- API surface counts unchanged; no migration, no seed, no index drop in the diff.
- Every request this agent made was read-only or refused by auth.
- **Limitation stated plainly**: the agent has no production DB access and no
  production password, so authenticated surfaces were not exercised. Owner
  confirmation by logging in is the remaining check.

### Other products
- `xdr.nivxforge.com` untouched: `build-info.json` still
  `product_scope=xdr`, `api_origin=https://nivxray.nivxforge.com`,
  `built_at 2026-09-09T21:16:47Z`; `/xdr` → 200. (Vercel-hosted; not part of
  this deploy.)
- No DNS change, no EDR deploy, no XDR frontend deploy.

### Rollback reference (unused)
Manage Publishes → Overview → rollback icon (↺) on the previous deployment
(atomic backend + Workspace). Code target: **`be651bce`**.

STOPPED. No credential minted, no collector created, no auditd installed, no
telemetry sent. Awaiting owner approval for collector enrolment.

---

## DIVERGENCE REPORT — `conflict_310826_2116` (2026-06) · NOTHING MODIFIED OR PUSHED

Owner cancelled the Save to GitHub dialog. No force-push, no new branch, no
deploy, no file modified while producing this.

### Requested facts
| | Value |
|---|---|
| **Remote HEAD** | `bb8a4d216106f168030711f1b843010e9f53d45e` — "Fix XDR frozen lockfile for D3 dependency" (owner-verified on GitHub) |
| **Local HEAD** | `72c36dacc848ac9e9eff5120f1c24b89abe78df2` ("Auto-generated changes", 2026-09-10T03:09:24Z) |
| **Merge-base** | **DOES NOT EXIST — cannot be computed** |
| **Commits unique to remote** | **Cannot be enumerated from this pod** |
| **Commits unique to local** | **Cannot be enumerated from this pod** |
| **Can the one-file change be cherry-picked / rebased cleanly?** | **NO — neither operation is possible here** |

### Why — the two histories are unrelated, not merely diverged
- `git remote -v` → **empty**. This workspace has no configured GitHub remote
  and no fetch path, so the remote cannot be read at all.
- Neither remote SHA exists in local object storage:
  `git cat-file -e bb8a4d21…` → **NO**; `git cat-file -e 6b1441c7…`
  (the SHA the live XDR deployment was built from) → **NO**.
- Local history: 1,900 commits beginning `5767e407 "Initial commit"`
  (2026-07-09). None of our SHAs (`be651bce`, `e9978291`, …) exist on GitHub.
- Cause: **Save to GitHub pushes a whole-workspace snapshot as a single
  commit**, so the GitHub history is an independent lineage. There is no
  common ancestor, which is exactly why the dialog can only offer *force-push*
  (erases remote commits — forbidden) or *a new branch* (forbidden by the owner,
  and Vercel does not build it).

`git rebase`, `git cherry-pick`, `git merge` and `git pull` are therefore all
unavailable for this reconciliation. Any claim to the contrary would be false.

### CORRECTION — a regression I introduced with the lockfile restore
The remote HEAD commit message names it: **"Fix XDR frozen lockfile for D3
dependency."** That was not incidental drift — it was a deliberate fix, and my
restore reverted it.

```
apps/nivxray-xdr/package.json declares  "d3": "^7.9.0"
restored apps/nivxray-xdr/yarn.lock     d3 entries: 0      ← would FAIL a frozen install
drifted backup (== memory/AUTHORITATIVE_XDR_yarn.lock)  d3@^7.9.0: present
```
Vercel installs with a frozen/immutable lockfile, so **pushing the restored
lockfile would break the XDR build**. `memory/AUTHORITATIVE_XDR_yarn.lock` was
accurately named; treating it as suspect was wrong for this file.

The Workspace lockfile is stale the same way — `frontend/yarn.lock` is missing
**21** declared dependencies (`@xyflow/react`, `dagre`, `konva`,
`react-konva`, `typescript`, the Storybook set, …). That deploy still
succeeded only because the Emergent build is **not** frozen: yarn silently
re-resolved them. This is the real reason the Workspace bundle hash moved
`main.46cdaa0a.js → main.f552a4b7.js`, and it means my earlier statement that
the build inputs were "byte-identical" was **wrong**.

Nothing has been changed in response — reporting only, as instructed.

### SAFEST MINIMAL RECONCILIATION — apply the one file on GitHub
Do **not** reconcile through this pod. Apply the change at the remote, where
the true history lives:

1. On GitHub, branch `conflict_310826_2116`, open
   `apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx`.
2. Confirm it matches the state this patch was generated against:
   sha256 `11208b6938ae59124eaa9dedb35eeeebffbed147a4513c29fdfdec5f2a97378a`
   (our `bf53d6c0` copy, the ancestor of the live build).
3. Apply `memory/xdr_frontend_patch/ApiKeysBody.confirm-tenant.patch`
   (73 lines, one file) — or paste
   `memory/xdr_frontend_patch/ApiKeysBody.jsx.final`
   (sha256 `509e04e5c9afa6c5789b5040e9589226fb9f9b5ecf2d2777e7dc86c98e912b6b`)
   if step 2 confirms the file is unmodified on the remote.
4. Commit directly to `conflict_310826_2116` (or via a PR into it).

Why this is the safest option available:
- **Every remote commit is preserved** — one commit is added, nothing rewritten.
- **No whole-workspace snapshot**, so the stale lockfiles never reach the remote
  and the D3 fix stays intact.
- Touches **one file**; no backend, no other product, no unrelated file.
- Lands on the branch Vercel builds, so **only** the XDR project rebuilds;
  `nivxray-edr-production` watches `phase2/edr-production` and is untouched.
- Rollback stays instant: promote `dpl_44tFN3uDajSgSrcRawrviJchJq1N` back.

### Rejected alternatives
| Option | Why rejected |
|---|---|
| Force Push | Permanently erases remote commits, including the D3 lockfile fix. Owner forbade it. |
| Create Branch & Push (`conflict_100926_0839`) | Owner forbade a new branch; and Vercel does not build that branch, so it would not publish anything. |
| Switch to `feature/rc2-alignment` | Changes the deployment path; not the XDR project's production branch. |
| Rebase / cherry-pick locally | **Impossible** — no remote, no shared ancestry. |

### Open decision for the owner
The local lockfiles are now stale relative to `package.json`. If a
whole-workspace push is ever wanted later, `apps/nivxray-xdr/yarn.lock` and
`frontend/yarn.lock` must first be restored from
`memory/lockfile_drift_backup_2026-06/` (the copies that satisfy
`package.json`). Not doing it now — awaiting instruction.
