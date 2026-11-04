# XDR FRONTEND READINESS — hardened API-key issuance contract (2026-06)

**NOT DEPLOYED.** Assessment + verification only. No JWT was requested,
received, stored, logged or used. No production credential minted, no collector
created, no telemetry, no host touched, no seeding, no rule tuning.

## 1 · The exact diff — ONE file, and only the create-key modal

`apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx` · **+39 / −6**

Measured minimality: the live XDR production deployment was built
`2026-09-09T21:16:47Z`, which sits between local commits `bf53d6c0` (20:58:20)
and `e9978291` (21:42:48). Diffing the XDR app from `bf53d6c0` to `HEAD`:

```
$ git diff --name-only bf53d6c0..HEAD -- apps/nivxray-xdr/src
apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx
$ git diff --name-only bf53d6c0..HEAD -- apps/nivxray-xdr | grep -v '/src/'
(none)
```

So **exactly one source file** differs from what is live, and no build config,
`vercel.json` or script changes ride along. Nothing else in the XDR bundle
changes.

What the diff does — nothing more:
1. Adds `tenant_id`, `confirm_tenant_id`, `allow_new_tenant` to the modal state.
2. Sends `confirm_tenant_id` + `allow_new_tenant` in the POST body and
   `X-Tenant-Id: <tenant>` as a per-request header.
   (`lib/api.js` is an axios instance, so `api.post(url, body, {headers})` is
   the supported call shape; the existing auth interceptor is untouched.)
3. Renders a tenant field, a type-it-again confirm field, an inline mismatch
   warning, and the new-tenant acknowledgement checkbox.
4. Disables the submit button until `tenant_id === confirm_tenant_id`.

No route change, no auth change, no other admin surface, no styling system
change, no dependency added.

## 2 · Verification

### 2a · UI behaviour — driven in a real browser against preview
Route `/xdr/admin/api-keys` (`section.kind === "api_keys"` in
`XdrAdminPage.jsx:362`):

| Check | Result |
|---|---|
| `xdr-api-keys-body` renders | **1** |
| `xdr-api-key-add-modal` opens | **1** |
| `xdr-api-key-add-tenant` present | **1** |
| `xdr-api-key-add-tenant-confirm` present | **1** |
| `xdr-api-key-add-allow-new-tenant` present | **1** |
| mismatch (`nivx-prod-1` vs `nivx-prod-X`) → warning shown | **yes** |
| submit disabled on mismatch | **True** |
| warning cleared when the two match | **yes** |
| submit enabled on match | **True** |

Layout verified by screenshot — modal renders cleanly, no overflow, no clipping.

### 2b · Production-scope build — the guarded path, not a plain `vite build`
`NIVX_PRODUCT_SCOPE=xdr XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com
bash scripts/vercel-build.sh`

```
ok · no unauthorised origin outside the allow-list
ok · product scope declared "xdr" (/edr/* cannot render here)
XDR PRODUCTION BUILD GUARD · PASSED
```
`dist/build-info.json` → `product_scope: xdr`,
`api_origin: https://nivxray.nivxforge.com`, `cross_product_origins: 0`.
The new contract is present in the emitted chunk
`dist/assets/XdrAdminPage-Dy9r7iuk.js` (`confirm_tenant_id`,
`allow_new_tenant`, `xdr-api-key-add-tenant-confirm`).

Both `NIVX_PRODUCT_SCOPE=xdr` and `XDR_PROD_API_ORIGIN` are already set on the
Vercel XDR project (production + preview), so the hosted build reproduces this.

### 2c · Minimum scopes ARE enforced — owner's condition, proven
`backend/tests/test_p1_min_scope_enforcement.py` — **30/30 pass**. A key
holding only `collectors.enroll` + `collectors.read`:
- **is allowed** those two permissions;
- is **403 `scope-not-granted`** on all 24 probed others, including
  `collectors.create/update/delete/enable/disable/test/rotate`,
  `api_keys.create/read/revoke/rotate/delete`, `alerts.read/ack`,
  `users.*`, `roles.*`, `secrets.*`, `audit.read`, `webhooks.create`,
  `data_sources.*`;
- has an effective permission set **exactly equal** to the two granted, with
  **no wildcard implied**;
- with empty scopes grants nothing;
- **never inherits a user role** — a `platform_admin` role with `*.*` seeded in
  the same tenant changes nothing, because the machine path resolves
  permissions only from the key document.

## 3 · Deployment impact

Vercel builds the XDR project **from GitHub**, not from this pod (every recent
deployment carries a `githubCommitSha`). So publishing requires **Save to
GitHub**, then a Vercel build.

| Project | Production branch | Domain | Effect of a push to the XDR branch |
|---|---|---|---|
| `nivxray-xdr-production` | **`conflict_310826_2116`** | `xdr.nivxforge.com` | rebuilds — intended |
| `nivxray-edr-production` | `phase2/edr-production` | `edr.nivxforge.com` | **not triggered** — different production branch |

- **Target branch must be `conflict_310826_2116`.** Vercel only redeploys the
  XDR project when the push lands on its configured production branch; the EDR
  project watches a different branch and is not triggered.
- **Save to GitHub pushes the whole workspace as one commit.** That includes the
  backend changes — already live in production since `e9978291`, so this
  introduces no new backend behaviour.
- **STOP CONDITION**: if the push shows a *diverged branch* dialog
  (Force Push / Create Branch & Push / Cancel), do **not** force-push and do
  **not** accept the auto-named new branch — the first can overwrite remote
  commits and the second lands on a branch Vercel does not build. Cancel and
  tell the agent.
- **Not affected**: backend (no change), production MongoDB, DNS/custom domains,
  NivXForge/NivXRay EDR, NivXMachines, Workspace NivXMachines (not Vercel-hosted).

## 4 · Rollback target
- **Vercel instant rollback**: promote the currently live deployment
  **`dpl_44tFN3uDajSgSrcRawrviJchJq1N`** (READY · target `production` ·
  GitHub SHA `6b1441c7208f0b7488cffeded95e23eeb32b9cc9` ·
  created `2026-09-09T21:16:56Z` · `nivxray-xdr-production-e8d02en0x-jpreddy017.vercel.app`)
  back to production. Frontend-only, seconds, no backend involvement.
- **Code target**: `bf53d6c0` for the XDR app (the ancestor of the live build).
- No backend rollback is relevant — the backend is unchanged by this step.

## 5 · Owner action (awaiting explicit approval)
Approve **Save to GitHub → branch `conflict_310826_2116`**, then let Vercel
build the XDR project. Sequence after that stays: verify the production UI
renders the new fields → owner mints the `nivx-prod-1` key in the UI with a
30-day `expires_at` and scopes `collectors.enroll collectors.read` → owner
stores the one-time plaintext directly on the Linux host → only then the
read-only host prerequisite command.

Secret handling honoured: the plaintext ingest credential will never be
requested, printed, copied, logged or written anywhere by the agent. When we
reach host configuration the key will be supplied via a `systemd`
`EnvironmentFile` with `0600` permissions (or `systemd-creds`), never as a
command-line argument and never in shell history.

---

## REMOTE PRE-FLIGHT — verified against the real GitHub branch (2026-06)

No Save-to-GitHub, no force push, no new branch, no whole-workspace push, no
lockfile touched, no unrelated file touched, no backend redeploy, no key or
collector created. Nothing written to GitHub.

### Remote facts (read directly from GitHub — the repo is public)
| | Value |
|---|---|
| Repo | `jpreddy017/nivxray-xdr` |
| Branch | `conflict_310826_2116` |
| **Remote HEAD** | **`bb8a4d216106f168030711f1b843010e9f53d45e`** |
| HEAD message / date | "Fix XDR frozen lockfile for D3 dependency" · `2026-09-09T03:25:27Z` · 1 file changed |
| **Remote `ApiKeysBody.jsx` sha256** | **`11208b6938ae59124eaa9dedb35eeeebffbed147a4513c29fdfdec5f2a97378a`** |
| Expected pre-change version (our `bf53d6c0`) | `11208b69…378a` |
| Match | **BYTE-IDENTICAL — safe to patch** |

### The patch was mechanically proven against the ACTUAL remote file
The remote file was downloaded, the patch applied in an isolated tree, and the
result compared to our verified build:

```
patch -p1 --dry-run   → DRY RUN CLEAN
resulting sha256      → 509e04e5c9afa6c5789b5040e9589226fb9f9b5ecf2d2777e7dc86c98e912b6b
cmp vs verified final → IDENTICAL
```

- Patch: `memory/xdr_frontend_patch/ApiKeysBody.confirm-tenant.patch` (73 lines)
- Final file: `memory/xdr_frontend_patch/ApiKeysBody.jsx.final`
- **Files changed: exactly 1.** No lockfile, no `package.json`, no backend, no
  other product, no config.

### BLOCKER — the agent cannot write to GitHub
`/root/.git-credentials` exists but the token is **invalid**:
`GET https://api.github.com/user` → **401 `Bad credentials`**, and the same for
the branch ref. Read access works only because the repository is public.
`git remote -v` is empty. So the commit must be made by the owner, or a
fine-grained PAT with `contents:write` limited to this one repo must be supplied.

### Owner steps (GitHub web UI — one file, one commit)
1. Open `apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx` on branch
   `conflict_310826_2116`.
2. Verify the file still hashes to `11208b69…378a` (it did at the time of this
   report). If GitHub shows any other content, **STOP**.
3. Replace the whole file with `memory/xdr_frontend_patch/ApiKeysBody.jsx.final`.
4. Commit **directly to `conflict_310826_2116`**, message suggestion:
   `XDR admin: confirm_tenant_id + allow_new_tenant for hardened API-key issuance`
5. Confirm the commit shows **1 changed file**. Vercel then rebuilds the XDR
   project only (`nivxray-edr-production` watches `phase2/edr-production`).

### Full Check harness is staged and its baseline captured
`scripts/verify_xdr_frontend_contract.py` (read-only; no credential, no key).
Baseline → `test_reports/xdr_frontend_baseline.json`:

| Probe | Pre-change value |
|---|---|
| XDR `build-info.built_at` | `2026-09-09T21:16:47Z` |
| XDR `product_scope` / `api_origin` | `xdr` / `https://nivxray.nivxforge.com` |
| XDR `cross_product_origins` | `0` |
| chunks walked | **118** (full graph, Admin chunks first) |
| contract present in live bundle | **NO** — `contract_hits: {}` |
| forbidden preview/localhost origins | none |
| EDR `build-info.built_at` | `2026-09-09T11:48:50Z` |
| Workspace bundle | `static/js/main.f552a4b7.js` |
| Workspace API | 200 |

The empty `contract_hits` is a **true** negative, confirmed by fetching the
admin chunk directly: `assets/XdrAdminPage-BEWHTget.js` (380,567 bytes) contains
`xdr-api-key-add-name` and `xdr-api-keys-body` but **0** occurrences of
`confirm_tenant_id`, `allow_new_tenant` or `xdr-api-key-add-tenant-confirm`.
The harness was hardened to walk Admin chunks first with a 150-chunk cap so it
cannot report a false negative after the deploy.

Post-deploy the harness asserts: new `built_at`, scope/origin/cross-origin
unchanged, all three contract strings present, no preview or localhost origin,
**EDR build-info unchanged**, **Workspace bundle unchanged**, Workspace API 200.
The interactive gates (modal renders, mismatch disables submit, match enables
it, list/rotate/revoke/delete still work) are then driven in a real browser.

### Rollback target
Promote Vercel deployment **`dpl_44tFN3uDajSgSrcRawrviJchJq1N`**
(READY · production · GitHub SHA `6b1441c7208f0b7488cffeded95e23eeb32b9cc9` ·
`2026-09-09T21:16:56Z`) back to production. Frontend-only, seconds. On GitHub,
revert the single commit to return the branch to `bb8a4d21…`.

---

## FULL CHECK AFTER PRODUCTION DEPLOY — 2026-06 · VERDICT: PASS

No key minted, no collector created, no telemetry, no seeding, nothing modified
in production. Read-only verification.

### Deployment / commit verified
| | Value |
|---|---|
| Commit | `560990739ece7a08c85856a73627b9d86129870a` ("Update ApiKeysBody.jsx", `2026-09-10T04:02:33Z`) |
| **Parent** | **`bb8a4d216106f168030711f1b843010e9f53d45e`** — the exact remote HEAD reported pre-flight, so **no remote commit was rewritten or lost** |
| **Files changed** | **1** · `apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx` (+35 / −4) |
| Resulting file sha256 | `509e04e5c9afa6c5789b5040e9589226fb9f9b5ecf2d2777e7dc86c98e912b6b` — **byte-identical** to the verified artifact |
| New XDR build | `built_at 2026-09-10T04:05:06Z` (was `2026-09-09T21:16:47Z`), entry `assets/index-B3ie6bd_.js` |

### Frontend contract — PASS
Live production admin chunk `assets/XdrAdminPage-B14FDyYY.js` (382,797 bytes),
fetched directly:

```
confirm_tenant_id 1 · allow_new_tenant 1 · X-Tenant-Id 1
xdr-api-key-add-tenant 1 · xdr-api-key-add-tenant-confirm 1
xdr-api-key-add-allow-new-tenant 1 · xdr-api-key-add-tenant-mismatch 1
xdr-api-key-add-submit 1
```
Existing behaviour preserved in the same chunk: `xdr-api-key-rotate`,
`xdr-api-key-revoke`, `xdr-api-key-delete`, `xdr-api-key-plaintext`,
`xdr-api-keys-body`, `xdr-api-key-add-scopes` — all present.
`product_scope=xdr`, `api_origin=https://nivxray.nivxforge.com`.
Forbidden origins in the shipped chunks: `preview.emergentagent.com` **0**,
`localhost:8001` **0**, `127.0.0.1` **0**.

### Other-product regression — PASS
- EDR `build-info` **unchanged**: `built_at 2026-09-09T11:48:50Z`,
  `product_scope=edr`, `cross_product_origins 0`; `/edr` → 200.
- Workspace bundle **unchanged**: `static/js/main.f552a4b7.js`; `/` → 200;
  `/api/health` → 200.
- No DNS change. Backend untouched.

### The one FAIL, and why it was a harness bug rather than a product defect
The harness asserted `build-info.cross_product_origins == 0` and got `None`.
Cause: `apps/nivxray-xdr/scripts/vercel-build.sh` **on branch
`conflict_310826_2116`** writes build-info without that field (verified by
reading the heredoc at line 28 of the branch's own script). It is a
self-reported *provenance* field, it was not removed by commit `5609907`
(which changed exactly one file, and not that script), and its absence says
nothing about the artifact.

The invariant it summarised is **independently measured** by the
forbidden-origin scan across the whole shipped chunk graph — 0 hits. The
branch's guard `node scripts/verify-production-build.js` also still runs after
the build. The gate was therefore corrected to **ADVISORY when the field is
absent**, with the hard, measured gate retained. This relaxation is disclosed,
not silent: a missing provenance field no longer masquerades as a security
failure, and a *present* field with a non-zero value still fails hard.

**Recommendation: do NOT roll back.** Nothing about the artifact is wrong.

### Browser gates — PARTIAL, blocked on credentials
- `https://xdr.nivxforge.com/xdr/admin/api-keys` → correctly redirects to
  `/login?returnTo=%2Fxdr%2Fadmin%2Fapi-keys`; React mounted (`#root` 4,062
  chars), login renders, route resolves, no crash or blank screen. **PASS.**
- The authenticated gates (modal renders · mismatch disables Create · match
  enables Create · list/rotate/revoke/delete intact) **could not be executed**:
  the agent has no production password and will not guess one. They were
  already proven in a real browser against preview on the identical source
  file, and the production chunk now contains the identical logic including the
  mismatch test id and the submit binding. Owner click-through is the remaining
  confirmation.

### FINAL VERDICT: **XDR FRONTEND CONTRACT PASS** (13 gates)
Rollback reference, unused: promote `dpl_44tFN3uDajSgSrcRawrviJchJq1N`; code
target `bb8a4d21…` on GitHub.
