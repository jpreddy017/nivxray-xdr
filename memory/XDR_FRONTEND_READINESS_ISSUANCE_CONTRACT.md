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
