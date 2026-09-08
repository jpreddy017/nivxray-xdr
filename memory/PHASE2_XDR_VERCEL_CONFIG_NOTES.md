# Phase 2 · `xdr.nivxforge.com` — Vercel config notes

The prepared `apps/nivxray-xdr/vercel.json` previously carried a large
`$comment` array. Vercel **rejects unsupported properties** during schema
validation (this is what aborted a Phase 1 Workspace deployment), so the notes
live here instead. Owner decisions applied: **1b · 2a · 3a · 4a · 5b**.

## What the config now contains, and why

| key | value | reason |
|---|---|---|
| `installCommand` | `yarn install --production=false` | `--frozen-lockfile` **removed**. It fails whenever the lockfile lags `package.json` — the exact Phase 1 failure. The lockfile is now correct anyway (below), so this is belt *and* braces. |
| `buildCommand` | `bash scripts/vercel-build.sh` | **28 chars.** Phase 1 died on `buildCommand should NOT be longer than 256 characters`; a script cannot regress into that. |
| `outputDirectory` | `dist` | Vite default. |
| `framework` | `null` | Explicit, so Vercel does not auto-detect and inject its own commands. |
| `redirects` | one rule: `/` on host `xdr.nivxforge.com` → `/xdr` | The app's catch-all is `<Route path="*" element={<Navigate to="/xdr"/>} />`, so `/` already resolves client-side; the server redirect makes the landing deterministic for typed URLs, bookmarks and hard refreshes. |
| `rewrites` | `/(.*)` → `/index.html` | SPA deep-link support (`/xdr/incidents/:id` etc. must survive F5). |

**The double dependency install is gone.** `package.json`'s `vercel-build`
script used to run `yarn install --production=false --frozen-lockfile` a
*second* time inside the build step, after Vercel had already installed. It now
runs the build only.

## Removed for Phase 2 (owner decision 5b)

The four `edr.nivxforge.com` cross-host redirect rules were **deleted**, not
left inert. `edr.nivxforge.com` does not exist, so Phase 2 carries **zero**
assumptions that EDR production exists. They must be re-added deliberately in
Phase 3, together with the reverse `/xdr/*` rules on the EDR host.

**Preserved for Phase 3 — the reasoning that justified those rules.** XDR and
EDR ship in **one** bundle (61 routes, 13 of them `/edr/*`) and the catch-all
sends unknown paths to `/xdr`. Without host-conditional redirects,
`edr.nivxforge.com/` would land an analyst on `/xdr/incidents` — XDR served
from the EDR hostname, i.e. the "silently falls back into the wrong product"
failure the owner prohibited. Order matters: cross-host rules must come
**before** the `/` landing rules so they cannot be shadowed, and both the bare
path and the `:path*` form should be listed. `permanent: false` (307) is
deliberate — a 308 gets cached by browsers, which is wrong while a topology is
still moving.

**Known residual gap, restated honestly:** these are *server* redirects, so
they fire on every real navigation (typed URL, external link, bookmark, hard
refresh) but **cannot** fire on client-side React navigation after the page has
loaded, because no HTTP request is made. `src/productScope.js` +
`components/ProductScopeGuard.jsx` exist to close that gap in-app; it also
self-heals on refresh.

## Environment

- Production: `REACT_APP_NIVXRAY_API_URL=https://nivxray.nivxforge.com`, passed
  as a **real env var** by `scripts/vercel-build.sh`. `vite.config.js` uses
  `loadEnv(mode, cwd, "")`, so a real environment variable overrides `.env` —
  no CRA-style dotenv precedence trap. Setting it in the Vercel dashboard as
  well is harmless and equivalent.
- **`apps/nivxray-xdr/.env` is deliberately left pointing at the preview
  backend** so Preview XDR keeps working. Preparation must not destroy the
  preview configuration to produce a production build.
- `REACT_APP_XDR_URL`, `REACT_APP_EDR_URL`, `REACT_APP_WORKSPACE_URL` stay
  **UNSET** (owner decision 4a of the earlier round): `productOrigins.js` then
  reports `SAME_ORIGIN` and no launcher points at an unverified product.
  Cross-product launchers are Phase 4.
- `TEMPORARY_MIGRATION_DEPENDENCY`: `nivxray.nivxforge.com` is the API for now.
  `api.nivxforge.com` is Phase 5. Do not retire or redirect the legacy host.

## Build guard — `scripts/verify-production-build.js`

Inspects the **compiled** `dist/` artifacts, never source `.env`, and exits
non-zero so Vercel fails the deploy:

1. zero preview origins (`preview.emergentagent.com`, `localhost:8001`, …)
2. the expected production API origin is actually **present**
3. no origin outside `ALLOWED_HOSTS` is baked in (catches an unauthorised API base)
4. no `edr.nivxforge.com` reference (Phase 2 is XDR only)

Override the expectation with `XDR_GUARD_EXPECTED_API` when the API moves in
Phase 5.
