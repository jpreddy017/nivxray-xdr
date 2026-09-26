# EDR PRODUCTION POST-DEPLOY AUDIT (2026-06) — READ ONLY

Nothing was changed: no code, no DNS, no Vercel config, no env vars, no
database, no auth, no redeploy, no workaround redirect. XDR production and
`nivxray.nivxforge.com` were not touched. No secret was exposed or requested.

---

## Evidence collected from the live hosts

| Probe | XDR (working) | EDR (broken) |
|---|---|---|
| `GET /build-info.json` | **real JSON** — `product_scope=xdr`, `api_origin=https://nivxray.nivxforge.com` | **`index.html`** (200 via the SPA rewrite — the file does **not exist**) |
| `GET /` | **307 → `/xdr`** | **200, no redirect** |
| `GET /xdr/incidents` | 200 (own lane) | **200 — renders XDR on the EDR host** |
| main bundle | `assets/index-Ckucwd-G.js` (243,443 B) | `assets/index-CzHM2mqs.js` (236,151 B) — **different build** |
| `nivxray.nivxforge.com` in bundle | **1 occurrence** | **0** |
| `preview.emergentagent.com` in bundle | 0 | 0 |
| `POST /api/auth/login` to the app host | n/a | **405** (reproduced exactly) |
| `POST /api/auth/login` to the real API | — | **422** (alive, accepts POST) |

The EDR bundle contains **no API origin at all** — not production, not
preview. That single fact drives both faults.

---

## 1 · ROOT CAUSE — XDR branding / `/xdr/incidents` routing
**The deployed EDR bundle is UNSCOPED: `REACT_APP_PRODUCT_SCOPE` compiled to
`""` — not `"edr"`, and not even `"xdr"`.**

`src/productScope.js`:
```js
export const PRODUCT_SCOPE = raw === "xdr" || raw === "edr" ? raw : "";
export const IS_SCOPED     = PRODUCT_SCOPE !== "";
export const HOME_PATH     = `/${PRODUCT_SCOPE || "xdr"}`;   // ← "" ⇒ /xdr
export function isForeignPath(pathname) { if (!IS_SCOPED) return false; ... }
```
With an empty scope the build is the **combined/preview** variant:
- `HOME_PATH` falls back to **`/xdr`** → the auth guard redirects to
  `/login?returnTo=%2Fxdr%2Fincidents` — **exactly the URL you saw**;
- `isForeignPath()` short-circuits to `false` → `/xdr/*` renders normally on
  `edr.nivxforge.com` with **no "wrong product host" notice** (confirmed: 200);
- the browser therefore lands on the generic `/login` route, whose
  `LoginPage` prop defaults to `product="NIVXRAY_XDR"` → the **"NIVXRAY XDR"**
  card. `/edr/login` is the route that renders `NivXForge EDR`.

**Answer to your specific question — it is NOT merely shared login branding.**
The `<title>NivXRay XDR</title>` *is* shared static text in `index.html` and
would appear even on a correct EDR build. But the deployed **bundle itself is
unscoped**, which is why it behaves as XDR: routing, home path and the guard
are all in combined mode. `NIVX_PRODUCT_SCOPE=edr` **never reached the build.**

**Why it never reached the build:** the value is only consumed by
`apps/nivxray-xdr/scripts/vercel-build.sh`, and that script **did not run** —
proven by the absent `dist/build-info.json` (the script's own output) and by
the bundle lacking the API origin the script injects.

## 2 · ROOT CAUSE — login HTTP 405
**The login POST is going to the EDR host itself, not to the API.**

Exact request when Sign In is clicked:
- Built in `src/lib/api.js`:
  ```js
  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL || "";   // ⇒ ""
  export const API_BASE = `${BACKEND_URL}/api`;                  // ⇒ "/api"
  const api = axios.create({ baseURL: API_BASE, ... });
  ```
- Method/URL: **`POST https://edr.nivxforge.com/api/auth/login`**
  (relative `/api/...`, so the browser resolves it against the page origin).
- `apps/nivxray-xdr/vercel.json` rewrites `/(.*)` → `/index.html`, so Vercel
  answers with a **static file**. A `POST` to a static asset is
  **405 Method Not Allowed** — no body, no CORS involvement.
- Reproduced with curl: `POST edr.nivxforge.com/api/auth/login → 405`, while
  the same POST to `nivxray.nivxforge.com` returns **422** (validation), i.e.
  the API is healthy and accepts POST.

**It is NOT reaching `https://nivxray.nivxforge.com`. It is incorrectly
hitting `https://edr.nivxforge.com`.**

**Which configuration causes it:** `REACT_APP_NIVXRAY_API_URL` was empty at
build time. Two compounding reasons:
1. `apps/nivxray-xdr/.env` (which holds the fallback origin) is
   **gitignored** — `.gitignore:113: *.env` — so it does **not exist in the
   Git repository** and Vite's `loadEnv` found nothing.
2. The only thing that injects the production origin is
   `scripts/vercel-build.sh`, which **did not run**.

`vite.config.js` then compiled
`process.env.REACT_APP_BACKEND_URL` to `""`. The XDR project is unaffected
because its build *does* run the script (its bundle contains
`nivxray.nivxforge.com`).

**Note:** `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com` being set in the
Vercel dashboard did nothing, because only the build script reads it.

## 3 · EXACT deployed branch + commit
**I cannot read this from the workspace, and I will not guess it.** This
container has **no Git remote configured** (`git remote -v` returns nothing),
so I have no visibility of `jpreddy017/nivxray-xdr` or its `main`.

Read it here: **Vercel → `nivxray-edr-production` → Deployments → the
Production deployment → Source / Git commit** (branch + 7-char SHA + message).
Do the same for `nivxray-xdr-production` so we can compare.

What I **can** prove about it: whatever commit was deployed, it does **not**
contain the guarded build path, because the artifact has no `build-info.json`,
no injected API origin, no product scope and no `edr.nivxforge.com` → `/edr`
redirect.

## 4 · Expected branch + commit
The proven Phase-2 work lives on local branch **`feature/rc2-alignment`**,
commit **`f083b8d7`** ("Production routing — XDR live and untouched, EDR
build-ready"), which added the scope-parameterised
`scripts/vercel-build.sh`, the scope-parameterised
`scripts/verify-production-build.js`, and the
`edr.nivxforge.com` → `/edr` redirect in `apps/nivxray-xdr/vercel.json`.

**This commit has never been pushed** (there is no remote here), so **it cannot
be what Vercel built.** The earlier, XDR-hardcoded version of the script came
from `4d4c6132` — and even *that* did not run, since it also writes
`build-info.json`.

**Did creating the project from `main` cause an older/wrong build? Almost
certainly yes.** Local `main` (`7f280b66`) has **no `apps/` directory at all**
and no `vercel.json`, and is **1,568 commits behind** `feature/rc2-alignment`.
GitHub's `main` clearly differs from this stale local copy (your build did find
`apps/nivxray-xdr`), but it is evidently a ref **without** the Phase-2
deployment configuration. Confirm with the commit SHA from step 3.

## 5 · Did the EDR build guard run and pass?
**NO — it never ran.**
- `dist/build-info.json` is absent from the artifact; the guard reads that file
  and would have aborted without it.
- The bundle contains no production API origin; the guard's check
  *"API origin https://nivxray.nivxforge.com · N reference(s)"* would have
  **failed** the deployment.
- The deployment therefore published with **zero** production checks. The
  guard working as designed would have **blocked exactly this outcome.**

## 6 · MINIMAL CORRECTIVE ACTION (no DNS change; DNS is correct)
DNS and the domain attachment are **fine** — the host resolves and serves. The
defect is entirely *which commit was built*. Minimal fix, in order:

1. **Read the deployed commit** for both projects (step 3) and send them to me.
2. **Publish the proven commit to GitHub** using the chat's **“Save to
   Github”** feature (I do not perform Git write actions). Target the branch
   that the Vercel projects build from, or a new branch you then select.
3. **Point `nivxray-edr-production` at that ref** (Settings → Git → Production
   Branch) and redeploy. Keep `NIVX_PRODUCT_SCOPE=edr` and
   `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com` exactly as they are —
   they are correct; they simply had no consumer on the old commit.
4. **Accept the deploy only if the build log prints
   `EDR PRODUCTION BUILD GUARD · PASSED`**, and then
   `https://edr.nivxforge.com/build-info.json` returns real JSON with
   `product_scope=edr` and `api_origin=https://nivxray.nivxforge.com`.

**Do not** add a redirect, patch the API base, or commit a `.env` to make this
pass — every one of those hides the real fault, which is a stale deployed
commit. The `.env` is gitignored on purpose; the build script is the correct
and only injector.

⚠ **Also check `nivxray-xdr-production` before redeploying anything**: it is
currently working, so it must be building from a ref that *does* contain the
guarded script. Confirm its commit first so repointing branches cannot
regress the live XDR site.

## 7 · GO / NO-GO for changing anything
**NO-GO** for changing code, DNS, env vars, Vercel build settings, the database
or auth right now — nothing in this repository needs a fix. The committed
source is already correct and independently proven; only the **deployed
commit** is wrong.

**GO** for exactly two owner actions, in this order: (a) read and report the
deployed commit SHAs, (b) publish the proven commit via **Save to Github** and
repoint the EDR project's branch.

## Standing risk while unfixed (not data exposure today)
`edr.nivxforge.com` currently serves the **full XDR console with no product
boundary** (`/xdr/*` renders, no wrong-host notice). It cannot reach the API,
so no customer data is retrievable and the 405 is, accidentally, containing
it. But if the API origin alone were "fixed" without restoring the product
scope, EDR visitors would get a working XDR console. The scope must be
restored **before or together with** the API origin — which is precisely what
the guarded build does in one step.
