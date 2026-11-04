# PRODUCTION URL ROUTING — AUDIT + FIX PLAN (2026-06)

**Read-only audit. No DNS changed, no deploy, no code changed.**

Target topology:
| Product | Hostname | Status today |
|---|---|---|
| XDR | `xdr.nivxforge.com` | **NXDOMAIN — no DNS record at all** |
| EDR | `edr.nivxforge.com` | **NXDOMAIN — no DNS record at all** |
| Workspace | `workspace.nivxmachines.com` | **LIVE** (HTTP 200, on Vercel) |
| API | `nivxray.nivxforge.com` | **LIVE** (`/api/health` 200, behind Cloudflare) |

---

## 1 · DNS — measured
```
xdr.nivxforge.com           NXDOMAIN            curl → 000 (cannot resolve)
edr.nivxforge.com           NXDOMAIN
workspace.nivxmachines.com  64.29.17.65  CNAME 4544e63c01509511.vercel-dns-017.com   → 200
nivxray.nivxforge.com       162.159.142.117                                          → /api/health 200
nivxforge.com   (apex)      162.159.142.117
nivxmachines.com (apex)     172.66.2.113
```

Readings:
- `xdr` / `edr` have **never been created, or were removed** — this is not a
  propagation delay or a TLS problem; the names do not exist. Any earlier note
  that `xdr.nivxforge.com` was live is **not true of the current DNS**. A
  Vercel project may still exist with the domain *added but unverified*.
- `nivxray.nivxforge.com` and the `nivxforge.com` apex share
  `162.159.142.117` → **`nivxforge.com` DNS is hosted at Cloudflare and the
  API is Cloudflare-proxied**. So the two missing records must be created in
  **Cloudflare**, not in Vercel.
- `workspace.nivxmachines.com` resolves to a **per-project Vercel DNS target**
  (`…vercel-dns-017.com`), which is the exact pattern the new records need.

### Missing records — precisely two
| Type | Name (zone `nivxforge.com`) | Value | Proxy |
|---|---|---|---|
| CNAME | `xdr` | the value Vercel shows for that project (`cname.vercel-dns.com` or a per-project `<hash>.vercel-dns-0NN.com`) | **DNS only (grey cloud)** |
| CNAME | `edr` | same, for the EDR project | **DNS only (grey cloud)** |

**Cloudflare proxying must be OFF** for these two. An orange-cloud record
breaks Vercel's domain verification and its TLS issuance, and would put two
proxies in front of a static SPA. `nivxray.nivxforge.com` stays exactly as it
is — do not touch it.

## 2 · Vercel project / deployment assignment
| Hostname | Must attach to | Root Directory | Output |
|---|---|---|---|
| `workspace.nivxmachines.com` | existing Workspace project (`/app/frontend`, CRA) | `frontend` | `build` |
| `xdr.nivxforge.com` | XDR project built from `apps/nivxray-xdr` | **`apps/nivxray-xdr`** | `dist` |
| `edr.nivxforge.com` | a **separate** EDR project, same repo/commit | **`apps/nivxray-xdr`** | `dist` |
| `nivxray.nivxforge.com` | **not Vercel** — the FastAPI backend behind Cloudflare | — | — |

### ⚠ FINDING 1 (highest risk) — two competing `vercel.json` files build the XDR app
| File | What it does |
|---|---|
| `/app/vercel.json` (repo root) | `cd apps/nivxray-xdr && yarn install --frozen-lockfile`, plain `vite build`, output `apps/nivxray-xdr/dist`. **No `PRODUCT_SCOPE`. No host redirect. No build guard.** |
| `/app/apps/nivxray-xdr/vercel.json` | `bash scripts/vercel-build.sh` → sets `REACT_APP_PRODUCT_SCOPE=xdr` **and** `REACT_APP_NIVXRAY_API_URL=https://nivxray.nivxforge.com`, then runs `verify-production-build.js`; plus a host redirect `/` → `/xdr` for `xdr.nivxforge.com`. |

Vercel uses **whichever file sits in the project's Root Directory**. If the XDR
project's Root Directory is the repo root, the root file wins and the
deployment gets:
- **no product scope** → the XDR host would happily render `/edr/*`
  (the product boundary silently disappears), and
- **the preview API origin** baked in from `apps/nivxray-xdr/.env`
  (`REACT_APP_NIVXRAY_API_URL=https://…preview.emergentagent.com`), because
  nothing overrides it.

**This is the single most important thing to confirm before any deploy.**

### FINDING 2 — the production build guard is XDR-only
`apps/nivxray-xdr/scripts/vercel-build.sh` hardcodes `SCOPE="xdr"`, and
`scripts/verify-production-build.js` **hard-fails** the deployment when
`build-info.json.product_scope !== "xdr"`, when the expected API origin is
absent, and it treats `edr.nivxforge.com` as a *forbidden host* inside the XDR
bundle. It therefore **cannot be reused as-is for the EDR project** — reusing
it would fail the EDR build, and bypassing it would ship an unguarded bundle.

## 3 · Can XDR and EDR share ONE canonical frontend deployment with hostname-aware routing?
**Not with today's code — no.** The product boundary is **build-time**:

- `src/productScope.js` reads `process.env.REACT_APP_PRODUCT_SCOPE`, which
  Vite inlines at build time. `PRODUCT_SCOPE`, `IS_SCOPED`, `HOME_PATH` and
  `isForeignPath()` all derive from that constant.
- `src/components/ProductScopeGuard.jsx` is the only thing preventing
  `xdr.nivxforge.com/edr/trajectory` from rendering EDR on the XDR host.
- One built artifact can therefore declare exactly **one** scope.

Two viable options:

**Option A (recommended) — one canonical source, two scoped builds.**
Two Vercel projects from the **same repo and same commit**, both with Root
Directory `apps/nivxray-xdr`, differing only in the scope passed to the build
(`xdr` vs `edr`). Same canonical frontend code; the product boundary stays a
hard, verifiable build fact; `verify-production-build.js` keeps working per
product. **No router/runtime code change.**

**Option B — runtime hostname-derived scope, one deployment.**
Change `productScope.js` to derive the scope from `window.location.hostname`.
One deployment then serves both hostnames. Costs: the boundary becomes a
runtime string comparison instead of a build artifact; `build-info.json` +
`verify-production-build.js` provenance checks must be redesigned (they assert
a single scope); `ProductScopeGuard`'s recovery (a full page reload expecting
an edge redirect) has to be replaced by an explicit cross-host redirect. **Not
recommended for the first production rollout** — it trades a proven guarantee
for one fewer Vercel project.

## 4 · Code / router changes required
**For Option A the SPA router needs no change** (`/xdr/*` and `/edr/*` routes
already exist, and `HOME_PATH` already follows the scope). Four small,
non-router changes are required:

1. **Parameterise the build script** — `scripts/vercel-build.sh` must accept
   `SCOPE` (default `xdr`) instead of hardcoding it, and
   `verify-production-build.js` must assert the scope it was *asked* for
   rather than the literal `"xdr"`, with the forbidden-host list derived from
   that scope. Without this the EDR project cannot build under the guard.
2. **Add the EDR host redirect** — `apps/nivxray-xdr/vercel.json` has
   `/` → `/xdr` only when `host = xdr.nivxforge.com`. An equivalent
   `/` → `/edr` for `host = edr.nivxforge.com` is needed, otherwise
   `edr.nivxforge.com/` server-renders `index.html` and then client-redirects
   via `HOME_PATH` (works, but the first paint is a redirect rather than an
   edge redirect).
3. **Set the cross-product origin variables at build time.**
   `REACT_APP_XDR_URL`, `REACT_APP_EDR_URL`, `REACT_APP_WORKSPACE_URL` are all
   **empty** today, so `productHref()` returns `SAME_ORIGIN` in-app paths.
   Combined with the fact that the cross-host `/edr/*` redirects were removed
   (owner decision 5b), a cross-product pivot on a scoped host reloads once and
   then renders the **"wrong product host" dead-end notice with no link out**.
   Setting the three URLs turns every pivot into a real absolute cross-origin
   link. This is configuration, not code.
4. **Delete or neutralise `/app/vercel.json`** (or prove no project uses the
   repo root as its Root Directory), so the unguarded, unscoped,
   preview-API-pointing build path cannot ever be selected. *Recommend
   deleting it once Root Directory is confirmed — it is a live footgun.*

## 5 · Auth and CORS implications
**Auth — separate logins per hostname (unavoidable as designed).**
The JWT lives in `localStorage["nvx_token"]` (`src/lib/api.js`,
`src/lib/auth.jsx`). `localStorage` is **origin-scoped**, so
`xdr.nivxforge.com`, `edr.nivxforge.com` and `workspace.nivxmachines.com` are
three separate stores → **an analyst logs in three times**, and a cross-product
pivot lands on a login screen until they do. There is no way to share it
across origins. Changing this means moving the session to a cookie on
`.nivxforge.com` (a real auth change, and it still would not reach
`nivxmachines.com`, a different registrable domain). **Owner decision, not a
bug.** Note `/login` is already `null`-scoped in `productOfPath()`, so both
hostnames can serve their own login page.

**CORS — must be confirmed against the production backend env.**
`security/cors.py` reads `CORS_ORIGINS`: an explicit comma list → that list
with `allow_credentials=True`; unset or `"*"` → wildcard with credentials
forced off. This pod has `CORS_ORIGINS="*"`, which would work because auth
uses an `Authorization: Bearer` header, not cookies. **If the production
backend uses an explicit allow-list, `https://xdr.nivxforge.com` and
`https://edr.nivxforge.com` must be added to it** or every API call from the
new hosts fails preflight. I cannot read the production env from here.

**Cloudflare** — no change needed for the API. New browser origins calling
`nivxray.nivxforge.com` need no edge change; only the backend `CORS_ORIGINS`
value matters.

**SPA routing** — both `vercel.json` files already rewrite `/(.*)` →
`/index.html`, so deep links such as `xdr.nivxforge.com/xdr/incidents/<id>`
will resolve once DNS and the domain attachment exist. No 404 risk.

---

## EXACT OWNER ACTIONS (in order)
**Confirm first (no changes yet) — 4 answers I cannot obtain:**
1. In Vercel, for the XDR project: what is the **Root Directory**? (Must be
   `apps/nivxray-xdr`. If it is the repo root, the build is unscoped and points
   at the preview API.)
2. Does `xdr.nivxforge.com` already appear under that project's **Domains**,
   and what exact DNS value does Vercel display for it?
3. Does an **EDR Vercel project** exist yet, or should one be created?
4. What is the **production backend `CORS_ORIGINS`** value — `*` or an
   explicit list?

**Then, DNS at Cloudflare (zone `nivxforge.com`):**
5. Add `CNAME xdr` → the value from answer 2, **proxy DNS-only (grey cloud)**.
6. Add `CNAME edr` → the value Vercel shows for the EDR project, **DNS-only**.
7. Do **not** modify `nivxray` or the apex.

**Then, Vercel:**
8. Attach `xdr.nivxforge.com` to the XDR project; attach
   `edr.nivxforge.com` to the EDR project. Set each project's Root Directory to
   `apps/nivxray-xdr`.
9. Set per-project build env: XDR → scope `xdr`; EDR → scope `edr`; both
   `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com`; and
   `REACT_APP_XDR_URL=https://xdr.nivxforge.com`,
   `REACT_APP_EDR_URL=https://edr.nivxforge.com`,
   `REACT_APP_WORKSPACE_URL=https://workspace.nivxmachines.com` on all three
   projects.

**Code work I will do on your approval (small, no router rewrite):**
10. Parameterise `vercel-build.sh` + `verify-production-build.js` for scope.
11. Add the `edr.nivxforge.com` `/` → `/edr` host redirect.
12. Remove `/app/vercel.json` once Root Directory is confirmed.

**Zero-damage guarantees**: `workspace.nivxmachines.com` and its
`frontend/vercel.json` are untouched; `nivxray.nivxforge.com` and Cloudflare
settings for the API are untouched; the shipped Workspace project is not
modified.

## Verification once DNS exists (I can run these)
- `xdr.nivxforge.com/` → 200 and lands on `/xdr/incidents`.
- `edr.nivxforge.com/` → 200 and lands on `/edr`.
- `xdr.nivxforge.com/edr/trajectory` → the "wrong product host" notice, never
  EDR content; and vice versa.
- Each host's `dist/build-info.json` reports the correct `product_scope` and
  `api_origin=https://nivxray.nivxforge.com`.
- A browser API call from each origin succeeds (CORS preflight OK).
- Deep-link refresh on both hosts returns 200, not 404.
