# PRODUCTION ROUTING — XDR LIVE · EDR BUILD-READY (2026-06)

**XDR production is LIVE and was not modified.** No DNS created or changed by
the agent. No deploy triggered. No database touched. No preview/test data
written to production. No secrets requested or exposed.

---

## 1 · XDR Root Directory + build config — RE-CONFIRMED FROM THE LIVE ARTIFACT
Not assumed — read off the running deployment:

```
GET https://xdr.nivxforge.com/build-info.json
{ "product":"nivxray-xdr", "product_scope":"xdr",
  "api_origin":"https://nivxray.nivxforge.com", "phase":"2",
  "built_at":"2026-09-09T03:26:37Z" }

GET https://xdr.nivxforge.com/            → 307 → https://xdr.nivxforge.com/xdr
GET https://xdr.nivxforge.com/xdr/incidents → 200
GET https://xdr.nivxforge.com/login         → 200
```

`build-info.json` is written **only** by
`apps/nivxray-xdr/scripts/vercel-build.sh`, and the `/` → `/xdr` host redirect
exists **only** in `apps/nivxray-xdr/vercel.json`. Both are present in the live
deployment, therefore:

- **Root Directory = `apps/nivxray-xdr`** ✔
- the **guarded** production build ran (scope declared, production API origin,
  `verify-production-build.js` executed) ✔
- the unguarded repo-root config was **never** used ✔

A working configuration was therefore left alone, exactly as instructed. The
XDR build path is byte-compatible after this change: rebuilding locally with
the defaults reproduces `product_scope=xdr` and
`api_origin=https://nivxray.nivxforge.com`.

## 2 · Root `vercel.json` risk — RESOLVED BY HARD FAILURE
The old `/app/vercel.json` was a fully working config that built
`apps/nivxray-xdr` with a plain `vite build`: **no product scope** (the XDR
host would render `/edr/*`), **no API override** (the *preview* origin from
`apps/nivxray-xdr/.env` baked into a production bundle), and **no build
guard** to catch either.

It is now a **deployment refusal**: `buildCommand` runs
`scripts/refuse-root-deployment.sh`, which prints the correct settings and
exits **1** — so an accidental root-directory project **fails and publishes
nothing** instead of silently shipping a bad bundle.

*Why not delete it?* With no config at the root, Vercel falls back to
framework auto-detection and would build something unpredictable. Failing
loudly is deterministic. Verified: `root_refusal_exit=1`.

## 3 · Scope-parameterised build + guard — ONE repo, TWO separate artifacts
Both projects share Root Directory `apps/nivxray-xdr`, therefore the same
`vercel.json` and the same build command — so the product **must** come from a
per-project environment variable.

| Variable | XDR project | EDR project |
|---|---|---|
| `NIVX_PRODUCT_SCOPE` | unset or `xdr` | **`edr`** |
| `XDR_PROD_API_ORIGIN` | `https://nivxray.nivxforge.com` (default) | same |

- `scripts/vercel-build.sh` now takes `NIVX_PRODUCT_SCOPE` (**default `xdr`**,
  so the live XDR build is unchanged), refuses any other value, and records
  the scope in `build-info.json`.
- `scripts/verify-production-build.js` now asserts the scope it was *asked*
  for, and derives the **forbidden host** from it: the XDR artifact must not
  contain `edr.nivxforge.com` and the EDR artifact must not contain
  `xdr.nivxforge.com`.

**XDR and EDR remain two separate artifacts on two hostnames.** No
hostname-aware single bundle was created — the boundary stays a build fact
enforced by `productScope.js` + `ProductScopeGuard`, not a runtime string
comparison.

## 4 · XDR production preserved
`https://xdr.nivxforge.com` re-verified **after** all code changes: `/` → 307
`/xdr`, `build-info.json` still `scope=xdr`,
`api=https://nivxray.nivxforge.com`. Nothing about the XDR DNS, domain
assignment or project settings was touched.

## 5 · EDR readiness
`apps/nivxray-xdr/vercel.json` now carries the second host redirect
(`/` → `/edr` when `host = edr.nivxforge.com`) alongside the XDR one. Both
rewrites `/(.*)` → `/index.html` remain, so deep links work on both hosts.

EDR build proven locally from the same commit — see the results table below.

## 6 · Cross-product URLs — WIRED AND VALIDATED, DELIBERATELY NOT ACTIVATED
`REACT_APP_XDR_URL` / `REACT_APP_EDR_URL` / `REACT_APP_WORKSPACE_URL` are now
driven by the build script behind an explicit switch:

```
NIVX_CROSS_PRODUCT_ORIGINS=1        # off by default
NIVX_XDR_ORIGIN        default https://xdr.nivxforge.com
NIVX_EDR_ORIGIN        default https://edr.nivxforge.com
NIVX_WORKSPACE_ORIGIN  default https://workspace.nivxmachines.com
```

**Why off by default — two hard reasons, not caution:**
1. `edr.nivxforge.com` does **not resolve yet**. Baking it in today ships dead
   links to production analysts.
2. The build guard treats the other product's hostname as a **forbidden
   string** (owner decision 5b). Setting `REACT_APP_EDR_URL` on the XDR build
   right now would **fail the XDR deployment**.

With the switch on, the guard reclassifies both product hosts from *forbidden*
to *allowed link targets* — proven by a real build (below). So it is
configured, validated end-to-end, and one env var away from active. Flip it on
**both** projects only after `edr.nivxforge.com` is live.

## 7 · Production CORS — MEASURED, NOTHING WEAKENED
Live preflight against the production API:

```
OPTIONS https://nivxray.nivxforge.com/api/auth/login
  Origin: https://xdr.nivxforge.com        → 200  ACAO: *   (no ACA-Credentials)
  Origin: https://edr.nivxforge.com        → 200  ACAO: *
  Origin: https://workspace.nivxmachines.com → 200  ACAO: *
  Origin: https://evil.example.com         → 200  ACAO: *
```

Production `CORS_ORIGINS` is therefore **wildcard mode**, which
`security/cors.py` handles by forcing `allow_credentials=False`.

**Conclusion: no CORS change is required for XDR or EDR — both origins already
work, and nothing was weakened.** This is safe as built because auth is an
`Authorization: Bearer` header and no cookie is used.

**Disclosed, NOT changed (out of scope):** wildcard means any website can call
the API from a browser. It cannot read a response without a token, so it is
not an authz hole, but tightening `CORS_ORIGINS` to the three real origins
would be a genuine hardening step. That is a separate, owner-approved change —
it also flips `allow_credentials` to `True`, which must be reviewed
deliberately rather than slipped into a routing task.

---

## FILES CHANGED (4 · frontend/deployment only, zero backend)
| File | Change |
|---|---|
| `apps/nivxray-xdr/scripts/vercel-build.sh` | Parameterised by `NIVX_PRODUCT_SCOPE` (default `xdr`); refuses an invalid scope; env-driven cross-product origins behind `NIVX_CROSS_PRODUCT_ORIGINS`; records scope + switch in `build-info.json`; passes the scope to the guard. |
| `apps/nivxray-xdr/scripts/verify-production-build.js` | Scope-parameterised: asserts the requested scope, derives the forbidden host from it, allows both product hosts only when cross-product linking is enabled; scope-labelled output. |
| `apps/nivxray-xdr/vercel.json` | Added the `edr.nivxforge.com` `/` → `/edr` host redirect next to the existing XDR one. |
| `/app/vercel.json` | Replaced the working-but-unguarded root build with a **hard refusal** (`scripts/refuse-root-deployment.sh`, new file). |

Untouched: all backend code, `frontend/` and `frontend/vercel.json`
(Workspace), `src/productScope.js`, `ProductScopeGuard.jsx`, the router, DNS,
Vercel settings, the database.

## TESTS / BUILD GUARDS EXECUTED
| Check | Result |
|---|---|
| XDR production build (defaults) | **PASS** — `XDR PRODUCTION BUILD GUARD · PASSED`, `product_scope=xdr`, `api_origin=https://nivxray.nivxforge.com`, no preview origin in 123 artifacts, no `edr.nivxforge.com` dependency |
| EDR production build (`NIVX_PRODUCT_SCOPE=edr`) | **PASS** — `EDR PRODUCTION BUILD GUARD · PASSED`, `product_scope=edr`, no `xdr.nivxforge.com` dependency |
| EDR build with cross-product linking on | **PASS** — guard reclassifies `xdr.nivxforge.com` to an allowed link target; `cross_product_origins: 1` recorded |
| Invalid scope rejected | **exit 1** |
| Guard rejects scope/artifact mismatch | **exit 1** (`product_scope is "edr" — must be "xdr"`) |
| Root-directory deployment refused | **exit 1**, nothing published |
| All three `vercel.json` files valid JSON | **OK** |
| `dist/` gitignored (no artifact pollution) | **OK** |

## XDR REGRESSION RESULT
- Live `https://xdr.nivxforge.com` **unchanged after all edits**: `/` 307 →
  `/xdr`, `/xdr/incidents` 200, `/login` 200, `build-info.json`
  `scope=xdr` + production API.
- Local XDR rebuild reproduces the live artifact's scope and API origin.
- Backend **58/58 PASS** (`test_collector_api_key_auth.py`,
  `test_p0sec_rbac_fail_closed.py`, `test_p0_dedupe_upgrade_guard.py`) — the
  proven collector-auth and hardened ingest-idempotency work is intact and was
  not reopened.

## EDR BUILD READINESS RESULT
**READY.** Same repo, same commit, Root Directory `apps/nivxray-xdr`, builds
clean and passes the production guard with `product_scope=edr`. The `/` →
`/edr` edge redirect is in place. Nothing further is needed from me before the
project is created.

---

## EXACT REMAINING MANUAL ACTION (owner)
**Step 1 — create the EDR Vercel project** (do not reuse the XDR project):
- Same Git repo and branch as `nivxray-xdr-production`
- **Root Directory: `apps/nivxray-xdr`**
- Environment Variables:
  - `NIVX_PRODUCT_SCOPE = edr`   ← without this the EDR host would serve XDR
  - `XDR_PROD_API_ORIGIN = https://nivxray.nivxforge.com`
- Deploy. The build must print **`EDR PRODUCTION BUILD GUARD · PASSED`**; if it
  prints `DEPLOYMENT REFUSED · WRONG ROOT DIRECTORY`, the Root Directory is
  wrong.

**Step 2 — add the domain in Vercel, then STOP.**
Add `edr.nivxforge.com` under that project's **Domains**. Vercel will then
display the CNAME it requires.

**Step 3 — the CNAME record (Cloudflare, zone `nivxforge.com`):**

| Field | Value |
|---|---|
| Type | `CNAME` |
| **Name** | **`edr`** |
| **Value** | **the exact target Vercel shows for the EDR project** |
| Proxy status | **DNS only (grey cloud) — must NOT be proxied** |
| TTL | Auto |

**I am not guessing the Value, and you should not either.** This account uses
**per-project** CNAME targets, confirmed by measurement:

```
xdr.nivxforge.com          → f0da8943bcd95c6a.vercel-dns-017.com
workspace.nivxmachines.com → 4544e63c01509511.vercel-dns-017.com
```

The EDR project will be issued a **different hash**. Copy it verbatim from the
Vercel Domains screen. Reusing the XDR target would point EDR at the XDR
deployment. Cloudflare proxying must stay off — an orange-cloud record breaks
Vercel's domain verification and TLS issuance.

**Step 4 — tell me when Vercel shows `edr.nivxforge.com` = Valid
Configuration**, and I will verify: `/` → 307 `/edr`; `/edr` 200;
`build-info.json` `scope=edr`; `edr.nivxforge.com/xdr/incidents` shows the
"wrong product host" notice and never XDR content (and the reverse on the XDR
host); deep-link refresh 200 on both; a browser API call from each origin.

**Step 5 — only after EDR is verified live**, set on **both** projects and
redeploy both, to turn cross-product links on:
`NIVX_CROSS_PRODUCT_ORIGINS = 1`

## Known consequence (not a defect)
The JWT lives in `localStorage["nvx_token"]`, which is origin-scoped, so an
analyst signs in separately on XDR, EDR and Workspace. Changing that is an
auth change (a `.nivxforge.com` cookie, which still would not reach
`nivxmachines.com`) and is deliberately out of scope here.
