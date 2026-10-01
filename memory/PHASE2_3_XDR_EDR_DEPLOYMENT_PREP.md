# Phase 2 / 3 · XDR + EDR production deployment prep

**Owner decisions: `1a · 2a · 3a · 4a · 5a`. PREPARE ONLY — nothing
deployed, no DNS, no new domains.**
Hostnames are fixed: `xdr.nivxforge.com`, `edr.nivxforge.com`,
`workspace.nivxmachines.com`. **No domain purchases required or proposed.**

Execution is gated behind Workspace Phase 1 verification, per the lock.

---

## 1 · The finding that drove the design

XDR and EDR are **not two applications**. They are one Vite bundle at
`apps/nivxray-xdr`:

| | |
|---|---|
| total routes in `src/App.jsx` | **60** |
| `/xdr/*` routes | **42** |
| `/edr/*` routes | **13** |
| catch-all | `<Route path="*" element={<Navigate to="/xdr" replace />} />` |

So attaching `edr.nivxforge.com` to that bundle unguarded means
`edr.nivxforge.com/` lands the analyst on **`/xdr/incidents`** — XDR served
from the EDR hostname. That is exactly the *"no launcher may silently fall
back into the wrong product"* failure the owner prohibited, and it would
have shipped on day one.

## 2 · Topology (owner 1a)

```
Vercel Project A                     Vercel Project B
Root: apps/nivxray-xdr               Root: apps/nivxray-xdr
Domain: xdr.nivxforge.com            Domain: edr.nivxforge.com
  /        → /xdr                      /        → /edr
  /xdr/*   served here                 /edr/*   served here
  /edr/*   → edr.nivxforge.com         /xdr/*   → xdr.nivxforge.com
```

Two projects, one Root Directory. Each product deploys, verifies and rolls
back **independently** — which is what makes Phase 2 and Phase 3 separate
gates rather than one coupled release.

**Both projects read the same `apps/nivxray-xdr/vercel.json`.** That is
precisely why the boundary is expressed as **host-conditional redirects**
(`has: [{ type: "host" }]`) instead of per-project build settings: a build
command cannot tell the two projects apart, but the edge can tell the two
hostnames apart.

## 3 · The guard (owner 2a) — written and proven

Six rules in `apps/nivxray-xdr/vercel.json`. Cross-host rules come **first**
so the `/` landing rules cannot shadow them; both the bare path and the
`:path*` form are listed rather than trusting `:path*` to also match the
bare path. `permanent: false` (307) is deliberate — a 308 is cached by
browsers and is the wrong tool while a topology is still moving.

`scripts/xdr_edr_redirect_rules_proof.py` reads the **actual** rule set,
re-implements Vercel's matching for the patterns used, and drives the real
route table extracted from `App.jsx`. **11/11 PASS**
(`memory/xdr_edr_redirect_rules_proof.json`):

- `xdr.nivxforge.com/` → `/xdr`; `edr.nivxforge.com/` → `/edr`
- **all 13** `/edr` routes leave the XDR host
- **all 42** `/xdr` routes leave the EDR host
- each host **keeps its own** routes (no accidental self-redirect)
- every chain **terminates** — 16 host/path combinations settle, no loops,
  no ping-pong between hosts
- **preview and `*.vercel.app` hosts match no rule**, so Preview XDR and
  Preview EDR keep working exactly as today (`productOrigins` stays in
  `SAME_ORIGIN` mode there)
- SPA rewrite intact; no 308s

### Coverage limit, stated plainly

These are **server** redirects. They fire on every real navigation — typed
URL, external link, bookmark, hard refresh, any full page load. They
**cannot** fire on client-side React navigation after the page is already
loaded, because no HTTP request is made.

**Closed. Owner-approved and implemented — see §3.1.**

The residual case was: on the EDR host, an unknown path hit the app's
catch-all, which client-side navigated to `/xdr`, so an analyst could end
up looking at XDR on `edr.nivxforge.com` without a server round-trip.

### 3.1 · Product scope — implemented and proven (owner: APPROVED)

`REACT_APP_PRODUCT_SCOPE` = `xdr` | `edr`, set per Vercel project. It is a
**product-scope** variable, not a cross-product origin variable: it lights
up no launcher, so decision 4a is untouched.

| file | role |
|---|---|
| `src/productScope.js` | `PRODUCT_SCOPE`, `HOME_PATH`, `productOfPath()`, `isForeignPath()` |
| `src/components/ProductScopeGuard.jsx` | blocks the other product from rendering |
| `src/App.jsx` | explicit `/` route → `HOME_PATH`; catch-all `*` → `HOME_PATH` (was a hard-coded `/xdr`); `<Routes>` wrapped in the guard |
| `vite.config.js` | exposes the variable (`REACT_APP_*` or `VITE_*`) |

**How it recovers without any origin variable.** The correct destination for
a foreign path is already encoded in the proven host redirects, so the guard
simply forces **one full page load of the same URL** — the edge rule then
sends the analyst to the right hostname. The redirect table stays the single
source of truth, and `REACT_APP_XDR_URL` / `_EDR_URL` stay unset.

**Loop-safe by construction.** The reload is attempted at most once per path
(session-scoped marker). If the host has no edge rule — a preview host where
a scope was set by mistake — the second pass renders an explicit
`wrong product host` notice and **never** the other product.

**UNSET is a first-class state.** Preview and any combined deployment
genuinely serve both products at one origin, so nothing is foreign there and
behaviour is byte-for-byte what it was. Preview XDR and Preview EDR are
untouched.

`/login` is treated as **neutral** — both hostnames need it — while `/kb`
and `/docs` are XDR-owned because they redirect into `/xdr/*`.

#### Proof · `scripts/xdr_edr_product_scope_proof.py` → **21/21 PASS**

The same bundle is built **three times** (scope `edr`, `xdr`, UNSET) and each
is served on a plain SPA host with **no edge redirects** — deliberately the
worst case, so the guard's behaviour is observable instead of being masked
by a redirect — then driven in a real browser
(`memory/xdr_edr_product_scope_proof.json`):

- all three builds succeed; the scope value is inlined
- `scope=edr`: `/` → `/edr`, unknown path → `/edr`, and **all three tested
  `/xdr` paths blocked with XDR never rendering**
- `scope=xdr`: mirrored, `/edr` paths blocked
- no loop on a host without an edge rule
- **own** product routes not blocked; neutral `/login` reachable on both
- `scope=UNSET`: `/` → `/xdr` and **no guard at all** — previous behaviour

#### A real bug this proof caught, which the build did not

The first run failed 2/21 with the foreign paths not blocked. Cause:
`ProductScopeGuard.jsx` imported only `useEffect` from `react`, but this app
builds with the **classic JSX runtime** (`vite.config.js ·
jsxRuntime: "classic"`), so JSX compiles to `React.createElement` and needs
`React` in scope. **The build passed cleanly and the entire app then crashed
at runtime with `ReferenceError: React is not defined`** — a blank page, not
a degraded guard. Fixed with an explicit `import React`, and the reason is
recorded in the file so it is not reintroduced. A build-only check would
have shipped this.

## 4 · API origin (owner 3a)

Set **per project** in the Vercel dashboard:

```
Project A (xdr.nivxforge.com)      Project B (edr.nivxforge.com)
REACT_APP_NIVXRAY_API_URL=         REACT_APP_NIVXRAY_API_URL=
  https://nivxray.nivxforge.com      https://nivxray.nivxforge.com
REACT_APP_PRODUCT_SCOPE=xdr        REACT_APP_PRODUCT_SCOPE=edr
```

`REACT_APP_PRODUCT_SCOPE` is **required** on both projects — without it the
client-side boundary is inert (see §3.1).

Classification: **`TEMPORARY_MIGRATION_DEPENDENCY`**, same as the Workspace.
Therefore `nivxray.nivxforge.com` remains **not eligible for retirement**
after Phase 2/3 either.

**No dotenv precedence trap in this app — verified, not assumed.**
`vite.config.js` uses `loadEnv(mode, process.cwd(), "")`, and a real
environment variable *does* override `.env`: a build run with
`REACT_APP_NIVXRAY_API_URL=https://nivxray.nivxforge.com` emitted **4
production refs and 0 preview refs**, despite `.env` still naming the
preview host. This is the opposite of the CRA Workspace app, where craco's
`dotenv` call at module load makes `.env` win — so **do not** copy the
Workspace's "everything in the buildCommand" pattern here; dashboard
variables are correct and cleaner for two projects sharing one config file.

## 5 · Launcher variables stay unset (owner 4a)

Leave `REACT_APP_XDR_URL`, `REACT_APP_EDR_URL` and
`REACT_APP_WORKSPACE_URL` **unset** on both projects.

`src/productOrigins.js` already distinguishes `CONFIGURED` from
`SAME_ORIGIN`, so unset means cross-product controls stay honest rather than
pointing at an unverified product. The acceptance sweep **asserts** they are
absent from the shipped bundle, so a launcher cannot be switched on by
accident.

## 6 · Acceptance (prepared, not run)

`scripts/xdr_edr_live_acceptance.py --product xdr|edr` — each product gated
**independently**:

- **A** host answers over https, serves the index document
- **B** `/` redirects to its own product
- **C** product containment: the sibling's routes redirect to the sibling
  host; **own** deep links are *not* redirected away
- **D** own deep links survive a **hard refresh**
- **E** protected surfaces gate to a login route
- **F** shipped artefact: 0 preview origins, approved production API
  present, **launcher origins still unset**
- **G** zero damage: legacy host, legacy API, Preview XDR, Preview EDR and
  the sibling product all still serving
- **H** no uncaught console/runtime errors
- **I** authenticated checks → **`BLOCKED_BY_PRODUCTION_CREDENTIAL`**, never
  skipped, never satisfied with preview credentials

Clean run classifies as `XDR_PRODUCTION_UNAUTHENTICATED_VERIFIED` /
`EDR_PRODUCTION_UNAUTHENTICATED_VERIFIED` — nothing stronger.

## 7 · Rollback drill (prepared, per product)

Independent rollback is the reason for two projects, so it must be proven
per product, not once:

1. Note the current production deployment id.
2. Deployments → previous known-good → **Promote to Production**. Vercel
   restores the **artefact**; it does not re-run the build.
3. Confirm the domain serves the previous version.
4. Re-promote the verified deployment.
5. Assert unchanged throughout: Emergent production, the legacy API, the
   production database, Preview XDR, Preview EDR, the Workspace deployment
   and the **sibling product's** domain.

## 8 · Commercial licensing — flagged, not assumed

**Vercel's Hobby plan is licensed for non-commercial use.** XDR and EDR are
sellable products, so **Pro is the expected plan before they serve
customers**. Per the owner: treat Pro as the assumption, **verify the current
licensing terms before launch**, and **do not upgrade now** — preparing the
configuration needs no paid plan.

## 9 · Execution order (unchanged)

```
Workspace Phase 1 verified  ← WE ARE HERE, blocked on owner-side Vercel setup
        ↓
Phase 2 · XDR → xdr.nivxforge.com → verify → owner approval
        ↓
Phase 3 · EDR → edr.nivxforge.com → verify → owner approval
        ↓
Phase 4 · cross-product launchers (origin variables set at last)
        ↓
Phase 5 · permanent API origin, then retire nivxray.nivxforge.com
```

**Nothing in Phase 2/3 may start before the Workspace gate.** This document
and the two scripts are preparation only.
