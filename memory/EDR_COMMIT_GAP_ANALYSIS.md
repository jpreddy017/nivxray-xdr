# EDR COMMIT-GAP ANALYSIS (2026-06) — READ ONLY

Nothing changed: no code, GitHub, Vercel, DNS, env vars or production.

## Deployment evidence taken as given
| | XDR | EDR |
|---|---|---|
| Project | `nivxray-xdr-production` | `nivxray-edr-production` |
| Branch | `conflict_310826_2116` | `main` |
| Commit | `bb8a4d2` — *Fix XDR frozen lockfile for D3 dependency* | `752a00f` |
| Vercel | Production / Current · guard **PASSED** | Production / Current · **no guard ran** |

`752a00f` resolves locally to **`752a00ff`** — *"Round 9 · P0.3 Collector
Runtime + Snort Adapter + P0.4 Golden E2E · SHIPPED"* — and it is an ancestor
on `feature/rc2-alignment`, so an exact file-level diff was possible.

---

## 1 · Exact proven EDR commit that should be deployed
**Branch `feature/rc2-alignment`, commit `f083b8d7`**
("Production routing — XDR live and untouched, EDR build-ready").

It is the only commit that carries all three EDR requirements:
scope-parameterised `scripts/vercel-build.sh` (`NIVX_PRODUCT_SCOPE`),
scope-parameterised `scripts/verify-production-build.js`, and the
`edr.nivxforge.com` → `/edr` redirect in `apps/nivxray-xdr/vercel.json`.

## 2 · Does `f083b8d7` exist in GitHub? **NO.**
This container has **no Git remote**, so `f083b8d7` has never been pushed.
Independently confirmed by your own XDR build log: it prints

```
ok · no edr.nivxforge.com dependency (Phase 2 is XDR only)
XDR PRODUCTION BUILD GUARD · PASSED
```

That is the **pre-parameterisation** wording. `f083b8d7`'s guard prints
`(this artifact is XDR only)` and adds a `scope · xdr → xdr.nivxforge.com`
line, neither of which appears. So GitHub's newest deployment-config commit
(`bb8a4d2`) **predates** `f083b8d7`.

## 3 · Exactly what is missing from `752a00ff`
**258 commits behind `f083b8d7`.** These files **do not exist at all** at the
deployed EDR commit:

| Missing file | Consequence |
|---|---|
| `apps/nivxray-xdr/src/productScope.js` | **there is no product-scope mechanism** — `PRODUCT_SCOPE`, `IS_SCOPED`, `HOME_PATH`, `isForeignPath` do not exist |
| `apps/nivxray-xdr/src/components/ProductScopeGuard.jsx` | **no product boundary whatsoever** — `/xdr/*` renders on any host |
| `apps/nivxray-xdr/src/productOrigins.js` | no cross-product origin resolution |
| `apps/nivxray-xdr/scripts/vercel-build.sh` | nothing injects `REACT_APP_PRODUCT_SCOPE` or the production API origin, and no `dist/build-info.json` is written |
| `apps/nivxray-xdr/scripts/verify-production-build.js` | **no build guard exists to run** |
| `scripts/refuse-root-deployment.sh` | root-directory misuse not blocked |

`apps/nivxray-xdr/vercel.json` **does** exist at `752a00ff`, but as:
```json
"buildCommand": "yarn run vercel-build",
"rewrites": [{ "source": "/(.*)", "destination": "/index.html" }]
```
— a plain Vite build, **no `redirects` block at all**. That matches the EDR
deploy log exactly (raw `dist/assets/...` listing, `built in 4.42s`, zero guard
lines) and explains every observed symptom:

- no `productScope.js` ⇒ unscoped/pre-split app ⇒ `HOME_PATH` is `/xdr`
  ⇒ `returnTo=%2Fxdr%2Fincidents` and XDR branding;
- no `ProductScopeGuard` ⇒ `/xdr/incidents` returns 200 on the EDR host;
- no build script ⇒ empty API origin ⇒ same-origin `POST /api/auth/login`
  ⇒ static file ⇒ **405**;
- no redirects block ⇒ `GET /` does not 307 to `/edr`.

**Headline: `752a00ff` predates the XDR/EDR product split entirely.** It is the
pre-split, XDR-only application — not a mis-configured EDR build.

## 4 · Is repointing/redeploying EDR sufficient?
**It depends entirely on WHICH commit — and the obvious choice is wrong.**

- ❌ **Repointing EDR to `conflict_310826_2116` @ `bb8a4d2`** (the only proven
  ref already in GitHub) is **NOT sufficient, and is actively misleading.**
  That commit's build script **hardcodes `SCOPE="xdr"`** — its own log line
  `product scope declared "xdr"` proves it — and its `vercel.json` carries only
  the `xdr.nivxforge.com` → `/xdr` redirect. EDR would build an **XDR-scoped**
  bundle: the **405 would disappear** (the API origin gets injected) while
  `edr.nivxforge.com` still serves the XDR console. The fault would *look*
  fixed while becoming worse — a working XDR console on the EDR hostname.
  `NIVX_PRODUCT_SCOPE=edr` would be silently ignored.

- ✅ **Repointing EDR to a ref containing `f083b8d7` is sufficient** — no other
  change is needed. DNS, the domain attachment and both env vars are already
  correct. But `f083b8d7` **must be published to GitHub first** (via the chat's
  **Save to Github**; I do not perform Git writes).

Acceptance test after redeploy: the log must print
**`EDR PRODUCTION BUILD GUARD · PASSED`** and
`https://edr.nivxforge.com/build-info.json` must return **real JSON** with
`product_scope=edr` and `api_origin=https://nivxray.nivxforge.com`.

## 5 · Risk to XDR production `bb8a4d2`
| Approach | Risk to XDR |
|---|---|
| Publish `f083b8d7` to a **NEW branch** and point **only** the EDR project at it | **ZERO.** XDR keeps building `conflict_310826_2116` @ `bb8a4d2`, untouched. **Recommended.** |
| Push `f083b8d7` onto `conflict_310826_2116` | XDR **auto-redeploys**. Functionally it should pass (a local XDR build with the parameterised script reproduced `product_scope=xdr`, the production API origin and `GUARD · PASSED`) — but see the hard risk below. |
| **Force-push / overwrite** `conflict_310826_2116` | 🔴 **DO NOT.** `bb8a4d2` is *"Fix XDR frozen lockfile for D3 dependency"* and **is not present in this workspace at all** — it exists only in GitHub. Overwriting from local would **destroy that lockfile fix**, and `installCommand` uses `--frozen-lockfile`, so the **XDR production install would fail**. This is the exact class of failure that blocked Phase 1. |

Additional note: the local `apps/nivxray-xdr/yarn.lock` is **modified and
uncommitted** here and does not include the D3 fix, which is another reason to
publish to a new branch rather than anything that could overwrite XDR's ref.

## Minimal corrective action
1. **Save to Github** → publish `f083b8d7` to a **new branch** (e.g.
   `phase2/edr-production`). Do **not** target `conflict_310826_2116`.
2. Vercel → `nivxray-edr-production` → Settings → Git → **Production Branch =
   that new branch** → Redeploy. Keep `NIVX_PRODUCT_SCOPE=edr` and
   `XDR_PROD_API_ORIGIN=https://nivxray.nivxforge.com` unchanged.
3. Touch nothing on `nivxray-xdr-production`, DNS, the API or the database.
4. Report the new build log and I will verify scope, API origin, `/` → `/edr`,
   product isolation both ways, and login reachability.

⚠ One consistency check for you before step 1: XDR builds from
`conflict_310826_2116` while EDR built from `main`. If the new branch is cut
from this workspace's `feature/rc2-alignment`, it will **not** contain
`bb8a4d2`'s D3 lockfile fix. That is fine for EDR only if the EDR install
succeeds — the guard will tell us immediately, and nothing is published if it
fails. Long term the two projects should build from one reconciled ref.

## STOP
Nothing deployed. Awaiting owner approval.
