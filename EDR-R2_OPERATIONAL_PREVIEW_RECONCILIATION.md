# EDR-R2 — Operational Preview Reconciliation (EDR / XDR / Workspace)

- **Date:** 2026-10-31
- **Scope:** read-only inspection of served config and source. No production publish, no production mutation, no auth weakening, no secret or telemetry disclosed.
- **Result:** **PARTIAL** — product scoping, backend selection and the EDR integration gate are VERIFIED from source and from the preview backend. Vercel-side project/deployment/commit bindings are **BLOCKED** (aliases sit behind Vercel Authentication; no Vercel token available; the IDs supplied in chat arrived masked by the secret filter).

---

## 1 · Reconciliation of the two reports

Both earlier statements were correct about different things, and the conflict was mine to resolve:

- My finding — *"one shared preview URL"* — described the **Emergent shared dev origin** `greeting-app-5782.preview.emergentagent.com`, which serves XDR and EDR from one Vite dev server with no product scope set. That remains true **as a development environment**, and is no longer offered as the official preview URL for any product.
- Codex's finding — three distinct Vercel aliases — describes **separate Vercel projects with separate artifacts**. Also true.

These are different layers. **Distinct frontend aliases do not imply runtime or data isolation**, and that distinction is the core of this report: the three aliases are separate *artifacts*, but they do **not** all reach separate *backends*, and none of them has a separate database.

---

## 2 · Evidence matrix

| | **NivXForge EDR** | **NivXRay XDR** | **NivXMachines Workspace** |
|---|---|---|---|
| **Frontend URL** | `nivxforge-edr-preview.vercel.app` | `nivxray-xdr-preview.vercel.app` | `nivxray-workspace-preview.vercel.app` |
| **Reachability (unauth)** | **302 → `vercel.com/sso-api`** | **302 → `vercel.com/sso-api`** | **302 → `vercel.com/sso-api`** |
| **Project / deployment** | **BLOCKED** (IDs masked in transit; no token) | **BLOCKED** | **BLOCKED** |
| **Commit** | `f22b74aa` **VERIFIED to exist** — `jpreddy017/nivxray-xdr`, head of `validation/edr-preview-backend-2026-10-31`, 2026-10-31 08:29:52Z. Binding to the deployment is **UNVERIFIED** | **BLOCKED** | **BLOCKED** |
| **Effective backend** | `greeting-app-5782.preview.emergentagent.com` — **CONSISTENT** with source: reachable only through the gated integration path (§3) | **production `nivxray.nivxforge.com`** — this is the **source default** (`XDR_PROD_API_ORIGIN:-https://nivxray.nivxforge.com`), and the integration override **cannot apply to XDR** (§3). Codex's observation is confirmed as structural, not a misconfiguration | **UNVERIFIED** — not produced by this repo's build script at all (§4) |
| **DB environment** | preview Mongo, local, `DB_NAME=test_database` | **production Atlas `greeting-app-5782-test_database`** | **UNVERIFIED** |
| **Auth** | JWT bearer + `X-Tenant-Id`; platform principal **fails closed** without a tenant (`TENANT_REQUIRED`) — verified live | same backend contract, against production data | **UNVERIFIED** |
| **CORS** | preview backend returns `Access-Control-Allow-Origin: *`, no `Allow-Credentials`; **preflight 200 verified** from this exact origin | preflight 200 verified | preflight 200 verified |
| **Correct landing route** | `/edr` — from `HOME_PATH = /${PRODUCT_SCOPE}` in-app, **not** the Vercel host redirect | `/xdr` | n/a |
| **Product boundary** | `REACT_APP_PRODUCT_SCOPE=edr` + `ProductScopeGuard`; `/xdr/*` is foreign and blocked | scope `xdr`; `/edr/*` foreign | separate deployment by design |
| **Read-only functional check** | **PASS** — 200 → 400 cumulative events, 0 overlap, tenant `default` only | **not run** — would read production data | **not run** |
| **Blocker** | deployment binding unverified | **preview alias reads production data** | backend, DB and identity all unverified |

---

## 3 · Why EDR reaches preview and XDR does not — verified from source

`apps/nivxray-xdr/scripts/vercel-build.sh` serves **both** scoped projects from one Root Directory. The API origin defaults to production:

```
API_ORIGIN="${XDR_PROD_API_ORIGIN:-https://nivxray.nivxforge.com}"
```

Commit `f22b74aa` adds a **deliberately narrow** override. The preview backend is substituted only when **all five** conditions hold simultaneously:

```
NIVX_EDR_INTEGRATION_PREVIEW=1
VERCEL_ENV              == preview
NIVX_PRODUCT_SCOPE      == edr
VERCEL_GIT_COMMIT_REF   == validation/edr-preview-backend-2026-10-31
NIVX_CROSS_PRODUCT_ORIGINS == 0
```

Anything else is a **hard build failure**, not a silent fallback. So the EDR alias pointing at the Emergent preview backend is *exactly* the designed behaviour, and **XDR structurally cannot** be pointed there: `NIVX_PRODUCT_SCOPE=xdr` is an explicit reject case.

I executed the new boundary test (`scripts/test-integration-build.cjs`) locally: **PASS, 13/13 cases**, including *production rejects preview*, *xdr rejects flag*, *wrong branch rejects flag*, *foreign preview rejected* and *suffix impersonation rejected* (`…preview.emergentagent.com.evil.com`).

The artifact also self-declares provenance in `dist/build-info.json` (`product`, `product_scope`, `api_origin`, `integration_preview`, `cross_product_origins`, `built_at`), and `verify-production-build.js` inspects the **compiled `dist/`**, never the source `.env`.

### Same source ≠ identical artifacts

Confirmed, and not asserted otherwise anywhere in this report: one Root Directory and one build script produce **two differently-scoped artifacts**, differing in `REACT_APP_PRODUCT_SCOPE`, `REACT_APP_NIVXRAY_API_URL` and `build-info.json`. They are separate Vercel projects and **cannot be promoted to production simultaneously**.

---

## 4 · Workspace is not in this codebase

`vercel-build.sh` accepts **only** `xdr` or `edr` and fatals on anything else, so it cannot have produced a Workspace artifact. `productOrigins.js` states it directly: Workspace *"is ALWAYS a separate deployment, never in this bundle"*, and with no URL configured its control must read **NOT CONFIGURED** rather than navigate. Its backend, database and auth are therefore **UNVERIFIED** from here.

---

## 5 · Landing-route correction

The host-conditional redirects in `apps/nivxray-xdr/vercel.json` match only `edr.nivxforge.com` / `xdr.nivxforge.com`, so they do **not** fire on a `*.vercel.app` alias. That does **not** break the alias: `App.jsx:225` routes `/` through `<Navigate to={HOME_PATH}>`, and `HOME_PATH` derives from the **build-time scope**, not the hostname. A correctly scoped EDR build therefore lands on `/edr` on any host. **No redirect change is required.**

---

## 6 · Source head reconciliation

| Ref | Status |
|---|---|
| `3bbc5c89` — staged in this workspace | **3 commits behind** `73e2bfea` |
| `73e2bfea` — head of `repair/edr-trajectory-navigation-2026-10-31` | VERIFIED. Adds on-demand loading + device-selection work across `DeviceTrajectoryPage.jsx`, `amp/Activity.jsx`, `amp/Grid.jsx`, `amp/TrajectoryPage.jsx` + 3 new tests |
| `f22b74aa` — head of `validation/edr-preview-backend-2026-10-31` | VERIFIED. **DIVERGED from `73e2bfea`: 2 ahead, 1 behind** — not a descendant |
| `5e7d1528` — "independent" head | **NOT FOUND** in either repository |

Two consequences: the EDR preview artifact is built from a **branch that diverges from the repair branch**, so validating one does not validate the other; and **the validation I completed earlier was against `3bbc5c89`**, which is now three commits stale.

`nivxforgeedr/nivxforge-edr` returns **404 even with the workspace token**. Per your instruction this is recorded as an **access limitation, not evidence of absence**, and I did **not** broaden token permissions.

---

## 7 · Required changes — precise

**Within existing authorization (preview-only, safe):**
1. **Nothing is needed for CORS.** Verified: preflight returns 200 with `Access-Control-Allow-Origin: *` and no credentials, from all three alias origins. Bearer-token auth works cross-origin unchanged. *(Separately noted: wildcard CORS on the preview backend is broad, but tightening it is a change, not a fix, and is out of scope here.)*
2. **Nothing is needed for the landing route** (§5).

**Requires an owner decision — cannot be done from here:**
3. **XDR preview reads production data.** This is the most consequential finding. Either accept it explicitly as a read-only production-data preview, or extend the integration gate to a second designated XDR validation branch — which means amending `vercel-build.sh` and `verify-production-build.js`, since `scope=xdr` is currently a hard reject. **I have not done this**: it would relax a deliberate production-data boundary.
4. **Disable Vercel Authentication on the three aliases**, or supply a Vercel token, otherwise no functional verification of the served artifacts is possible.
5. **Confirm the Workspace project's backend and database** before it is called an operational preview.
6. **Decide the authoritative EDR head** — `73e2bfea` (repair) or `f22b74aa` (preview-backend validation) — and reconcile the divergence before any promotion.

---

## 8 · Blockers

| # | Blocker | Severity |
|---|---|---|
| B-1 | Vercel Authentication returns 302 unauthenticated; no token → served bundle, `build-info.json` and per-project env **names** unverifiable | HIGH |
| B-2 | Project/deployment IDs arrived **masked**; alias→project→deployment→commit chain unverified | HIGH |
| B-3 | **XDR preview alias is wired to the production backend and production Atlas database** | HIGH |
| B-4 | Workspace backend/DB/auth entirely unverified | MEDIUM |
| B-5 | `f22b74aa` and `73e2bfea` have diverged; `5e7d1528` not found; staged workspace is 3 behind | MEDIUM |
| B-6 | `nivxforgeedr/nivxforge-edr` inaccessible — access limitation, not absence | MEDIUM |
| B-7 | No alias has an isolated database; "distinct preview" is currently **frontend-only** for XDR and unverified for Workspace | HIGH |

---

*Read-only. Production untouched. Rollout remains on HOLD.*
