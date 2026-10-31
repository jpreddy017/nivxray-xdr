# PREVIEW ENVIRONMENTS — Stable demonstration URLs, branch rules, alias procedure

- **Status:** BINDING for all future Emergent sessions doing UI/UX work on EDR, XDR or Workspace.
- **Last updated:** 2026-10-31
- **Authority:** ChatGPT coordination, authorized by Janardhan.
- **Nature:** engineering handoff documentation. **Not product telemetry.** No database record was created, altered or migrated to record any of this.

---

## 1 · Stable demonstration URLs — use these, not the Emergent dev origin

| Product | **Stable demonstration URL** | Source root | Product scope |
|---|---|---|---|
| **NivXForge EDR** | `https://nivxforge-edr-preview.vercel.app` | `apps/nivxray-xdr` | `edr` |
| **NivXRay XDR** | `https://nivxray-xdr-preview.vercel.app` | `apps/nivxray-xdr` | `xdr` |
| **NivXMachines Workspace** | `https://nivxray-workspace-preview.vercel.app` | `frontend` | `workspace` |

`https://greeting-app-5782.preview.emergentagent.com` remains a **developer convenience only**. It is the shared Emergent dev origin with no product scope set, so it renders the unscoped/combined build. **Never present it as the URL for any product.**

All three URLs sit behind **Vercel Authentication**. Unauthenticated fetches legitimately return `302 → vercel.com/sso-api`; an authenticated Vercel fetch returns `200`. These are consistent, not contradictory. **Keep Vercel protection enabled** — do not disable it to make a check pass.

---

## 2 · Verified state (2026-10-31)

Commits verified read-only against `jpreddy017/nivxray-xdr`; each is confirmed to be the **head of its designated validation branch**.

| Product | Validation branch | Commit | Verified |
|---|---|---|---|
| EDR | `validation/edr-preview-backend-2026-10-31` | `f22b74aa9c676e84997c0ff339a6fd6789dd7427` | branch head, 2026-10-31 08:29:52Z |
| XDR | `validation/xdr-preview-backend-2026-10-31` | `7ed7c03bc5f58b880b5f505475ba5399ebfd0f89` | branch head, 2026-10-31 09:03:46Z — *"build(xdr): restrict nonproduction API override to designated preview…"* |
| Workspace | `validation/workspace-preview-backend-2026-10-31` | `98713f705c07022cac942585bc1a64bd0bed4a40` | branch head, 2026-10-31 09:05:08Z — *"build(workspace): enable narrowly gated nonproduction preview backend"* |

Compiled artifact metadata (`build-info.json` at each alias, confirmed by ChatGPT via authorized Vercel fetch): all three now declare `integration_preview=1` and `api_origin=https://greeting-app-5782.preview.emergentagent.com`, with `product_scope` of `edr`, `xdr` and `workspace` respectively. Boundary tests passed: **EDR 13, XDR 22, Workspace 10**.

Deployment IDs are held by the Vercel owner and are deliberately **not recorded here**.

---

## 3 · Current limitations — state these plainly, never overstate

1. **Frontend-only separation.** All three aliases are distinct **frontend** deployments that **share one non-production backend and one database** (`greeting-app-5782.preview.emergentagent.com`, local Mongo, `DB_NAME=test_database`). Distinct URLs do **not** prove operational or architectural isolation.
2. **No independent runtimes or databases exist yet.** Full per-product runtime/data isolation is unfinished.
3. **No database migration or addition occurred**, and **no production deployment occurred**.
4. **Certification status differs per product:**
   - **EDR** — read-only functional check passed (paged trajectory: 200 → 400 cumulative, 0 overlap, tenant-scoped).
   - **XDR** — browser login succeeded and Control Center loaded preview incident/customer data (user-confirmed). A lazy stylesheet initially failed to load; refreshing protected deployment access restored rendering. **This is not full workflow certification.**
   - **Workspace** — authenticated workflow and browser checks **remain pending**.
5. **Aliases are pinned manually to specific deployments.** Editing `/app`, or pushing a different branch, does **NOT** refresh any alias.

---

## 4 · Where to implement UI/UX

| Work | Directory | Notes |
|---|---|---|
| EDR and XDR | `apps/nivxray-xdr` | One Root Directory, one build script, **two scoped artifacts**. The product comes from `NIVX_PRODUCT_SCOPE` / `REACT_APP_PRODUCT_SCOPE`. Same source ≠ identical artifacts. |
| Workspace | `frontend` | Separate CRA/craco tree with its own `vercel.json` and `scripts/vercel-build.sh`. |

`frontend/src/nivxforge` is a **stale, unserved copy** of the EDR console. The served EDR/XDR console is `apps/nivxray-xdr/src/nivxforge`. Do not edit the stale copy.

**Always preserve unrelated changes.** Never reset `/app` and never overwrite dirty files outside the change set.

---

## 5 · Build rules that must not be weakened

- Product scope is **required**, not cosmetic. `ProductScopeGuard` + `productScope.js` are the only thing preventing one product rendering on the other's hostname.
- The non-production API override is **narrowly gated** and must stay that way: it requires `VERCEL_ENV=preview`, the matching product scope, the **designated validation branch**, `NIVX_CROSS_PRODUCT_ORIGINS=0`, and the explicit integration flag. Anything else is a hard build failure.
- `verify-production-build.js` inspects the **compiled `dist/`**, never the source `.env`. **Keep production build guards enabled.**
- Landing route comes from `HOME_PATH = /${PRODUCT_SCOPE}` in-app, not from the Vercel host redirect, so scoped builds land correctly on `*.vercel.app` aliases too.

---

## 6 · Alias update procedure (ordered — do not skip or reorder)

1. Agree the exact candidate commit with the Vercel owner.
2. Land it on the **appropriate designated validation branch** for that product.
3. Confirm the deployment reaches **READY**.
4. Verify the **compiled** API origin and product metadata in `build-info.json` at the deployment.
5. Verify **authenticated product behaviour** in the browser.
6. **Only then** repoint that product's stable alias to the verified deployment.

**Hard rule:** never tell Janardhan that a URL shows new work until the deployment **and** commit behind that alias have been verified. An alias may still be serving an older deployment.

---

## 7 · Division of work

- **ChatGPT owns all Vercel-side writes** — projects, environment variables, deployments, alias repointing — and browser verification. **Coordinate before any duplicate mutation.**
- **Emergent (E1) owns** the backend/preview runtime, backend code, and read-only verification of source, API, auth, CORS and data environment.
- Emergent must **not** disable Vercel protection, republish production, or mutate production data.

---

## 8 · Emergent preview backend — verified reference

| Property | Value |
|---|---|
| Identity | `/api/` → `{"service":"NivXRay"}`; `/api/health` → `nivxray-api`; OpenAPI *NivXRay API 1.0.0-rc*, 875 paths |
| Database | local Mongo, `DB_NAME=test_database`, 176 collections |
| Scale | 369,927 shadow observations · 390,891 raw events · 610 endpoints · 159 tenants |
| Distinct from production | yes — reports 213,868 MB free vs production's two replica values (74,605 / 94,471 MB) |
| Auth | JWT bearer + `X-Tenant-Id`; no token → 403, bad token → 401, platform principal without tenant → `TENANT_REQUIRED` fail-closed |
| CORS | `Access-Control-Allow-Origin: *`, no credentials; allows `authorization, x-tenant-id, content-type`; `max-age 600`. **Admits all three alias origins — no CORS change required.** |

Production backend (`nivxray.nivxforge.com`, deployment `greeting-app-5782`) remains **untouched**; EDR trajectory rollout remains on **HOLD**.
