# PHASE 0 PROMOTION — STAGE 3 · CONSOLE PROMOTION · PRE-DEPLOYMENT GATE

Mode: **READ-ONLY** w.r.t. production. Local scoped builds only (`dist/` is git-ignored).
No Vercel deployment, no backend change, no DB write, no secret access.

RESULT: **STAGE 3: BLOCKED — pre-deployment gate PASS, promotion is an owner-only Vercel action.**

## 1 · Why the agent cannot promote

- No Vercel credentials exist in this pod (`env | grep -i vercel` → empty), no `vercel` CLI.
- Production promotion in these projects is a **manual dashboard action**, evidenced by the
  timing of the last promotion: push at 15:44 → Preview deployments 15:45 → **Production**
  deployments at **15:55 / 15:58** (`f7a25183`), i.e. ~10 minutes later, by hand.
- Pushing again would only produce Previews (proven in Stage 1: all four `8f370c7d`
  deployments are `Preview`).

## 2 · Pre-deployment gate — PASS

The production build was **emulated locally with the exact production script and guard**
(`scripts/vercel-build.sh` + `scripts/verify-production-build.js`), once per scope.

### XDR — `NIVX_PRODUCT_SCOPE=xdr`
```
build-info.json  {"product":"nivxray-xdr","product_scope":"xdr",
                  "api_origin":"https://nivxray.nivxforge.com","cross_product_origins":0}
guard            ok · no preview origin embedded (174 artifacts scanned)
                 ok · no edr.nivxforge.com dependency (this artifact is XDR only)
                 ok · API origin https://nivxray.nivxforge.com · 4 reference(s)
                 ok · no unauthorised origin outside the allow-list
                 ok · product scope declared "xdr" (/edr/* cannot render here)
                 ok · landed collector base .../api/xdr/collector resolves
                 XDR PRODUCTION BUILD GUARD · PASSED   (exit 0)
artifacts        index-jibR6pJH.js · TelemetryFreshness-C5Y1RAEl.js
Phase 0 marker   RAW_ONLY_NOT_INVESTIGABLE present in TelemetryFreshness-C5Y1RAEl.js
```

### EDR — `NIVX_PRODUCT_SCOPE=edr`
```
build-info.json  {"product":"nivxray-edr","product_scope":"edr",
                  "api_origin":"https://nivxray.nivxforge.com","cross_product_origins":0}
guard            ok · no preview origin embedded (174 artifacts scanned)
                 ok · no xdr.nivxforge.com dependency (this artifact is EDR only)
                 ok · API origin https://nivxray.nivxforge.com · 4 reference(s)
                 ok · no unauthorised origin outside the allow-list
                 ok · product scope declared "edr" (/xdr/* cannot render here)
                 EDR PRODUCTION BUILD GUARD · PASSED   (exit 0)
artifacts        index-Jn2JDa9x.js · TelemetryFreshness-niZ7i_uq.js
Phase 0 marker   RAW_ONLY_NOT_INVESTIGABLE + investigability present
`[object Object]` defect  GONE — source line 123 is now `readableError(error)`; the compiled
                          chunk carries the readable-error path ("unreachable" fallbacks)
```

| Gate item | XDR | EDR |
|---|---|---|
| Project | `nivxray-xdr-production` | `nivxray-edr-production` |
| Root Directory | `apps/nivxray-xdr` (selects the correct `vercel.json`) | same |
| Product scope | `xdr` | `edr` |
| Production API origin | `https://nivxray.nivxforge.com` | same |
| Preview origin embedded | **NO** (guard scanned 174 artifacts) | **NO** |
| Cross-product host dependency | **NONE** | **NONE** |
| Source contains `8f370c7d` / `bea8852b` | YES (Stage 1: 10/10 SHA-256 matches) | YES |
| `TelemetryFreshness.jsx` Phase 0 change | PRESENT | PRESENT |

Corroboration that the two projects are already configured this way: the **currently live**
production artifacts report `product_scope=xdr|edr` with `api_origin=https://nivxray.nivxforge.com`
(`/build-info.json` on each host), so only the source needs to move forward.

## 3 · Live production consoles BEFORE promotion (baseline for the after-diff)

```
xdr.nivxforge.com  build-info built_at 2026-09-26T15:55:50Z  entry index-DWES00xC.js
                   TelemetryFreshness-Bn7VDqn2.js → 0 × investigability, 0 × RAW_ONLY_NOT_INVESTIGABLE
edr.nivxforge.com  build-info built_at 2026-09-26T15:58:00Z  entry index-Dyygw0sM.js
                   TelemetryFreshness-DntlSql7.js → 0 × investigability, 0 × RAW_ONLY_NOT_INVESTIGABLE
```

## 4 · Owner action (two clicks, one per project)

For **each** of `nivxray-xdr-production` and `nivxray-edr-production`:
Vercel → the project → **Deployments** → the deployment built from commit **`8f370c7d`**
(created 17:35, status Ready) → **⋯ → Promote to Production**.
If you prefer a clean rebuild instead: **⋯ → Redeploy**, target **Production**, and
**uncheck "Use existing build cache"**.

Do **not** touch the legacy `nivxray-xdr` project (its root-deployment refusal is deliberate)
and do **not** touch `nivxmachines-workspace`.

## 5 · What I will verify the moment you confirm both are promoted (read-only)

Per host: production alias serves the new deployment; deployment id; deployed commit;
`build-info.json` `built_at` + `product_scope` + `api_origin`; served entry bundle; served
`TelemetryFreshness-*.js` chunk **fetched from the hostname** (not from source) and grepped
for `investigability` / `RAW_ONLY_NOT_INVESTIGABLE`; `[object Object]` path absent; zero
preview origin; product-host isolation (`xdr.…` → XDR only, `edr.…` → EDR only); backend
`/api/health` 200 and 862 routes; response authority still FAIL-CLOSED; and all data-plane
counters at zero.

## 6 · Counters for this stage

```
VERCEL DEPLOYMENTS BY AGENT: 0   LEGACY nivxray-xdr TOUCHED: NO   WORKSPACE TOUCHED: NO
refuse-root-deployment.sh MODIFIED: NO
BACKEND CHANGED: NO   EMERGENT REPUBLISH: NO   DB MIGRATIONS: 0   BACKFILLS: 0
ORGANIZATIONS: 0   TENANTS: 0   TOKENS: 0   ENDPOINTS: 0   RESPONSE ACTIONS: 0
SECRETS / ENV CHANGED: 0   RESPONSE AUTHORITY: FAIL-CLOSED
HUNT / FILES / NETWORK / FORENSICS / LIVE QUERY: untouched — still honestly N/I, not cosmetically enabled
CODE CHANGED: 0
```

**Truthfulness rule honoured:** Stage 3 will only prove the consoles can **display** the
Phase 0 investigability state. The Windows bridge stays
`PRESENT_IN_PUBLISHED_SOURCE_NOT_LIVE_PROVEN` until the first authorised real Windows endpoint
delivers telemetry.
