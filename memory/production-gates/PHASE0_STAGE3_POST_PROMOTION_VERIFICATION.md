# PHASE 0 PROMOTION — STAGE 3 · POST-PROMOTION VERIFICATION (READ-ONLY)

Mode: **READ-ONLY**. Nothing deployed, changed, created or retried. Zero production DB writes.
No tenant, no token, no endpoint, no secret. Response authority untouched (**FAIL-CLOSED**).

RESULT: **PHASE 0 PROMOTION — STAGE 3: PASS**

## 1 · XDR — `xdr.nivxforge.com`

```
XDR PROJECT:                    nivxray-xdr-production
XDR PRODUCTION DEPLOYMENT:      commit 8f370c7 · Production / Ready / Current (owner-attested)
XDR SOURCE:                     8f370c7d  (contains Phase 0 bea8852b)
XDR BUILD:                      build-info built_at 2026-09-26T18:19:37Z   ← was 15:55:50Z
XDR MAIN BUNDLE:                assets/index-jibR6pJH.js                   ← was index-DWES00xC.js
XDR TELEMETRY FRESHNESS CHUNK:  assets/TelemetryFreshness-C5Y1RAEl.js      ← was TelemetryFreshness-Bn7VDqn2.js
XDR INVESTIGABILITY:            PRESENT (1 occurrence in the SERVED chunk)
XDR RAW_ONLY_NOT_INVESTIGABLE:  PRESENT (also NO_DELIVERY_TO_ASSESS present)
XDR OBJECT-OBJECT DEFECT:       REMOVED (0 occurrences of "object Object"; readable-error path shipped)
XDR API ORIGIN:                 https://nivxray.nivxforge.com  (1 ref in entry; 0 preview origins)
XDR PRODUCT SCOPE:              xdr  (build-info product_scope=xdr, cross_product_origins=0)
```

## 2 · EDR — `edr.nivxforge.com`

```
EDR PROJECT:                    nivxray-edr-production
EDR PRODUCTION DEPLOYMENT:      commit 8f370c7 · Production / Ready / Latest (owner-attested)
EDR SOURCE:                     8f370c7d  (contains Phase 0 bea8852b)
EDR BUILD:                      build-info built_at 2026-09-26T18:20:24Z   ← was 15:58:00Z
EDR MAIN BUNDLE:                assets/index-Jn2JDa9x.js                   ← was index-Dyygw0sM.js
EDR TELEMETRY FRESHNESS CHUNK:  assets/TelemetryFreshness-niZ7i_uq.js      ← was TelemetryFreshness-DntlSql7.js
EDR INVESTIGABILITY:            PRESENT (served chunk)
EDR RAW_ONLY_NOT_INVESTIGABLE:  PRESENT (also NO_DELIVERY_TO_ASSESS)
EDR OBJECT-OBJECT DEFECT:       REMOVED (0 occurrences)
EDR API ORIGIN:                 https://nivxray.nivxforge.com  (0 preview origins)
EDR PRODUCT SCOPE:              edr  (build-info product_scope=edr, cross_product_origins=0)
```

### Artifact-identity proof (not source inspection)
The **served** EDR `TelemetryFreshness-niZ7i_uq.js` has SHA-256 prefix `3d257c12a0ce53b9`,
**byte-identical** to the chunk produced by the locally emulated production build in the
Stage-3 pre-gate. Both entry bundles (`index-jibR6pJH.js`, `index-Jn2JDa9x.js`) and both
chunk names are Vite **content hashes** and match the pre-gate artifacts exactly — so what is
live is the same artifact the guard passed, not merely the same source. Cache status on the
first fetch was `x-vercel-cache: MISS`, `age: 0` — a genuinely new deployment, not an edge copy.

## 3 · Product-host isolation — verified live in a browser

| Probe | Result |
|---|---|
| `xdr.nivxforge.com/` | `307 → /xdr` |
| `edr.nivxforge.com/` | `307 → /edr` |
| `xdr.nivxforge.com/edr/overview` | **WRONG PRODUCT HOST** — "This deployment serves NivXRay XDR. /edr/overview belongs to NivXRay EDR… Nothing was loaded from the other product." |
| `edr.nivxforge.com/xdr/dashboard` | **WRONG PRODUCT HOST** — mirror-image refusal |
| `edr.nivxforge.com/edr` | `→ /login?returnTo=%2Fedr`, renders **NIVXRAY EDR** sign-in |
| Cross-product hostname references inside either served entry bundle | **0 / 0** |

`PRODUCT-HOST ISOLATION: ENFORCED` — both directions, artifact-level and runtime-level.

## 4 · Backend (unchanged by Stage 3)

```
BACKEND HEALTH:     PASS — GET https://nivxray.nivxforge.com/api/health → 200 {"status":"ok","service":"nivxray-api"}
BACKEND ROUTES:     862  (openapi sha 8c04168feebf43f0 — identical to the Stage 2 measurement)
RESPONSE AUTHORITY: FAIL-CLOSED — unchanged; `edr_plane/response.py` last modified in `901f5651`
                    (pre-Phase 0). NOT probed live, because any probe is itself a response action.
```

## 5 · Data-plane mutations caused by Stage 3

```
DB MIGRATIONS: 0        DB BACKFILLS: 0
ORGANIZATIONS CREATED: 0  TENANTS CREATED: 0  TOKENS CREATED: 0
ENDPOINTS ENROLLED: 0     RESPONSE ACTIONS: 0
SECRETS / ENV CHANGED: 0  BACKEND REPUBLISHED: NO   CODE CHANGED: 0
LEGACY NIVXRAY-XDR PROJECT TOUCHED: NO   (refuse-root-deployment.sh untouched)
NIVXMACHINES-WORKSPACE TOUCHED: NO
HUNT / FILES / NETWORK / FORENSICS / LIVE QUERY: untouched — still honestly N/I
ROLLBACK REQUIRED: NO     ROLLBACK PERFORMED: NO
```

## 6 · Truthfulness statement

Stage 3 proves the production consoles can **display** the Phase 0 investigability state and
that the `[object Object]` defect is gone from the artifacts actually served by both hostnames.
It does **not** prove Windows canonicalisation has executed. The Windows bridge remains:

```
PRODUCTION CAN NOW CANONICALIZE WINDOWS TELEMETRY:
PRESENT_IN_PUBLISHED_SOURCE_NOT_LIVE_PROVEN
```

Live proof requires the first authorised real Windows endpoint.

**Next:** NivX Machines production validation tenant bootstrap → one enrollment token → one
real Windows host (Sysmon configured first) → live canonicalisation proof → Device Trajectory /
Process Tree / Events / Detections / Findings inspection.
