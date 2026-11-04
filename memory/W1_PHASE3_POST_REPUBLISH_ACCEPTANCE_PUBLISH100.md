# PHASE 2 · PRODUCTION ACCEPTANCE — PUBLISH 100 / BUILD `e2d8f54`

Target `https://nivxray.nivxforge.com` · verified 2026-09-17 (UTC)
Live build `e2d8f54` (publish 100) · rollback target `8e473e4` (publish 99) ·
older baseline `5567f46` (publish 98).
Verification only. No production object created. No credential used except
where explicitly noted as owner-side.

## REPUBLISH: **SUCCESS**

## A · HEALTH
| gate | expected | actual |
|---|---|---|
| GET /api/ | 200 | **200** `{"service":"NivXRay","status":"ok"}` |
| GET /api/health | 200 | **200** `{"status":"ok","service":"nivxray-api"}` |
| GET /api/zzz-not-a-route-12345 | 404 | **404** |
| GET / (Workspace CRA) | 200 html | **200** `text/html` |

## B · 795-PATH CONTRACT: **PASS**
paths **790 → 795**. All five tenancy paths PRESENT:
`/api/xdr/organizations` · `/api/xdr/organizations/{org_id}/state` ·
`/api/xdr/tenants` · `/api/xdr/tenants/{tenant_id}` ·
`/api/xdr/tenants/{tenant_id}/state`.
`CanonicalEnvelope.declared_source` PRESENT · `TelemetryReceipt.routing_blocked`
PRESENT · 14 `/api/v2/security-state/*` operations present.

### Build-identity proof (stronger than a path count)
Production OpenAPI compared to the OpenAPI generated from the accepted
candidate in this pod: `candidate_only=[]`, `prod_only=[]`, path-object hash
**identical**, schema name sets equal, **0 schema bodies differing**.
⇒ the deployed build is the accepted code, so B3/B4/B5/B6, D14, D15, DCR-1 and
the W1 Sysmon DSM changes are all present in production.

## C · FAIL-CLOSED (anonymous, no credential used)
| gate | expected | actual |
|---|---|---|
| GET /api/xdr/organizations | 403 | **403** `ACCESS_DENIED` |
| POST /api/xdr/tenants | 403 | **403** `tenants.manage / unauthenticated` |
| GET /api/xdr/tenants | 403 | **403** |
| GET /api/v2/security-state/streaming/status | 403 | **403** |
| GET /api/v2/security-state/{case}?tenant_id=… | 403 | **403** |
| POST /api/v2/security-state/evaluate | 403 | **403** `incidents.read / unauthenticated` |
| POST /api/xdr/ingest/telemetry (no credential) | 403 | **403** `collectors.enroll / unauthenticated` |
| POST /api/xdr/ingest/telemetry (unknown `nvx_` key) | 401 | **401** `unknown-api-key` |
| GET /api/xdr/collectors/sources/catalog | 403 | **403** |
| GET /api/xdr/ingest/routing/summary | 403 | **403** |
| GET /api/auth/me | fail closed | **403** `Not authenticated` |
| POST /api/auth/login (nonexistent account) | reject | **401** `Invalid credentials` |

**B6 is proven live**: the security-state plane answered **200 anonymously
before this republish** and answers **403 unauthenticated now**.

## D · D14 / D15 / W1 CONTRACT
- D15: `declared_source` + `routing_blocked` in the live contract; all four
  routing/catalog endpoints present and anonymous-denied.
- D14 and the `microsoft-sysmon` source contract are code-level (not
  anonymously observable) and are established by the build-identity proof in
  §B plus the pre-deploy gate run on this exact code
  (**341 passed / 15 skipped**, single pre-existing stale EDR test).
- W1: no Windows telemetry has been transmitted, accepted or evidenced.
  `_COLLECTED_PRODUCTS` remains `{"linux"}`. **W1 STILL PAUSED.**

## E · AUTO-SEED = NONE
`server.py` and `deps.py` contain **no** reference to `tenant_registry`,
`create_organization`, `create_tenant` or `adopt_legacy` — grep returns
nothing. There is no startup hook, no migration and no backfill that can
create tenancy, so a deployment cannot have seeded an organization or tenant.
No existing `tenant_id` value is read or rewritten by any code path in this
build.

## F · ENFORCEMENT = OFF
`NIVX_TENANT_REGISTRY_ENFORCE` is absent from the repository `.env` and was not
added to production Secrets; `enforcing()` is read per call and defaults to
`False`. **This cannot be proven anonymously** — no unauthenticated endpoint
reports it. One owner-side authenticated read closes both §E and §F:

```powershell
$H = @{ Authorization = "Bearer $tok"; 'X-Tenant-Id' = 'acceptance-probe' }
Invoke-RestMethod -Uri 'https://nivxray.nivxforge.com/api/xdr/tenants' -Headers $H
# expected:  count = 0   enforcing = false
```
`count: 0` = nothing was auto-seeded · `enforcing: false` = the flag is off.
A GET creates nothing, and the probe header value is never persisted.

## G · FRONTEND / API COMPATIBILITY
- Root `/` serves the Workspace CRA (200, `text/html`); the Vercel SPAs
  (`xdr.nivxforge.com`, `edr.nivxforge.com`) were untouched by this republish.
- Both UI API clients already attach `Authorization: Bearer`
  (`frontend/src/lib/api.js:130`, `apps/nivxray-xdr/src/lib/api.js:29`), so an
  authenticated admin session keeps working against the now-authenticated
  security-state plane.
- **Known follow-up (not authorized, not performed):** the Vite investigation
  page hardcodes `tenant_id=default`
  (`XdrInvestigationWorkspacePage.jsx:179`) and the Workspace tab passes a
  `tenantId` (`SecurityStateTab.jsx:48-54`). For a cross-tenant admin these
  still return 200; for a tenant-scoped user naming another tenant they now
  return 403 — which is the B6 fix working. Once the real `ten_*` exists, the
  hardcoded `default` must be replaced with the selected tenant.

## REMAINING BLOCKER
One: the §F/§E authenticated confirmation read, which only the owner can run
(this workspace holds no production credential). Everything else passed.

## STATUS
```
REPUBLISH SUCCESS
PRODUCTION BUILD ID   e2d8f54  (publish 100)
ROLLBACK BUILD ID     8e473e4  (publish 99)
795-PATH CONTRACT     PASS
TENANT REGISTRY       PRESENT (routes live, collections empty)
ENFORCEMENT = OFF     asserted by absence; owner read pending
AUTO-SEED = NONE      PROVEN (no startup/migration path exists)
B3 / B4 / B5 / B6     PRESENT IN PRODUCTION (build-identity proof)
D14 / D15             INTACT
W1                    STILL PAUSED
NOT BOOTSTRAPPED
```
Rollback to `8e473e4` is NOT recommended. STOP for owner review before
production tenant bootstrap.
