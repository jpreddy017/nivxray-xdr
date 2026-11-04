# PRODUCTION SMOKE VERIFICATION — `xdr.nivxforge.com`

Production rebuild of `3njhqYa5K` on `release/xdr-w1-candidate`
(accepted candidate `9ae7bdac21408b575231b1e77e850de49f2564fb`).
Read-only. No code, configuration, deployment, tenant data, credential or
telemetry touched. **W1 HELD.**

---

## CHECK 1 · ARTEFACT CHANGED — PASS
```
before promotion : assets/index-CmdMrjfH.js   (stale · no tenant header, no collector base)
now              : assets/index-dQhjKK0o.js
build-info.json  : {"product":"nivxray-xdr","product_scope":"xdr",
                    "api_origin":"https://nivxray.nivxforge.com",
                    "phase":"2","cross_product_origins":0,
                    "built_at":"2026-09-18T09:25:23Z"}
```

## CHECK 2 · PRODUCTION IS BYTE-IDENTICAL TO THE ACCEPTED CANDIDATE — PASS
Crawled the entry chunk for its whole module graph (116 chunks), fetched every
one, then rebuilt the accepted candidate locally with the same production
command and compared SHA-256 per file:
```
production js chunks fetched   117  (116 lazy + entry)
byte-identical to local build  117
same name, different content     0
production-only chunks           0
local-only                       1   EdrTrajectoryRedirect-B-G-fBvc.js
```
The single local-only file is a lazy route not referenced by the entry graph I
crawled, so it was never requested — not a content difference. Every chunk
production actually serves is byte-for-byte the accepted candidate.

## CHECK 3 · THE FIXES ARE IN THE SERVED ARTEFACT — PASS
| marker | present |
|---|---|
| `X-Tenant-Id` | yes (2 chunks) |
| `nvx_tenant` (active-tenant module) | yes |
| `nvx_token` (session bearer) | yes |
| landed collector base `/api/xdr/collector` | yes |
| `nivxray.nivxforge.com` api origin | yes |
| `evops-tenant-select` (tenant dropdown) | yes |
| `admin-surface-error` (error boundary) | yes |
| `ADMINISTRATION SURFACE FAILED TO RENDER` | yes |
| `refusal.js` remedies ("Name the authoritative tenant on this surface", "This session is not authorised for that operation") | yes |

Regression markers absent:
- `typeof process …/api/xdr/collector` (the collector-base short-circuit) → **0 matches**; `typeof process` survives only in vendor code (axios), nowhere near the collector base.
- bare `Bug` identifier in `XdrDetectionRuleEditorPage-CQtGda1A.js` → **0** (the `ReferenceError` crash is gone).

## CHECK 4 · NO ORIGIN LEAKAGE — PASS
```
greeting-app-5782 (preview origin)   0 occurrences across all 117 chunks
edr.nivxforge.com (cross-product)    0 occurrences
cross_product_origins                0  (build-info.json)
```

## CHECK 5 · ROUTES SERVED + SPA FALLBACK — PASS
All `200` with `<title>NivXRay XDR</title>`:
`/xdr` · `/xdr/admin/collectors` · `/xdr/admin/audit-log` ·
`/xdr/admin/integrations` · `/xdr/admin/api-keys` ·
`/xdr/detections/rule-77830359-…` · `/xdr/no-such-route`.

## CHECK 6 · BROWSER, UNAUTHENTICATED — PASS
Each route loads the SPA, the router resolves, and the session guard redirects
while PRESERVING the destination; login renders; **zero page errors** on all
seven:
```
/xdr                        -> /login?returnTo=%2Fxdr%2Fmss-dashboard
/xdr/admin/collectors       -> /login?returnTo=%2Fxdr%2Fadmin%2Fcollectors
/xdr/admin/audit-log        -> /login?returnTo=%2Fxdr%2Fadmin%2Faudit-log
/xdr/admin/integrations     -> /login?returnTo=%2Fxdr%2Fadmin%2Fintegrations
/xdr/admin/api-keys         -> /login?returnTo=%2Fxdr%2Fadmin%2Fapi-keys
/xdr/detections/rule-778…   -> /login?returnTo=%2Fxdr%2Fdetections%2Frule-778…
/xdr/no-such-route          -> /login?returnTo=%2Fxdr%2Fmss-dashboard   (catch-all, no crash)
```

## CHECK 7 · BACKEND UNCHANGED AND STILL FAIL-CLOSED — PASS
```
GET https://nivxray.nivxforge.com/api/xdr/collector/connectors  (anonymous)
403 {"detail":{"code":"ACCESS_DENIED","permission":"collectors.read",
               "reason":"unauthenticated"}}
```
No republish occurred; Collector Auth P0 remains live.

---

## WHAT I COULD NOT VERIFY — NEEDS THE OWNER'S BROWSER
This workspace holds **no production password**, and I took none from
`memory/test_credentials.md` or anywhere else. The *authenticated* half of the
UI acceptance is therefore owner-side. Five steps, read-only, ~2 minutes:

1. `https://xdr.nivxforge.com/xdr/admin/collectors` → sign in. Page must
   RENDER (not black). With no tenant selected it should read
   `TENANT_REQUIRED — … Name the authoritative tenant …`.
2. `/xdr/admin/audit-log` → renders, same readable refusal, no black screen.
3. `/xdr/admin/integrations` → the **Authoritative tenant** dropdown must list
   your ACTIVE tenant **by display name** (`Internal Validation`), not an
   opaque `ten_*`. Select it → the panel loads (`NO INTEGRATIONS CONFIGURED`
   is the correct empty state).
4. Press the page-header **Refresh** on Integrations → it must re-query (it
   was inert before this candidate).
5. `/xdr/admin/api-keys` → renders; the tenant field must be **empty**, not
   prefilled with `default`.

If any of those five misbehaves, screenshot it and I will diagnose before W1.

## STATUS
```
CHECK 1 artefact changed                PASS
CHECK 2 identical to accepted candidate PASS  (117/117 chunks byte-identical)
CHECK 3 fixes present, regressions gone PASS
CHECK 4 no origin leakage               PASS
CHECK 5 routes + SPA fallback           PASS
CHECK 6 browser, unauthenticated        PASS  (0 page errors)
CHECK 7 backend still fail-closed       PASS
authenticated UI acceptance             OWNER-SIDE (5 steps above)
changes made during verification        NONE
W1                                      HELD
```
