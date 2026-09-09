# P0-SEC · XDR RBAC bootstrap bypass (2026-09-09)

## Root cause
`backend/routers/xdr_rbac.py` · `require_permission()._dep`

```python
if _c_users() is None: return True                        # DB down -> ALLOW
ten, pid, pkd = _principal(request)                       # identity from HEADERS
if _c_users().count_documents({"tenant_id": ten}) == 0:   # tenant empty -> ALLOW
    return True
```
`_principal()` (`routers/xdr_ingest.py:67-74`) defaults an anonymous caller to
tenant `"default"` / principal `system@ingest`, and `deps.seed_admin()`
(`deps.py:373-379`) inserts admins with **no `tenant_id`**. The count was
therefore permanently 0 and every RBAC-gated route was open to unauthenticated
callers. Datastore failure also failed open.

## Fix
Identity now comes only from the verified JWT via
`Depends(_deps_current_user)`; client headers cannot establish identity;
`system@ingest` is unreachable externally; the tenant-empty bypass is deleted;
datastore unavailability returns **503**, never allow. Cross-tenant `admin`
role short-circuits (same rule as `deps.require_admin`); tenant-scoped
principals take their tenant from the **user record** and go through
`check_access`. First-admin bootstrap needs no RBAC path — `seed_admin()` runs
at startup and never traverses it.

## Invariant
> No request is authorized unless it carries a valid JWT resolving to a real
> user, and either that user is `role == "admin"` or `check_access(tenant from
> the user record, …)` allows it. Absent/invalid credentials, missing tenant
> scope, spoofed headers, or an unavailable authorization store all DENY.

## Behaviour change to be aware of
Tenant-scoped non-admin users (e.g. `analyst@nivx-live.com`) now receive
**403 `{"code":"ACCESS_DENIED","reason":"user-not-provisioned"}`** on
RBAC-gated XDR admin surfaces (collectors/secrets/api-keys/rule-studio) until
an RBAC role is assigned to them. Previously the bypass let them through.
`GET /api/incidents` is unaffected (different gate) — verified 200 for that
analyst.

## Status
- Code: fixed and tested in preview. `backend/tests/test_p0sec_rbac_fail_closed.py`
  **21/21 pass**; `tests/test_xdr_rbac.py` **14/14 pass** (single-process and
  under the default xdist runner: 35/35 combined).
- `tests/test_xdr_rbac.py` needed adapting because it authenticated by header
  and therefore depended on the bypass. Final root cause of the last failure:
  line 129 `client.get("/api/xdr/rbac/roles/role_builtin_platform_admin")`
  carried **no headers** — it now 403s, so `r2.json()["data"]` raised
  `KeyError: 'data'`. The suite's *first* call was already returning 200
  (`status=200` in the middleware log); the exception came from the second,
  unauthenticated call. **Pre-existing test debt exposed by the fix, not a
  defect in the fix.**
- **PRODUCTION CLOSED 2026-09-09.** Post-redeploy verification against
  `nivxray.nivxforge.com`: all five anonymous surfaces now **403 Not
  authenticated** (were 200/200/200/200/400), header spoofing
  (`X-Tenant-Id: default` + `X-Principal-Id: system@ingest`) also **403**,
  authenticated admin `GET /api/xdr/collectors` and `/api/incidents` both
  **200**, and every production data count unchanged against the pre-deploy
  baseline (incidents 0, cases 48, history 35, correlations 1, investigations
  3, EDR endpoints 1, collectors 0). Standard Redeploy; existing production
  MongoDB preserved.
- No collector enrolled, no telemetry seeded.
