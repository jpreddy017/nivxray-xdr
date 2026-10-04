# P0 · RESPONSE-EXECUTION TENANT ISOLATION — 2026-06-21

**Status: CLOSED · PROVEN.** Backend only, authorization only. No frontend
change, no Evidence Namespace Bridge work.
Proof: `scripts/p0_response_execution_tenant_isolation.py` → **21 PASS · 0
FAIL** (`test_reports/p0_response_tenant_isolation.txt`) ·
`tests/test_p0_response_execution_tenant_scope.py` +
`tests/test_xdr_response_evidence.py` → **23 passed in 0.6 s**
(`test_reports/p0_response_focused_tests.txt`). No broad regression run.

## ROOT CAUSE

`GET /api/xdr/incidents/{incident_id}/response-executions` queried
`xdr_response_evidence` by `{"invoker.context.incident_id": incident_id}`
**alone**. The only tenant predicate came from an **optional, client-supplied
`tenant_id` query parameter** — documented in the code as "defensive scoping…
never leaks records for other tenants", which was false: omitting the
parameter removed the predicate entirely. Any principal holding
`evidence.read` could read another customer's response executions (invoker
identity, action, parameters, canonical target, adapter result,
authorization block) by putting their own incident id in the path. The join
onto `xdr_response_executions` had the same optional predicate, so the
evidence/audit/timeline ref triple leaked with it.

The sibling `GET /api/xdr/response-evidence/{execution_id}` had the identical
defect keyed on an execution id: no principal, no tenant predicate unless the
caller volunteered one.

## AUTHORITATIVE TENANT RESOLUTION

One helper, `_apply_principal_tenant_scope()`, used by both reads:

    verified principal → resolve_tenant_scope(principal.email)
      · unauthorized        ⇒ predicate {"$in": []} — matches nothing
      · cross-tenant role   ⇒ ALL_TENANTS (unchanged authority)
      · everyone else       ⇒ {"tenant_id": {"$in": <own tenants>}}
    a client-presented `tenant_id` may only INTERSECT that set

…and, for the incident-keyed route, the incident itself is resolved through
**THE incident authority** (`routers.incidents.authorized_incident`) first, so
an incident the principal cannot address answers **404** and never discloses
that it exists. The same `resolve_tenant_scope` the incident plane uses — no
second tenancy model. The response now reports the **applied** scope
(`tenant_scope: ALL_TENANTS | PRINCIPAL_TENANTS`, `tenant_id` = the scope
actually used), never the value a caller sent.

## ROUTES INSPECTED

| route | verdict |
|---|---|
| `GET /api/xdr/incidents/{id}/response-executions` | **AFFECTED + FIXED** |
| `GET /api/xdr/response-evidence/{execution_id}` | **AFFECTED + FIXED** (identical root defect) |
| `POST /api/xdr/response-evidence` | **NOT FIXED — out of this pass's scope (a WRITE).** Reported: it stores `body.tenant_id`, i.e. the writer's own claimed tenant, gated only by `response.execute`. Same *class* of defect (client-supplied tenant) on the write path. Needs an owner decision; the Response Engine is the caller. |

No other route exists in this resource family (the router has exactly three),
and no other router reads `xdr_response_evidence` / `xdr_response_executions`.

## LIVE JWT MATRIX (21 PASS · 0 FAIL)

anonymous → **403** · tenant analyst without the grant → **403**, no
`execution_id` in the body · cross-tenant (both directions) → **403/404**, the
string `nivx-live` absent · `?tenant_id=`, `?customer=`, `?tenant=`,
`X-Tenant-Id`, `X-Principal-Id`, `X-Tenant`+`X-Customer-Id` → **denied, no
disclosure** · cross-tenant admin → **200 ALL_TENANTS** (unchanged) · a
requested tenant only **narrows** (admin + `?tenant_id=nivx-live` on a
`default` incident ⇒ `count 0`) · unknown execution id → **404** ·
valid-looking `exec_…`, `evt_…`, `tf_…` and `sysmon-1-…` ids cannot enumerate
another tenant's evidence (**404**, no `evidence_ref`).

**Honest limitation, stated:** no production tenant role in this deployment
holds `evidence.read` (the only role carrying it, `l2_investigator_copy`, is
assigned to nobody), so on the live edge a tenant analyst is refused by the
RBAC gate *before* the tenant authority is reached. The positive same-tenant
path and the decisive leak case are therefore proven against the real router
in pytest, not on the live edge.

## FOCUSED PYTEST RESULT

`tests/test_p0_response_execution_tenant_scope.py` — **13 passed**, driving
the REAL router with the REAL tenant + incident authorities (only the RBAC
permission gate is overridden, as the pre-existing harness does). **The
decisive case:** two evidence rows referencing the SAME `incident_id`, one per
tenant — the own-tenant principal receives exactly `["exec-own"]`,
`exec-foreign` appears nowhere in the response, and the joined ref triple is
the own-tenant one. Plus: anonymous refused · cross-tenant 404 without
disclosure · requested tenant can only narrow (`tenant_id: []`, `count 0`) ·
cross-tenant role unchanged (sees both) · execution detail of another tenant
404 while own tenant reads `ev-own` · a principal with no user record holds
**no** tenant (there is no default tenant).

`tests/test_xdr_response_evidence.py` — **10 passed** after a contract-honest
update: its harness presented **no principal at all**, which under the new
(correct) contract means "no tenant ⇒ nothing", so it now presents a
cross-tenant principal explicitly and seeds the incident ids it addresses.
One expectation was corrected rather than absorbed: an incident that cannot
be addressed now answers **404**, not an empty list — *"no executions"* and
*"not your incident"* are different answers.

## FILES CHANGED

- `backend/routers/xdr_response_evidence.py` — `_apply_principal_tenant_scope`
  + the incident authority on both reads; the applied scope is reported.
- `backend/tests/test_xdr_response_evidence.py` — harness principal + seeded
  incidents + the corrected 404 expectation.
- New: `backend/tests/test_p0_response_execution_tenant_scope.py` ·
  `scripts/p0_response_execution_tenant_isolation.py`.
- **No frontend change needed**: the one caller that sends `tenant_id`
  (`EvidenceFirstInvestigationWorkspace`) sends the incident's own tenant,
  which now merely narrows within the principal's resolved scope; no consumer
  reads the response's `tenant_id` field.

## RESIDUALS

1. **P1 (new, reported, not fixed): the WRITE path.**
   `POST /api/xdr/response-evidence` persists `body.tenant_id` — the caller's
   own claim — as the tenant of the evidence record. Every read is now scoped
   by that stored value, so a mis-declared write would land in the wrong
   tenant. Owner decision needed (the Response Engine is the caller).
2. **No tenant role holds `evidence.read`** in this deployment, so no real
   analyst can currently exercise this route at all. That is RBAC
   provisioning, not authorization logic — but it means the fix is unobserved
   in production use until a role grants it.
3. Evidence rows that carry **no** `tenant_id` are invisible to a non-admin
   principal (fail-closed). If legacy rows exist without a tenant, they are
   admin-only until backfilled — deliberately not rewritten here.
4. Unchanged and still open: the **Evidence Namespace Bridge** (P1-1), next in
   the sequence.
