# T-RISK-3 — READ-ONLY REACHABILITY & IMPACT ANALYSIS
`backend/routers/xdr_respond_boundary.py` · `user.get("tenant_id") or "default"`

Date: 2026-06 · Mode: **READ-ONLY. NO REPAIR APPLIED.**
Classification: **P0 · TENANT-ISOLATION BLOCKER — REACHABLE AND ALREADY MATERIALIZED**

---

## 1. The four call sites

| # | Line | Function | Route | Tenant use |
|---|------|----------|-------|-----------|
| 1 | 87  | `_permissions_of()` | all respond routes | RBAC lookup key for `xdr_user_roles` |
| 2 | 190 | `execution()` | `GET /api/xdr/respond/executions/{id}` | engine idempotency-key component (read) |
| 3 | 203 | `pending_approvals()` | `GET /api/xdr/respond/pending-approvals` | engine tenant filter (read) |
| 4 | 217 | `execute()` | `POST /api/xdr/respond/execute` | **tenant of record for the dispatched action (write)** |

## 2. Chain of custody

`caller → get_current_user (deps.py:282)` — decodes JWT, loads `db.users`
document. **`tenant_id` is NOT a required field of `users`.**

Measured in the live preview database:

```
users total                6
users with a tenant_id     2      (analyst@nivx-live → nivx-live,
                                   analyst@default.com → default)
users WITHOUT tenant_id    4      INCLUDING admin@nivxray.com
```

`seed_admin()` (deps.py:373) inserts the platform admin with
`email / password / role / must_change_password / created_at` — **no
`tenant_id`**. So for the only principal the owner actually signs in
with, `user.get("tenant_id")` is `None` at all four sites and the
fallback fires **on every request**.

## 3. The fallback is not a harmless placeholder

`"default"` is **a real customer in the authorized corpus**, not a
sentinel. `GET /api/xdr/scope/authorized` as `admin@nivxray.com`:

```
tenants[0] = { "customer": "default", "open_incidents": 683, "incidents": 683 }
```

So the fallback silently **names a specific existing tenant** — the
largest one — as the tenant of record for the response action.

## 4. Reachability of dispatch — CONFIRMED, NOT THEORETICAL

* `XDR_RESPONSE_SERVICE_URL=http://localhost:8056` is configured;
  supervisor program `xdr_response` is **RUNNING**; `/health` returns
  `status: ok`, `actions: 18`, `forwarder.state: connected`.
* The engine's `POST /api/respond/execute` (`routes/execute.py:15`)
  takes `tenant_id` as a **required client-supplied field** and performs
  **no independent tenant derivation**. `framework/executor.py:138`
  (`tenant = req["tenant_id"]`) writes it into the execution row, the
  idempotency key (`execution_store.key_of`) and the audit/evidence
  records. The boundary is therefore the *only* tenant authority on this
  path, and it is guessing.
* **Already materialized.** `GET /api/xdr/respond/pending-approvals` as
  `admin@nivxray.com` returns 5 rows, every one of them:

```
{ "execution_id": "p01-fail-…", "state": "WAITING_APPROVAL",
  "action_id": "endpoint.kill_process",
  "invoker": { "kind": "analyst", "id": "admin@nivxray.com" },
  "tenant_id": "default" }
```

Real `endpoint.kill_process` requests are parked in the engine store
attributed to the customer `default` **because of the fallback**, not
because anyone selected that customer.

## 5. Cross-tenant reachability — two distinct defects

**D1 · Mis-attribution of execution (sites 2, 3, 4).**
A cross-tenant/MDR principal investigating incident X belonging to
tenant `t-m365-phase1b` executes a response. The boundary overwrites
`payload["tenant_id"]` with `"default"`. The action is dispatched,
audited, keyed and evidence-forwarded **against the wrong customer**.
The analyst's own incident context (`INHERITED_FROM_INCIDENT`) is never
consulted — `execute()` does not read `incident_id` at all and does not
call `services.session_context.effective_scope`. Conversely, a
genuinely `default`-scoped analyst and the cross-tenant admin now share
an idempotency namespace, so one can collide with / read the other's
executions via site 2.

**D2 · Approval with no tenant authority at all (`/approve`, `/reject`).**
`approve()` (line 254) and `reject()` (line 279) forward **only the
execution_id and the session principal** — no tenant is sent, and the
engine's `routes/approvals.py` approve/reject path applies **no tenant
filter whatsoever** (only `pending-approvals` filters, and only when a
`tenant_id` query param is supplied). Any principal holding
`response.approve` can therefore approve or reject **any tenant's**
pending execution by id. `reject()` additionally performs **no
permission check at all** — it does not verify `RESPONSE_APPROVE`.
This is a tenant-isolation break in the approval position, and it is
independent of the `"default"` fallback.

## 6. Audit behaviour

The audit trail is *internally consistent and externally wrong*: the
approver/invoker identity is trustworthy (taken from the session, never
the body), but the tenant attached to it is a guess. An audit record
that confidently names the wrong customer is worse than a missing one.
`authorization_basis` is disclosed, `tenant_basis` is not.

## 7. Production-promotability

Every path under `POST /api/xdr/respond/execute`,
`POST /api/xdr/respond/approve/{id}`, `POST /api/xdr/respond/reject/{id}`,
`GET /api/xdr/respond/executions/{id}` and
`GET /api/xdr/respond/pending-approvals` is **NOT production-promotable**
until D1 and D2 are closed.

## 8. Minimal proposed repair — FOR OWNER AUTHORIZATION ONLY (NOT APPLIED)

1. **Delete the fallback.** Resolve the tenant through the existing
   A0.5 authority `services.session_context.effective_scope(email,
   incident_id=…)`. No new resolver.
2. **Bind execution to a single tenant.** `execute()` accepts the
   incident/tenant the analyst is actually in, and requires the
   resolved scope to be exactly one tenant
   (`EXPLICIT_REQUEST_TENANT`, `SINGLE_AUTHORIZED_TENANT` or
   `INHERITED_FROM_INCIDENT`). A cross-tenant principal with
   `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` must be **403
   `RESPONSE_TENANT_NOT_DETERMINED`** — response is a single-tenant act.
3. **RBAC key (site 1).** Use the resolved tenant; if unresolved, return
   the empty permission set with basis `tenant_not_resolved` so the
   existing 403 fires. Never look up permissions under `"default"`.
4. **Approval tenant check (D2).** Before forwarding approve/reject,
   read the execution via the engine's tenant-scoped lookup with the
   *resolved* tenant and refuse if it does not belong to it. Add the
   missing `RESPONSE_APPROVE` check to `reject()`.
5. **Disclose `tenant_basis`** on every respond response.

**Deliberately NOT proposed in this pass:** any change to who may
approve, the approval state machine, or the engine's lifecycle. The
repair is a tenant-authority repair only.

## 9. Regression requirements for that repair

* Admin with no `tenant_id` → `execute` returns 403
  `RESPONSE_TENANT_NOT_DETERMINED`; nothing dispatched
  (`dispatched/executing/executed/verified` all `false`).
* Same admin inside incident X → tenant == X's authoritative tenant.
* Analyst of tenant A approving an execution of tenant B → 403.
* `reject` without `response.approve` → 403.
* Tenant-scoped analyst happy path unchanged.
* The 5 existing `tenant_id: "default"` WAITING_APPROVAL rows must be
  re-classified, not silently re-attributed.

T-RISK-4 and T-RISK-5 remain fenced and were not inspected.
