# NIVXRAY XDR · TENANT / SCOPE AUTHORIZATION CONTRACT

Produced under the owner's *APPROVED WITH MULTITENANT / MDR AMENDMENT*
(directive item 18). **Contract document only — no code changed.**

Governing sentence:
> **Dual Console is one dimension. Multi-Tenant Operation is another.**
> Analyst/Admin separation must never be confused with tenant/customer
> separation.

Authorization chain, in order, every request:
```
Identity → Console Authorization → Authorized Tenants → Active Scope
        → Resource Scope → Permission → Action → (Approval) → Verification
```

---

## 1 · What already exists (authoritative, do not duplicate)

Discovery of the live code found a **real, server-side tenant authority**. It
must be consumed, never re-implemented in React.

| component | file | role |
|---|---|---|
`resolve_tenant_scope()` | `backend/services/dashboard_lenses.py` | resolves the principal's authorized tenant set |
`_scope()` | `backend/services/dashboard_lenses.py` | **the single authoritative queue predicate** — every tenant-scoped list must go through it |
`tenant_context()` | `backend/services/session_context.py` | returns `customers[]` + `active_customer{value, basis}`; *"Nothing here trusts the browser — the principal comes from the bearer token"* |
`list_customers()` | `backend/services/session_context.py` | the real customers the principal may see, derived from the case corpus, **not** from a tenant table |
`EDR_TENANT_BOUNDARY` | `backend/services/session_context.py` | owner-locked endpoint-ownership rule; unattributed observations stay `UNATTRIBUTED_LEGACY_OBSERVATION` and are released to cross-tenant roles only, **never assigned to a customer by inference** |
`require_permission(permission, *, resource_id_header)` | `backend/routers/xdr_rbac.py` | one enforcement factory; USER-JWT **or** MACHINE (`X-XDR-API-Key` + `X-Tenant-Id`), never both |
entry context | `session_context.py` | `DIRECT_EDR` vs `XDR_PIVOT` — on an XDR pivot the tenant is **INHERITED and may not be switched while the investigation context is held** |

### 1a · The six authoritative `active_customer.basis` values
```
EXPLICIT_REQUEST_TENANT              analyst asked for a specific tenant, and is authorized
INHERITED_FROM_INCIDENT              arrived via pivot; tenant is locked to the incident
SINGLE_AUTHORIZED_TENANT             principal has exactly one
MULTIPLE_AUTHORIZED_TENANTS          principal has many, none selected yet
CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER cross-tenant role, no single customer resolvable
NOT_AUTHORIZED                       no tenant scope at all
```
**These six bases are the Scope Navigator's state machine.** The current shell
collapses two of them into the static label `ALL CUSTOMERS` and the rest into
`◇ NOT RESOLVED` — that is the defect the owner flagged.

## 2 · Scope model (new, additive)

```
ScopeSelection  (what the UI REQUESTS — never authority)
  kind: "tenant" | "group" | "all_authorized"
  tenant_id?:  str          # kind == tenant
  group_id?:   str          # kind == group

EffectiveScope  (what the SERVER RESOLVES — the only thing enforced)
  tenant_ids:      [str]    # = requested ∩ authorized     ALWAYS an intersection
  requested:       ScopeSelection
  authorized_count: int
  basis:           one of §1a
  denied_tenant_ids: [str]  # requested but not authorized — reported, never silently dropped
  cross_tenant:    bool
  locked:          bool     # true when basis == INHERITED_FROM_INCIDENT
  lock_reason?:    str
```

### 2a · Hard rules
1. **Effective scope is always an intersection:**
   `effective = requested_scope ∩ authorized_scope`. Never a union, never the
   requested set, never the group's membership list.
2. **A frontend tenant selector is a request, not a grant.** Every tenant-scoped
   endpoint re-resolves scope from the token. `?tenant_id=` is an input to
   authorization, never a result of it.
3. **Tenant groups never confer access.** Group membership is an *operational
   grouping*. If a group contains 12 tenants and the principal is authorized
   for 9, the effective scope is 9 and `denied_tenant_ids` lists the 3 — the
   UI states *"9 of 12 tenants in this group are within your authorization"*.
4. **Visibility ≠ access.** A tenant appears in the Navigator only because
   `list_customers()` returned it. Nothing is listed because it exists in a
   tenant table.
5. **Pivot lock.** When `basis == INHERITED_FROM_INCIDENT`, the Scope Navigator
   renders **read-only** with the lock reason. The existing rule ("may not be
   switched while the investigation context is held") is a security property,
   not a UX preference.
6. **Unattributed data never becomes a customer's.** Observations without an
   owner stay `UNATTRIBUTED_LEGACY_OBSERVATION`, visible to cross-tenant roles
   only. Cross-tenant views must label them, never fold them into a customer row.
7. **Machine principals have no console and no scope navigator.**
   `console.*` permissions are user-principal only; a collector API key is
   already pinned to one `X-Tenant-Id`.
8. **Every cross-tenant row carries tenant provenance.** A row in a
   cross-tenant queue without a resolved `tenant_id` is a defect, not a blank
   cell.
9. **Absence is never zero.** A tenant with no telemetry is
   `EVIDENCE INCOMPLETE` / `COLLECTION GAP`, never `0 incidents · healthy`.

## 3 · Known risk found in the live code — must be closed before Wave A1
`backend/routers/xdr_rbac.py:332`
```python
ten = (req.headers.get("X-Tenant-Id")
       or getattr(req.state, "tenant_id", None) or "default")
```
An absent tenant silently falls back to the literal tenant `"default"`. In a
single-tenant deployment that is harmless; under the multitenant/MDR model it is
a **silent cross-tenant read**. Required change (auth/RBAC lane, not UX):
fail closed — resolve through `resolve_tenant_scope()` and reject the request
when no tenant can be established, rather than defaulting.
**Logged as T-RISK-1. It is a precondition of the multitenant amendment.**

## 4 · Console authorization (owner item 2)
```
console.soc.access      enter the Security Operations Console
console.admin.access    enter the Administration Console
```
- Delivered by the **authoritative auth/RBAC lane**, added to the permission
  catalogue in `xdr_rbac.py`, enforced by `require_permission` on every
  console-scoped endpoint. Not a frontend flag.
- The `console` token claim is a **destination only**. Presenting
  `console=admin` grants nothing; the permission decides.
- No implication in either direction: administrator ⇏ SOC response authority;
  analyst ⇏ administrative authority.
- **Knowing a URL grants nothing.** Test requirement, not aspiration: an
  analyst token must be **rejected by the admin API with 403**, and the
  assertion must be on the API response, not on UI visibility.
- Console switch re-reads `/api/xdr/rbac/me/effective` **and** re-resolves
  tenant scope, and is audited on both grant and denial.

## 5 · Required contract additions (do not exist today)
| # | contract | consumer | note |
|---|---|---|---|
| C1 | `GET /api/xdr/scope/authorized` → `{tenants[], groups[], favorites[], recent[], basis}` | Scope Navigator | server-resolved; must reuse `list_customers()` + `resolve_tenant_scope()` |
| C2 | `POST /api/xdr/scope/select` → `EffectiveScope` | Scope Navigator | returns the **intersection** and `denied_tenant_ids` |
| C3 | tenant-group CRUD + membership | Admin › Tenant Groups | grouping only; cannot grant access |
| C4 | every tenant-scoped list accepts `EffectiveScope` and returns `tenant_id` + `tenant_name` per row | cross-tenant queues | must route through `_scope()` |
| C5 | `GET /api/xdr/tenants/evidence-health` → per-tenant `{state, reason, last_event_at, sources[]}` | Tenant Evidence Health | states: `HEALTHY`, `HEALTHY · EVIDENCE INCOMPLETE`, `COLLECTION GAP`, `AUTHENTICATION FAILED`, `NOT CONFIGURED`; **`CONNECTED` only on real telemetry** |
| C6 | reverse effective-access query: *who can do X on tenant/resource Y* | Effective Access | forward `users/{id}/effective` exists; reverse does not |
| C7 | direct grants / direct restrictions / resource scopes | Assignments | **RBAC-1 prerequisite**; roles + groups exist today |
| C8 | response action must carry `tenant_id` + `resource_id` and be re-validated at approve **and** dispatch | Response | the UI selector must never be able to redirect an approved action to another customer |
| C9 | audit records for scope selection, console switch, and every denial | Audit | one audit authority |

## 6 · Response safety under multitenancy (owner item 10)
- The consequential-action dialog states **Customer · Resource · Reason ·
  Approval** explicitly, as the owner specified.
- The authoritative response service re-validates tenant + resource scope
  **independently at approve time and again at dispatch time**. Changing the UI
  scope after approval must be incapable of retargeting the action.
- `REQUESTED ≠ APPROVED ≠ DISPATCHED ≠ EXECUTED ≠ VERIFIED` is preserved
  verbatim; the response approval authority is **not** touched by UX work.

## 7 · Effective Access + Access Simulator (owner items 13–14)
- Both consume **the same resolver used for production authorization**
  (`resolve_tenant_scope` + `_resolve_user_permissions` + `require_permission`
  semantics). Building a second, "simulator-only" algorithm is a hard review
  failure — a simulator that can disagree with production is worse than none.
- Grant-chain answer shape:
```
response.execute      ALLOWED     Tenant: ACME Healthcare
  ↳ group   Incident Responders
    ↳ role  Incident Responder
      ↳ permission response.execute
        ↳ resource scope  tenant:acme-prod
  changed by  s.iqbal   2026-06-02 11:04Z   audit ref  AUD-77120
  effective now  YES

response.execute      DENIED      Tenant: Northwind Finance
  ↳ explicit restriction  deny response.execute on tenant:northwind-prod
  changed by  a.rahman  2026-05-27 09:12Z   audit ref  AUD-74880
```
- Simulator input: `User × Console × Tenant × Resource × Action → ALLOW/DENY +
  the chain above`. `POST /api/xdr/rbac/simulate` already exists server-side.

## 8 · Acceptance tests this contract requires (before Wave A1 ships)
1. Analyst token is **403** on every admin endpoint (API assertion, not UI).
2. Admin token without `console.soc.access` is **403** on SOC endpoints.
3. Requesting a tenant outside the authorized set returns the intersection and
   names the denial; it never returns the requested tenant's data.
4. A tenant group containing unauthorized tenants yields only the authorized
   subset, and `denied_tenant_ids` is populated.
5. With `basis == INHERITED_FROM_INCIDENT`, a scope-change request is refused.
6. Absent tenant header/scope **fails closed** (T-RISK-1), no `"default"`.
7. Every row of every cross-tenant list carries a resolved `tenant_id`.
8. A response approved for tenant A cannot be dispatched against tenant B after
   a UI scope change.
9. Access Simulator and production authorization agree on a randomised matrix
   of principal × tenant × action.
10. A tenant with no telemetry reports an evidence state, never `healthy`/`0`.
11. Scope selection, console switch and all denials appear in the audit trail.
12. Unattributed observations never appear under a customer row.

## STOP
Contract delivered. **Items C1–C9, T-RISK-1 and the `console.*` permissions are
auth/RBAC-lane work and are not self-authorized.** Wave A1/B1 UI may proceed
only against these contracts, and only for the surfaces the owner has approved.
