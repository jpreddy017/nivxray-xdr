# P0 TENANT AUTHORITY · FIX 6A — vendor/MSSP multi-tenant authority
## INSPECTION + MINIMUM CONTRACT (design only · no code changed)

Owner-approved 2026-06. Fix 6A is inspection and contract only. No authority
code, role semantics, membership, grant, database, frontend, switch API or
audit persistence was changed. The live zero-tenant cell stays
**UNPROVEN LIVE / PREREQUISITE MISSING** and no credential was created.

---

## CURRENT_AUTHORITY_MODEL

Two separate planes exist today and only the first one decides tenancy:

```
TENANCY (who may see which customer)
  users.role  ──► services/dashboard_lenses.resolve_tenant_scope()
                    role ∈ _CROSS_TENANT_ROLES  ──► all_tenants: True
                    else                        ──► tenant_ids: users.tenant_ids[] | [users.tenant_id]
                    ↓
  services/session_context.authorize_requested_tenant()   AUTHORISATION
                    ↓
  services/tenant_registry.authoritative_required()       AUTHORITY (Fix 5A)
                    ↓
  routers/edr_tenancy.edr_tenant()  → request.state.effective_tenant_id

RBAC (which operations, INSIDE one tenant)
  xdr_users / xdr_user_roles / xdr_groups / xdr_access_grants
    ──► services/access_authority.resolve() ──► effective_permissions
    ──► routers/xdr_rbac.require_permission("<perm>")
```

The RBAC plane is keyed `(tenant_id, user_id)` — it answers *what may you do
in this tenant*, never *which tenants are yours*.

## CURRENT_PRINCIPAL_MODEL

- Auth principal: `users` collection (bearer token → `deps.get_current_user`),
  fields `email`, `role`, `tenant_id`, `tenant_ids[]`.
  Live: **76 users — 72 `analyst`, 3 `admin`, 1 `soc_manager`; 68 carry
  `tenant_id`, exactly 1 carries `tenant_ids[]`.**
- RBAC principal: `xdr_users` (19 rows, tenant-scoped) + `xdr_user_roles`
  (11) + `xdr_access_grants` (**0 rows**). Disjoint from `users`.
- Machine principal: API key, already hard-bound to one tenant
  (`xdr_rbac.authenticate_api_key`, `api-key-tenant-mismatch`).

## CURRENT_TENANT_GRANT_SOURCE

`users.tenant_ids[]` (array) with legacy single `users.tenant_id` promoted to
a one-element list. This IS an explicit, server-side, per-principal grant
list — it is already the authority for every non-cross-tenant principal and
it is already registry-validated downstream by Fix 5A.

`xdr_access_grants` is NOT a principal→tenant-set store (it grants
*permissions* inside an already-established tenant) and is empty.

## ROLE_BASED_AUTHORITY_LOCATIONS  (inspected, NOT changed)

| # | Location | What role alone currently establishes |
|---|----------|----------------------------------------|
| 1 | `services/dashboard_lenses.py` `_CROSS_TENANT_ROLES = {admin, platform_admin, soc_manager, mssp_operator}` + `resolve_tenant_scope()` | **ROOT CAUSE** · a role name alone yields `all_tenants: True` — unlimited customer authority with zero explicit tenant grant |
| 2 | `services/session_context.py` `authorize_requested_tenant()` — `if all_tenants or requested in authorized: return requested` | any *registered* tenant is authorised for a cross-tenant role |
| 3 | `services/session_context.py` `effective_scope()` — `universe = customers if all_tenants` | the authorised universe becomes the whole case corpus |
| 4 | `routers/xdr_rbac.py` `authorize_tenant()` — `if scope.get("all_tenants"): return resolved` (non-EDR B6 path; still uses the legacy flag-gated `authoritative()`) | same inference on the XDR/security-state plane |
| 5 | `routers/edr_tenancy.py` `_may_discover_tenants()` | `tenants.read` from the built-in role — **disclosure only**, grants nothing (Fix 2) |
| 6 | `apps/nivxray-xdr/src/nivxforge/components/CustomerPicker.jsx` | selectable list = `GET /api/xdr/tenants` (**the whole registry**, ACTIVE-filtered) — not a grant set |
| 7 | `apps/nivxray-xdr/src/nivxforge/tenantContext.js` `SWITCHABLE_BASES` includes `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` | switchability derived from a role-produced basis |

Notes: `mssp_operator` is listed in `_CROSS_TENANT_ROLES` but **does not exist
in the RBAC role catalog** (`_BUILTIN_ROLES`) and no live user holds it;
`admin` likewise is not a catalog role and is mapped to `platform_admin` only
inside `_may_discover_tenants`. So today's cross-tenant authority keys off a
free-text `users.role` string that the RBAC catalog does not govern.

## TENANTS_READ_BEHAVIOR

`tenants.read` / `tenants.manage` are held by **`platform_admin` only** (via
`*.*`); no other built-in role expands to them. It gates
`GET /api/xdr/tenants`, `GET /api/xdr/tenants/{id}`, org/tenant writes, and
the Fix 2 decision on whether a refusal may name the precise reason. It is a
*discovery/management* permission and never grants tenancy.

## CROSS_TENANT_BEHAVIOR

`all_tenants: True` → (a) `_scope()` adds no tenant filter to the case
corpus; (b) `authorize_requested_tenant` accepts any named tenant; (c) with
**no** tenant named, Fix 1 refuses `TENANT_REQUIRED /
CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`; (d) `edr_scope()` always collapses to
`all_tenants: False, tenant_ids:[resolved]`, so reads execute inside exactly
one tenant. Breadth is therefore *selection* breadth, not simultaneous
multi-tenant reads — the gap is that the selectable set is unbounded.

## CUSTOMER_LIST_SOURCE

`services/session_context.list_customers()` → `workspace_cases` aggregation
under the one queue predicate `dashboard_lenses._scope`, grouped by
`tenant_id ?? user_email` (Fix 5B dropped the `"default"` fallback). It is
**evidence-derived, not grant-derived**: for a cross-tenant principal it is
every customer with cases; a granted customer with zero cases never appears.
The EDR picker instead reads the registry (row 6 above). Neither is the
authorized grant set.

## ACTIVE_CUSTOMER_BEHAVIOR

`tenant_context()` publishes `active_customer.{value,basis}` over the six
`SCOPE_BASES`. Resolution order: `EXPLICIT_REQUEST_TENANT` →
`INHERITED_FROM_INCIDENT` → `NOT_AUTHORIZED` → `SINGLE_AUTHORIZED_TENANT` →
`CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` → `MULTIPLE_AUTHORIZED_TENANTS`. The
console (Fix 4A/4B) renders a picker only for the two switchable bases and
fails closed otherwise. Server-side it is **stateless per request** — there
is no persisted "current tenant" for a session.

## X_TENANT_ID_BEHAVIOR

Read once, in `edr_tenancy.edr_tenant()`, as a *request* input:
`X-Tenant-Id` → `authorize_requested_tenant` (principal grant check) →
`authoritative_required` (registered + ACTIVE + ACTIVE org, mandatory since
Fix 5A) → `request.state.effective_tenant_id` + `tenant_resolution_basis`.
Sensor routes never read it. `?tenant=` and `localStorage` are ignored
server-side and sealed client-side (Fix 4A/4B).
**Conclusion: the existing header is sufficient as the requested-context
input for Fix 6. No new switch API is needed for authorization** — only for
the *audit record* of a switch (below).

## EXISTING_VENDOR_MSSP_MODEL

- `tenant_registry.ORG_KINDS = (VENDOR, CUSTOMER, MSSP)` and
  `TENANT_KINDS = (INTERNAL_VALIDATION, CUSTOMER, LAB, LEGACY_ADOPTED)`
  already model a vendor/MSSP organization owning customer tenants.
- **Nothing in the authority path reads `organization.kind`.** It is
  descriptive metadata only. There is no MSSP→customer relationship, no
  delegated-access record, and `TENANT_GROUP_STATE =
  DEFERRED_NOT_YET_AUTHORITATIVE` (groups never grant).

## EXISTING_AUDIT_INFRASTRUCTURE

`routers/xdr_audit_log.emit_audit(...)` → `xdr_audit_log`, append-only,
per-tenant HMAC chain (`prev_sig`/`sig`/`sig_key_id`), fail-closed if Mongo
is unavailable. Fields available today: `tenant_id, principal_id,
principal_kind, action, resource_kind, resource_id, outcome, before, after,
correlation_id, source, metadata, at`. **19,017 live rows.** This already
covers every field the Fix 6 switch record needs — no new audit
infrastructure is required.

## EXISTING_SWITCH_AUDIT

**NONE.** No action name for a successful customer/tenant switch exists
(live action histogram shows `DETECTION_SYNCED`, `ACCESS_DENIED`,
`USER_CREATED`, `TENANT_CREATED`, `TENANT_STATE_CHANGED`, … and nothing
switch-like). Today a "switch" is a browser-local `setActiveTenant()` +
reload; the server only sees a different `X-Tenant-Id` on the next request
and records nothing.

## EXISTING_REFUSAL_AUDIT

**YES.** `xdr_rbac._audit_scope_denial()` emits `action="ACCESS_DENIED",
resource_kind="tenant_scope"` and Fix 2's `_opaque_refusal()` calls it with
`P0-FIX-2:non_disclosing:<precise_code>`, so the precise reason survives
server-side while the response stays opaque. **442 live `ACCESS_DENIED`
rows.** Fix 6 needs no new refusal feature (the separate "Refusal Audit
Trail" idea stays out of scope).

## AUTHORITY_GAPS

- **G6-1** Role ⇒ tenancy. `users.role ∈ _CROSS_TENANT_ROLES` grants every
  customer with no explicit grant (locations 1–4).
- **G6-2** The cross-tenant role string is not governed by the RBAC catalog
  (`admin`, `mssp_operator` are not built-in roles), so tenancy hangs off an
  unvalidated free-text field.
- **G6-3** No principal→authorized-tenant-set surface exists. The UI's
  selectable list is the **entire registry** (`/api/xdr/tenants`), gated only
  by `tenants.read`.
- **G6-4** No successful-switch audit event; a switch is not attributable.
- **G6-5** `organization.kind = VENDOR/MSSP` is inert — no delegated
  customer-access model.
- **G6-6** Client-side switching (`setActiveTenant()` + `window.location
  .reload()`) makes the browser the *initiator* of context change with no
  server acknowledgement (authorization is still server-side per request, so
  this is an auditability/UX gap, not an access bypass).
- **G6-7** `xdr_rbac.authorize_tenant()` (non-EDR) still uses the legacy
  flag-gated `authoritative()` — out of Fix 6 scope but recorded.

## PROPOSED_MINIMUM_FIX6_CONTRACT

```
authenticated principal                       (users, bearer)          #1
  ↓
multi-tenant ELIGIBILITY  = role                                        #2
  ↓
TENANT GRANTS            = users.tenant_ids[]   ← explicit, server-side #3
  ↓   requested tenant MUST be a member (role alone never satisfies #3)
authoritative_required(): registered → ACTIVE → org ACTIVE              #4-6
  ↓
RBAC: require_permission for the operation, inside that tenant          #7
  ↓
active tenant context established server-side (request.state)           #8
  ↓
switch auditable (emit_audit, action TENANT_CONTEXT_SWITCHED)            #9
  ↓
EDR operates only inside that tenant (edr_scope narrowing, unchanged)
```

Concretely:

1. `resolve_tenant_scope()` stops returning `all_tenants: True` from a role
   alone. It returns `{eligible_multi_tenant: bool, tenant_ids: [...]}` where
   `tenant_ids` comes ONLY from `users.tenant_ids[]`. `all_tenants` is
   retained as a computed *platform* flag only if the owner elects option (A)
   below, and never as a substitute for #3.
2. `authorize_requested_tenant()` authorises a requested tenant **iff** it is
   in the grant list; `MULTIPLE_AUTHORIZED_TENANTS` becomes the switchable
   basis for vendor/MSSP principals, and a multi-tenant principal naming none
   keeps today's `TENANT_REQUIRED`.
3. Grants ≠ evidence: session-context gains `authorized_tenants[]` (grant set
   ∩ registry ACTIVE, with display name) and the EDR picker consumes ONLY
   that — never `/api/xdr/tenants`, never localStorage, never a role guess.
   `customers[]` (evidence-derived) stays for the queue panels.
4. Switch record: ONE small server call
   `POST /api/edr/session/active-tenant {tenant_id}` that re-runs the same
   authority chain, emits `TENANT_CONTEXT_SWITCHED` (or `ACCESS_DENIED` on
   refusal) and returns the resolved tenant + basis. `X-Tenant-Id` remains
   the per-request context input; the endpoint adds attribution, not
   authority.
5. Single-customer principals are untouched (Fix 4A/4B): exactly one grant →
   `SINGLE_AUTHORIZED_TENANT` → no picker, no switch call.

### RISK — the live `admin` / `soc_manager` accounts
The 3 `admin` + 1 `soc_manager` live principals hold **no** `tenant_ids[]`.
Under #3 they would lose all customer authority, and the owner has forbidden
creating credentials or modifying memberships. **Owner decision required:**

- **(A)** Declare a documented, narrow *platform-wide* authority contract for
  `platform_admin`-tier principals: eligibility from role, but every request
  must still name the tenant (already enforced), the selectable set comes from
  the registry *with* `tenants.read`, and **every** resolution is audited as
  `PLATFORM_WIDE_TENANT_ACCESS`. Role never becomes an implicit grant for
  non-platform roles (`soc_manager`, `mssp_operator`).
- **(B)** Require explicit grants for everyone, which needs `tenant_ids[]`
  written onto those accounts — a data change requiring owner approval.

Fix 6A recommends **(A) for `platform_admin` only + (B) for `soc_manager` /
`mssp_operator`**, but does not implement either.

## PROPOSED_DATA_MODEL_CHANGE

**NONE (reuse) + one optional additive field.** `users.tenant_ids[]` already
is the authoritative grant list, so no second authority store is created. The
only additive element, if the owner picks option (A), is a per-user marker
recording platform-wide authority explicitly (e.g. `platform_authority: true`
on the `users` document) so the fact is data, not an inference from a role
string. No migration, no rewrite of existing tenant ids.

## PROPOSED_FILES_TO_CHANGE (Fix 6B, on approval)

| File | Change |
|------|--------|
| `backend/services/dashboard_lenses.py` | grants-first `resolve_tenant_scope()`; retire role⇒all-tenants inference |
| `backend/services/session_context.py` | grant-based `authorize_requested_tenant()`; `authorized_tenants[]` in `tenant_context()`; `effective_scope()` universe = grants |
| `backend/routers/edr_tenancy.py` | emit switch/resolution audit; keep Fix 1/2/5A ordering |
| `backend/routers/edr_session.py` *(new, ~40 lines)* | `POST /api/edr/session/active-tenant` — validate + audit + return basis |
| `backend/routers/xdr_rbac.py` | `authorize_tenant()` aligned to grants (non-EDR parity; optional, owner call) |
| `apps/nivxray-xdr/src/nivxforge/components/CustomerPicker.jsx` | list from `authorized_tenants[]`; switch via the server call |
| `apps/nivxray-xdr/src/nivxforge/tenantContext.js` | switchability from the grant set, not a role-derived basis |

## PROPOSED_FOCUSED_TESTS

- `backend/tests/edr/test_p0_tenant_authority_fix6.py` — cases A–N below with
  stubbed principals/registry (no Mongo writes, no credentials).
- `apps/nivxray-xdr/src/lib/__tests__/tenantAuthority.test.js` — extend for
  case O and "picker list never comes from the registry/localStorage/role".
- Re-run fix1 / fix2 / 5A / 5B + `test_a05_tenant_scope_contract.py` only.

## SECURITY_CASE_MATRIX_A_TO_O

| # | Case | Required outcome | Proven by |
|---|------|------------------|-----------|
| A | single-tenant A → A | allowed, `SINGLE_AUTHORIZED_TENANT` | backend unit |
| B | single-tenant A → B | 403 opaque (Fix 2) | backend unit |
| C | MSSP grants[A,B] → A | allowed, `EXPLICIT_REQUEST_TENANT` | backend unit |
| D | MSSP grants[A,B] → B | allowed + switch audit | backend unit |
| E | MSSP grants[A,B] → C | 403, no existence disclosure | backend unit |
| F | MSSP role, no grants | no customer authority (`TENANT_NOT_RESOLVED`) | backend unit |
| G | hand-edited `X-Tenant-Id: C` | refused (grants checked before registry) | backend unit |
| H | `?tenant=C` | ignored server-side, sealed client-side | vitest + backend |
| I | edited `localStorage` | cannot establish authority | vitest |
| J | granted but INACTIVE tenant | refused (`TENANT_NOT_ACTIVE`, Fix 5A) | backend unit |
| K | granted, org INACTIVE | refused (`ORGANIZATION_NOT_ACTIVE`) | backend unit |
| L | registry unavailable | fail closed (`REGISTRY_UNAVAILABLE` 503) | backend unit |
| M | legitimate A → B | `TENANT_CONTEXT_SWITCHED` audit row with principal, previous, requested, resolved, basis, correlation, outcome | backend unit |
| N | refused A → C | existing `ACCESS_DENIED` / `tenant_scope` audit row | backend unit |
| O | single-customer user | never sees switching UI (Fix 4A preserved) | vitest |

## RISKS_OR_OPEN_QUESTIONS

1. **Live admin accounts hold no grants** → option (A) vs (B) above is an
   owner decision and blocks Fix 6B.
2. `soc_manager` (1 live user) and the phantom `mssp_operator` lose breadth
   under grants-first; confirm that is intended.
3. `effective_scope()` currently reports `authorized_count` from the case
   corpus; switching to grants changes a *number the XDR UI displays* (no
   authority change) — confirm acceptable.
4. Evidence-derived `customers[]` and grant-derived `authorized_tenants[]`
   will legitimately differ (granted customer with zero cases). Confirm the
   picker shows grants and the queue shows evidence.
5. Should `organization.kind = MSSP` become authoritative later (an MSSP
   organization implying its customer tenants)? Recommended **NO** for Fix 6 —
   explicit grants only.
6. `xdr_rbac.authorize_tenant()` parity (G6-7) — in or out of Fix 6B?

## VERDICT

**Fix 6A COMPLETE — design established, nothing implemented.** The
authoritative grant source already exists (`users.tenant_ids[]`), the audit
infrastructure already exists (`emit_audit`, refusals already captured), and
`X-Tenant-Id` is sufficient as the requested-context input. The single
blocking decision is the platform-wide authority contract for the live
`admin` / `soc_manager` principals. Awaiting owner approval before Fix 6B.
