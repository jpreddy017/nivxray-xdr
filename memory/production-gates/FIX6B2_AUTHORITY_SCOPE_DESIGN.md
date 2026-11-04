# P0 TENANT AUTHORITY · FIX 6B-2 DESIGN AMENDMENT
## Authority classes: CUSTOMER vs NIVX PLATFORM SUPER ADMIN (design only)

Owner decisions recorded 2026-06:
- `admin@nivxray.com` **IS the initial NIVX PLATFORM SUPER ADMIN** by explicit
  owner designation — **never** inferred from `role == admin`.
- Three authority classes: CUSTOMER USER/ANALYST, CUSTOMER ADMIN (customer
  scope, admin permissions *inside* granted customers only), NIVX PLATFORM
  SUPER ADMIN (platform scope).
- Platform authority is represented SEPARATELY from `tenant_ids[]`.
  `tenant_ids[]` is never filled with the whole registry.

**CODE_CHANGED: NO · DATA_CHANGED: NO.** Inspection + contract only.

---

## CURRENT_USER_SCHEMA (`users`, 76 live documents — no validator, loose)

| field | present | notes |
|-------|---------|-------|
| `_id` | 76 | |
| `email` | 76 | the principal identifier used everywhere |
| `role` | 76 | free text; live values `analyst` (72), `admin` (3), `soc_manager` (1) |
| `tenant_id` | 68 | legacy single grant |
| `password` | 65 | bcrypt via `deps.hash_password` |
| `created_at` | 34 | |
| `tenant_ids` | **4** | `admin@nivxray.com`, `approver@…`, `p0a-approver@…` (Fix 6B-1) + `a05-mdr-…` fixture |
| `must_change_password` | 3 | 428 gate in `deps.get_current_user` |
| `enabled` | 2 / `is_active` 1 | inconsistent legacy status fields |
| `name` | 1 | |
| `password_hash` | 1 | legacy variant |
| `tenants` | 1 | legacy stray field, read by nothing |

Authority-relevant facts:
- `deps.get_current_user` re-reads the user document **on every request**
  (JWT carries only `sub`), so a new server-side field is authoritative
  immediately and cannot be asserted by a client.
- **No API writes arbitrary `users` fields.** The only `users` write in the
  whole backend is `routers/auth.py:81` (password change). `xdr_users` is a
  different, tenant-scoped collection. So `authority_scope` can only be set
  by an operator-run script — exactly the required property.

## PROPOSED_AUTHORITY_SCOPE_FIELD

**ONE field, on `users`:**

```
authority_scope : "CUSTOMER" | "PLATFORM"      (absent ⇒ CUSTOMER)
```

No `is_super_admin`, no `superuser`, no `global_access`, no persisted
`all_tenants`, no second collection. Rationale: the platform already has one
principal document per human, re-read per request, writable only server-side.

Constraint satisfaction: stored server-side ✔ · explicit ✔ · auditable
(recorded in every switch/refusal record and settable only by an audited
operator script) ✔ · default ≠ PLATFORM ✔ · missing ⇒ CUSTOMER ✔ ·
unsettable from the browser ✔ (no API writes it) · never inferred from
`role`, `tenants.read`, `organization.kind`, `CustomerPicker` or
`X-Tenant-Id` ✔ (the only read is `users.authority_scope == "PLATFORM"`).

Helper (single reader, so the rule exists once):
`dashboard_lenses.authority_scope(user_doc) -> "PLATFORM" | "CUSTOMER"` —
returns PLATFORM **iff** the stored value is exactly the string `PLATFORM`
(case-sensitive, whitespace-stripped); anything else, including a truthy
oddity, is CUSTOMER.

## DEFAULT_BEHAVIOR

Absent / null / unknown / malformed → **CUSTOMER** (fail closed towards least
authority). A CUSTOMER principal's breadth is exactly `tenant_ids[]`
(∪ legacy `tenant_id`), so a CUSTOMER principal with no grants has **no**
customer authority (`TENANT_NOT_RESOLVED`), which is already Fix 1 behaviour.

## MIGRATION_REQUIRED

**Additive, no backfill of the 76 documents** (absent ⇒ CUSTOMER is the
correct outcome for 75 of them). Exactly ONE designation write is required:

```
users.update_one({"email": "admin@nivxray.com"},
                 {"$set": {"authority_scope": "PLATFORM"}})
```

**Ordering rule (same lesson as Fix 6B-1): the designation write must land
BEFORE the enforcement flip**, otherwise the owner account becomes
CUSTOMER-scoped to `["default","nivx-live"]` the moment
`_CROSS_TENANT_ROLES` is retired. Proposed as its own micro-step
**Fix 6B-1b** (one field, one principal, idempotent, verified read-back,
nothing else touched). The two approver accounts need no write — absent is
already CUSTOMER — though writing an explicit `"CUSTOMER"` is available if
you prefer the fact to be stated rather than defaulted.

## INITIAL_PLATFORM_SUPER_ADMIN

`admin@nivxray.com` — by explicit owner designation only. Its Fix 6B-1
grants `["default","nivx-live"]` are **retained** as its stated operational
customer context and migration fallback; PLATFORM scope is not expressed
through them.

## CUSTOMER_ADMIN_BEHAVIOR

```
authority_scope = CUSTOMER (or absent)
breadth        = tenant_ids[] (∪ legacy tenant_id)      ← authoritative
permissions    = role/RBAC, applied INSIDE the resolved tenant
requested tenant ∉ tenant_ids[]   -> REFUSE (opaque per Fix 2)
no tenant named, 1 grant          -> auto-bind SINGLE_AUTHORIZED_TENANT
no tenant named, >1 grants        -> TENANT_REQUIRED
0 grants                          -> TENANT_NOT_RESOLVED
```
Admin permissions never leak across customers: they are evaluated after the
one tenant is established, inside that tenant.

## PLATFORM_SUPER_ADMIN_BEHAVIOR

```
authority_scope = PLATFORM
    ↓ requested customer tenant (X-Tenant-Id) — REQUIRED, never defaulted
server verifies PLATFORM scope            (users.authority_scope)
    ↓
authoritative_required(): registered -> ACTIVE -> ACTIVE organization  (Fix 5A)
    ↓
RBAC: require_permission for the operation
    ↓
ONE active tenant context (request.state.effective_tenant_id)
    ↓
audit (TENANT_CONTEXT_SWITCHED)
    ↓
EDR/XDR inside that customer only
```
PLATFORM **does not** bypass registry validation, RBAC, response-approval
separation of duties, or the Fix 5A fail-closed states. It does not read
multiple tenants simultaneously — `edr_scope()` still collapses to one.

## RESOLVE_TENANT_SCOPE_CHANGE (`services/dashboard_lenses.py`)

```
BEFORE: role ∈ _CROSS_TENANT_ROLES        -> {all_tenants: True}
AFTER : authority_scope == "PLATFORM"     -> {authority_scope: "PLATFORM",
                                              all_tenants: True}
        everything else                   -> {authority_scope: "CUSTOMER",
                                              all_tenants: False,
                                              tenant_ids: grants}
```
`_CROSS_TENANT_ROLES` is **deleted**; `role` is still returned (permissions
only). `all_tenants` is deliberately KEPT as a *derived* key computed solely
from PLATFORM scope, so its four existing consumers
(`session_context.authorize_requested_tenant` / `effective_scope` /
`list_customers` gate, `xdr_rbac.authorize_tenant`) keep working unchanged —
this is what keeps 6B-2 small and keeps G6-7 deferred rather than dragged in.

## AUTHORIZE_REQUESTED_TENANT_CHANGE (`services/session_context.py`)

Structure is unchanged; only the *source* of breadth changes (role → scope).
Refusal codes and Fix 2 non-disclosure are untouched. `effective_scope`'s
`authorized_count` becomes **grant-derived** for CUSTOMER principals (today
it counts customers in the case corpus). For PLATFORM principals the honest
count is "every ACTIVE registered tenant" — proposed as
`authorized_count = len(registry ACTIVE tenants)` with
`authority_scope: "PLATFORM"` alongside, never the evidence corpus.
**Open question 1** for the owner.

`SCOPE_BASES` is a locked six-value set consumed by the frontend
(`tenantContext.SWITCHABLE_BASES`). To avoid touching Fix 4A/4B UI in 6B-2,
PLATFORM principals keep `EXPLICIT_REQUEST_TENANT` (named) and
`CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` (none named) and the *new* fact
travels as a separate `authority_scope` field in session-context. The basis
NAME still says "role" — proposed rename to `PLATFORM_SCOPE_NO_SINGLE_CUSTOMER`
when the Super Admin Control Center is built. **Open question 2.**

## REGISTRY_VALIDATION

Unchanged and still mandatory for both classes: `authoritative_required()`
(Fix 5A) — registered → tenant ACTIVE → organization ACTIVE, with
`REGISTRY_UNAVAILABLE` fail-closed. PLATFORM scope is checked BEFORE the
registry lookup, so a platform principal naming an unregistered tenant still
learns nothing beyond the refusal it is entitled to.

## RBAC_INTERACTION

Untouched. `authority_scope` answers WHERE; `role`/`xdr_user_roles`/
`xdr_access_grants` answer WHAT. A PLATFORM principal without
`response.execute` still cannot execute a response, and the P0-A
self-approval refusal remains intact.

## SWITCH_AUDIT_DESIGN (reuses `xdr_audit_log`, 19,017 rows)

```
emit_audit(tenant_id=<resolved>, principal_id=<email>, principal_kind="user",
           action="TENANT_CONTEXT_SWITCHED",
           resource_kind="tenant_context", resource_id=<resolved>,
           outcome="SUCCESS",
           before={"tenant_id": <previous or None>},
           after={"tenant_id": <resolved>},
           correlation_id=<request trace_id>,
           metadata={"authority_scope": "PLATFORM"|"CUSTOMER",
                     "basis": <SCOPE_BASES value>,
                     "requested_tenant": <header value>})
```
Emission point: the `POST /api/edr/session/active-tenant` micro-endpoint from
Fix 6A (the only place a "previous context" is knowable), NOT on every
request — per-request emission would add ~1 audit row per API call. No new
audit infrastructure, no new collection, no Refusal Audit Trail product.

## EXISTING_REFUSAL_AUDIT_PRESERVATION

`xdr_rbac._audit_scope_denial()` → `action="ACCESS_DENIED",
resource_kind="tenant_scope"` (442 live rows) and Fix 2's
`_opaque_refusal()` hook stay exactly as they are; 6B-2 only adds
`authority_scope` to the metadata of refusals it raises.

## A05_FIXTURE_IMPACT

`tests/test_a05_tenant_scope_contract.py` seeds `U_ADMIN` with `role: admin`
and no grants, then asserts cross-tenant outcomes
(`authorize_requested_tenant(U_ADMIN, T_ACME) == (T_ACME,
"EXPLICIT_REQUEST_TENANT")`, `/api/xdr/scope/authorized`, queue breadth).
Post-6B-2 that principal is CUSTOMER with zero grants. Repair is a **fixture**
change made during 6B-2, per assertion intent:
- assertions about a *platform* principal → seed `authority_scope: "PLATFORM"`;
- assertions about a *multi-customer* principal → seed
  `tenant_ids: [T_ACME, T_CONTOSO]`.
No live grant and no live credential will be used to make a test pass. Other
role-only-admin fixtures will be reported per suite as they surface.
The CUSTOMER-admin refusal case (grants `["default","nivx-live"]` requesting
`probe-t-00bf71` → REFUSE) will be proven with a **hermetic stubbed
principal**, never with `admin@nivxray.com` (now PLATFORM) and without
creating any credential.

## PROPOSED_FILES_TO_CHANGE (Fix 6B-2, on approval)

| File | Change |
|------|--------|
| `backend/services/dashboard_lenses.py` | `authority_scope()` helper; grants-first `resolve_tenant_scope()`; delete `_CROSS_TENANT_ROLES` |
| `backend/services/session_context.py` | breadth from scope+grants; `authority_scope` in `tenant_context()`/`effective_scope()`; grant-derived `authorized_count` |
| `backend/routers/edr_tenancy.py` | `authority_scope` in refusal metadata (no ordering change) |
| `backend/routers/edr_session.py` *(new, ~40 lines)* | `POST /api/edr/session/active-tenant` — validate + `TENANT_CONTEXT_SWITCHED` audit |
| `scripts/fix6b1b_platform_designation.py` *(new, Fix 6B-1b)* | the single `authority_scope: "PLATFORM"` designation write |
| `backend/tests/…` | new 6B-2 suite + A05 fixture seeding repair |
| *(NOT in 6B-2)* `CustomerPicker.jsx`, `tenantContext.js` | picker-from-grants comes after 6B-2 |

## PROPOSED_FOCUSED_TESTS (hermetic, stubbed, no writes/credentials)

1. absent `authority_scope` ⇒ CUSTOMER; malformed/truthy junk ⇒ CUSTOMER.
2. `role == admin` alone ⇒ **not** PLATFORM. Same for `soc_manager`,
   `mssp_operator`, `tenants.read`, `organization.kind == VENDOR`,
   `len(tenant_ids) > 1`, and a hostile `X-Authority-Scope`-style header.
3. CUSTOMER admin grants `[A,B]` → A/B allowed, C refused (the
   `probe-t-00bf71` regression, hermetically reproduced).
4. CUSTOMER principal, 0 grants → `TENANT_NOT_RESOLVED`.
5. PLATFORM + registered ACTIVE tenant → allowed; PLATFORM + unregistered /
   inactive / inactive-org / registry-down → refused (Fix 5A intact).
6. PLATFORM naming no tenant → `TENANT_REQUIRED` (no default customer).
7. PLATFORM without `response.execute` → RBAC still refuses (no bypass).
8. Fix 2 non-disclosure byte-identical for CUSTOMER refusals.
9. `TENANT_CONTEXT_SWITCHED` row contains principal, authority_scope,
   previous, requested, resolved, basis, correlation, outcome.
10. Refused switch still produces the existing `ACCESS_DENIED`/`tenant_scope`
    row.
11. Fix 4A/4B UI unchanged for a single-grant customer principal (vitest).

## SUPER_ADMIN_CONSOLE_REQUIREMENT_RECORDED

**RECORDED, NOT BUILT.** When a PLATFORM Super Admin logs in, the eventual
default landing experience is the **NIVX SUPER ADMIN CONTROL CENTER**, not an
arbitrary customer EDR console. It must give cross-customer operational
visibility over: customers/tenants, customer health, EDR health, XDR health,
endpoint totals, connected/disconnected/stale endpoints, sensor health and
version, telemetry freshness, detections/incidents, integrations and data
sources, ingestion/evidence pipeline health, policy/response status,
platform/backend/service health, deployment/version status, authority and
security failures, audit activity, customer drill-down and operational
controls. Only metrics backed by real evidence may be displayed; where
telemetry does not exist the state must stay an explicit
`UNKNOWN / NOT IMPLEMENTED`. It is **not** an expanded customer picker. Not
to be built during the Tenant Authority gate.

## DEVICE_TRAJECTORY_PRIORITY_PRESERVED

Unchanged and still the controlling requirement: **immediately** after Tenant
Authority closes, return to the Cisco Secure Endpoint / AMP Device Trajectory
operational-clone target — process lifelines, parent/child relationships,
time-based trajectory, attached DNS/network/file/registry activity, detection
markers, before/after navigation, event/detection focus, search/filter/MATCH
navigation, smooth zoom/pan/scroll, evidence/raw/provenance inspection and the
real analyst investigation workflow — implemented independently on real
NivXForge evidence. Not generic, not merely AMP-inspired. The Super Admin
Control Center does not precede it.

## OPEN QUESTIONS FOR THE OWNER

1. PLATFORM `authorized_count` = number of ACTIVE registered tenants
   (proposed) — confirm?
2. Keep the six locked `SCOPE_BASES` in 6B-2 (no frontend change) and rename
   `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` → `PLATFORM_SCOPE_…` later, or
   rename now and touch `tenantContext.js`?
3. Write explicit `authority_scope: "CUSTOMER"` on the two approver accounts,
   or rely on absent ⇒ CUSTOMER (proposed)?
4. Confirm Fix 6B-1b (designation write) runs as its own micro-step BEFORE
   6B-2 enforcement.

## VERDICT

Design amendment complete. One clean additive field (`users.authority_scope`),
one designation write, no competing flags, no platform bypass of registry or
RBAC, Fix 1/2/4A/4B/5A/5B semantics preserved. **Nothing implemented.**
