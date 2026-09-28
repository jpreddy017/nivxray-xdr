# P0 · CUSTOMER / TENANT AUTHORITY — READ-ONLY AUDIT

Date: 2026-06 · Mode: **READ ONLY**. No code, UI, DB, deployment or DT2 change
was made. No probes were executed (owner deferred the live cross-tenant test
matrix to a separate authorization).

Requirement under audit: a normal single-customer EDR user must NOT see or use
"SELECT CUSTOMER"; the authenticated principal's authorized customer must be
resolved SERVER-SIDE; the browser must never grant tenant authority.

---

## FILES_INSPECTED

Frontend (`apps/nivxray-xdr/src`)
- `lib/tenant.js` — the browser's tenant "authority" (`?tenant=`, `nvx_tenant`)
- `lib/api.js` — axios interceptor attaching `X-Tenant-Id` to every call
- `lib/auth.jsx` — login/session (`nvx_token`, `nvx_email`, `/auth/me`)
- `lib/scopeApi.js` — A0.5 scope client (`/xdr/scope/*`)
- `nivxforge/components/CustomerPicker.jsx` — the "◇ SELECT CUSTOMER" control
- `nivxforge/NivXForgeConsole.jsx` — renders the picker; client-side auto-select
- `nivxforge/edrApi.js` — `getSessionContext()` → `/api/xdr/rbac/session-context`
- `xdr/admin/collectorApi.js`, `ApiKeysBody.jsx`, `CollectorsBody.jsx`,
  `AdminTenantGate.jsx` — explicit per-call `X-Tenant-Id`
- `xdr/components/XdrContextBar.jsx`, `XdrScopeNavigator.jsx`

Backend (`backend`)
- `routers/edr_tenancy.py` — `edr_tenant()`, `sensor_tenant()`, `edr_scope()`,
  `ROUTE_CLASSIFICATION`
- `services/tenant_registry.py` — `authoritative()`, `enforcing()`
- `services/session_context.py` — `tenant_context()`,
  `authorize_requested_tenant()`, `effective_scope()`, `authorised_incident()`
- `services/dashboard_lenses.py` — `resolve_tenant_scope()`, `_scope()`,
  `_CROSS_TENANT_ROLES`
- `routers/xdr_rbac.py` — `resolve_principal()`, `verified_actor()`,
  `require_permission()`, built-in roles, `/rbac/session-context`
- `routers/xdr_tenancy.py` — `/api/xdr/tenants` registry listing
- `routers/edr.py`, `edr_events.py`, `edr_findings.py`, `edr_policies.py`,
  `edr_exclusions.py`, `edr_saved_views.py`, `edr_response.py`,
  `edr_audit.py`, `edr_connector.py`, `edr_wave0.py`, `edr_enrollment.py`
- `edr_plane/authority.py` — response authority gate
- `tests/test_edr_route_tenant_authority.py` — the existing R4 gate
- `backend/.env` — `NIVX_TENANT_REGISTRY_ENFORCE=true`, `NIVX_DEPLOYMENT_ENV=preview`

---

## CURRENT_AUTH_FLOW

```
POST /api/auth/login  (email+password)
  -> bearer token, stored in localStorage["nvx_token"]  (lib/auth.jsx)
  -> GET /api/auth/me                      (principal identity)
  -> GET /api/xdr/rbac/session-context     (NO tenant header required)
         -> services.session_context.tenant_context(email)
              -> dashboard_lenses.resolve_tenant_scope(email)
                   users.{role, tenant_ids|tenant_id}
  -> browser picks a tenant and stores it in localStorage["nvx_tenant"]
  -> every subsequent call carries X-Tenant-Id  (lib/api.js interceptor)
  -> /api/edr/*  ->  Depends(edr_tenant)   (header -> registry)
                 ->  edr_scope(tenant, user)  [ONLY where a route calls it]
                 ->  object lookup filtered by tenant_id
```

Identity itself is sound: `verified_actor()` accepts only an API key stamped by
`authenticate_api_key()` or a bearer `sub` verified with the same secret as
`deps.get_current_user`. Client `X-Principal-Id` is recorded as a
non-authoritative claim (T-RISK-2 closed).

---

## CURRENT_TENANT_AUTHORITY

Two resolvers exist, and they do **not** behave the same way:

| Plane | Resolver | Single-tenant principal | Header required |
|---|---|---|---|
| XDR control plane | `xdr_rbac.resolve_principal` → `session_context.authorize_requested_tenant` | **auto-bound** server-side (`SINGLE_AUTHORIZED_TENANT`) | no |
| EDR plane (`/api/edr/*`) | `edr_tenancy.edr_tenant` | **not bound** — 403 `TENANT_REQUIRED` | **yes** |

`edr_tenant()` answers only "is this a registered ACTIVE tenant?"
(`tenant_registry.authoritative`). The second question — "is this PRINCIPAL
authorized for it?" — lives in a *separate, optional* helper `edr_scope()` that
each route must remember to call.

`edr_scope()` itself is correct: `resolve_tenant_scope` ∩ named tenant, refusing
with `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`, never widening, never falling back.

---

## SELECT_CUSTOMER_SOURCE

- Control: `nivxforge/components/CustomerPicker.jsx`, label `"◇ SELECT CUSTOMER"`,
  testids `nvf-customer-pill` / `nvf-customer-open` / `nvf-customer-menu`.
- Rendered **unconditionally** in `NivXForgeConsole.jsx` (line ~301)
  `<CustomerPicker withEvidence={tenants} />` — there is **no principal/role
  condition of any kind**. A single-customer analyst sees it.
- Its option list comes from `GET /api/xdr/tenants`, which is gated by
  `tenants.read`. Among built-in roles only `platform_admin` (`*.*`) holds it,
  so for every normal customer principal the call 403s and the menu renders
  the error "the tenant registry could not be read with this principal's
  permissions" — i.e. the control is both **present and non-functional** for
  exactly the user who should never see it.
- Selecting writes `localStorage["nvx_tenant"]` and calls
  `window.location.reload()` (`pick()`), i.e. the browser re-keys the whole
  console's data scope.
- `NivXForgeConsole.jsx` lines ~219-226 auto-select **in the browser** when
  `tenants.length === 1`, derived from `session-context`. The intent is right;
  the mechanism is client-side and still ends as a client-supplied header.
- Related, benign: `datasources/windows/WindowsPrimitives.jsx::SelectCustomerNotice`
  is only an empty-state notice ("select a customer"), not an authority control.

---

## CLIENT_CONTROLLED_TENANT_INPUTS

1. **`?tenant=` query parameter** — `lib/tenant.js::activeTenant()` reads it
   FIRST, ahead of storage; `NivXForgeConsole.propagate()` re-attaches it on
   every in-app navigation; `XdrIocIntelPage` documents deep links carrying it.
2. **`localStorage["nvx_tenant"]`** — `activeTenant()` / `setActiveTenant()`.
   (Only three other keys exist: `nvx_token`, `nvx_email`, `nx.theme`. No
   tenant value is kept in `sessionStorage`.)
3. **`X-Tenant-Id` header** — attached to EVERY request by the single axios
   interceptor in `lib/api.js`, plus explicit per-call headers in
   `xdr/admin/collectorApi.js`, `ApiKeysBody.jsx`, `CollectorsBody.jsx`.
4. No tenant id is sent in a request **body** on the audited EDR surfaces
   (`/xdr/scope/select` sends `tenant_id`, but that endpoint intersects with
   the authorized set and returns server truth).

So today the browser is the *only* thing that decides which customer the EDR
console acts as, and the server validates that choice **inconsistently**.

---

## SERVER_AUTHORIZATION_CONTROLS

Present and working:
- `tenant_registry.authoritative()` — existence + ACTIVE state, fail closed
  while `NIVX_TENANT_REGISTRY_ENFORCE=true`.
- `dashboard_lenses.resolve_tenant_scope()` — the one authorization fact
  (`users.tenant_ids` / `tenant_id`, or cross-tenant role).
- `edr_tenancy.edr_scope()` — intersection; 403 `ACCESS_DENIED` /
  `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL`.
- `session_context.authorize_requested_tenant()` / `effective_scope()` —
  `EffectiveScope = Requested ∩ Authorized`, never a fallback tenant.
- `session_context.authorised_incident()` — incident-bound scope lock.
- Data partitioning at the query: `_case_scope`, `_tenant_scope`,
  `{"tenant_id": tenant}` predicates in `edr_events`, `edr_findings`,
  `edr_saved_views`, `edr_policies`, `edr_exclusions`, `resp.get_command`.
- `ROUTE_CLASSIFICATION` + R4 gate: an unclassified `/api/edr/*` route fails.

**Missing:** nothing forces a TENANT_SCOPED route to call `edr_scope()`.
Route-level authorization is by convention, and the convention is broken in
eight places (below).

---

## SINGLE_CUSTOMER_BEHAVIOR

- **Not** auto-bound on the EDR plane. `edr_tenant()` raises 403
  `TENANT_REQUIRED` when the header is absent, even when the principal holds
  exactly one tenant and no ambiguity exists.
- Because `GET /api/edr/context` is itself `TENANT_SCOPED`, the EDR entry
  context cannot be read before a tenant is chosen — a chicken-and-egg that
  only `/api/xdr/rbac/session-context` (tenant-free) breaks.
- Consequence: the product *needs* the browser to name the tenant, which is
  exactly why "SELECT CUSTOMER" exists and why it is shown to users who have
  nothing to select. The correct server behaviour already exists one module
  away (`authorize_requested_tenant` → `SINGLE_AUTHORIZED_TENANT`) and is
  simply not used by the EDR dependency.

---

## MULTI_TENANT_BEHAVIOR

- Cross-tenant identity is decided by **role name**:
  `dashboard_lenses._CROSS_TENANT_ROLES = {admin, platform_admin, soc_manager,
  mssp_operator}` → `all_tenants: True`.
- For such a principal `edr_scope()` accepts any registered ACTIVE tenant it
  names and narrows the answer to it; `authorize_requested_tenant()` refuses to
  pick one implicitly (`TENANT_REQUIRED`, basis
  `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`). That part matches the requirement.
- There is **no vendor/MSSP tenancy model** behind it: `organizations.kind`
  supports `VENDOR|CUSTOMER|MSSP` and `tenants.kind` supports
  `CUSTOMER|MSSP|LAB|INTERNAL_VALIDATION|LEGACY_ADOPTED`, but authorization
  never reads them. A customer's own `soc_manager` is therefore treated as a
  cross-tenant (vendor-grade) identity.
- Active context is reported (`active_customer.basis`, `SCOPE_BASES`) and scope
  denials are audited (`_audit_scope_denial`), but a *tenant switch* on the EDR
  console is a `localStorage` write + page reload, with no audit event.
- Tenant groups are explicitly non-authoritative
  (`TENANT_GROUP_STATE = DEFERRED_NOT_YET_AUTHORITATIVE`) — correct.

---

## CROSS_TENANT_OBJECT_TEST_STATUS

**NOT EMPIRICALLY TESTED — code-path analysis only** (owner deferred probes).
Static result per object class, where "scoped" = the route both filters by
tenant AND authorizes the principal for it:

| Object | Route(s) | Status |
|---|---|---|
| endpoint id | `/api/edr/endpoints`, `/endpoints/{id}/trajectory`, `/process-tree`, `/endpoint-detections` | scoped (`_tenant_scope`) |
| event / raw-event id | `/api/edr/events`, `/events/{raw_id}` | scoped; 404 `EVENT_NOT_FOUND` |
| canonical / observation id | `/observation-narrative`, `/endpoints/{id}/trajectory` | scoped |
| detection / finding id | `/findings`, `/findings/{id}` | scoped |
| **detections (per incident)** | `GET /api/edr/detections` | **UNSCOPED** |
| trajectory / focus | `/device-trajectory`, `/endpoints/{id}/trajectory/focus` | scoped |
| **campaign story** | `GET /api/edr/campaign-story` | **UNSCOPED** |
| **file trajectory / fleet spread** | `GET /api/edr/file-trajectory`, `/fleet-spread-index` | **UNSCOPED** |
| evidence (saved views, audit, exclusions) | `/saved-views*`, `/audit*`, `/exclusions*` | scoped |
| policy | `/policies*`, `/groups` | scoped |
| **isolation policy (read)** | `GET /api/edr/response/isolation-policy` | **UNSCOPED** |
| **response action record** | `GET /api/edr/response/actions/{command_id}` | **UNSCOPED** |
| **raw-event stats / replay** | `GET /api/edr/wave0/raw-events/stats`, `/replay-candidates` | **UNSCOPED** |
| response execute / policy write | `POST /response/actions`, `PUT /isolation-policy` | scoped + response authority |
| sensor plane | `/api/edr/agent/*` | `SENSOR_SCOPED`, header never read |

The eight UNSCOPED operations take `Depends(edr_tenant)` and then query
`{"tenant_id": <header value>}` **without ever calling `edr_scope()`**. They are
registry-validated but not principal-authorized, so on those routes a
client-supplied tenant *does* expand authorization.

Existing regression coverage: `tests/test_edr_route_tenant_authority.py`
exercises `TENANT_REQUIRED` / `TENANT_NOT_FOUND` / `TENANT_NOT_ACTIVE` for every
TENANT_SCOPED op, but the cross-principal assertions
(`test_scoped_principal_cannot_name_a_tenant_it_does_not_hold`) run against
`/api/edr/endpoints` **only** — which is why the eight gaps are invisible today.

---

## DEFAULT_OR_FALLBACK_FINDINGS

1. `tenant_registry.authoritative(..., compat_default="default")` — with
   `NIVX_TENANT_REGISTRY_ENFORCE` **off (the documented default)**, a missing
   header silently becomes the literal tenant `"default"` and *any* arbitrary
   tenant string is accepted. Preview sets the flag `true`; the safe behaviour
   therefore depends on an env var rather than on code.
2. `session_context.authorised_incident()` falls back to
   `doc.tenant_id or doc.user_email or "default"` when reading an incident's
   owner.
3. `session_context.list_customers()` groups on
   `tenant_id → user_email → "default"`, so a `"default"` pseudo-customer can
   appear in the console's customer list.
4. `resolve_tenant_scope()` correctly returns an EMPTY tenant list (no
   `"default"`) — that fallback is already closed.
5. Frontend has no default tenant (`activeTenant()` returns `null`) — correct;
   the price is the deadlock described in SINGLE_CUSTOMER_BEHAVIOR.

---

## SECURITY_GAPS

- **G1 (P0, cross-tenant read).** Eight TENANT_SCOPED EDR operations never call
  `edr_scope()`: `/api/edr/detections`, `/campaign-story`, `/file-trajectory`,
  `/fleet-spread-index`, `/response/actions/{command_id}`,
  `/response/isolation-policy`, `/wave0/raw-events/stats`,
  `/wave0/raw-events/replay-candidates`. Any authenticated principal — including
  one authorized for zero tenants — can read another customer's data by naming
  that tenant in `X-Tenant-Id`.
- **G2 (P0, architecture).** Tenant authority on the EDR plane is
  *registry validation only*; principal authorization is an optional per-route
  call. Correctness depends on every future route author remembering it.
- **G3 (P0, product/UX boundary).** "SELECT CUSTOMER" is rendered for every
  principal with no role condition, and is non-functional for normal customers
  (`/api/xdr/tenants` requires `tenants.read` = platform admin). The requirement
  "a single-customer user must not see or use SELECT CUSTOMER" is violated.
- **G4 (P0, browser authority).** `?tenant=` (highest precedence) and
  `localStorage["nvx_tenant"]` are the console's tenant source of truth; the
  header is minted from them for every call. On G1 routes this *is* authority.
- **G5 (P1, no server auto-bind).** A single-authorized-tenant principal is not
  bound server-side on `/api/edr/*`, forcing the browser into the loop.
- **G6 (P1, enumeration oracle).** `edr_tenant()` distinguishes
  `TENANT_NOT_FOUND` (403) from `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` (403), so
  any authenticated principal can enumerate which tenant ids exist. Object-level
  failures *are* non-disclosing (404 "no such event in the tenant you are
  authorised for"); the tenant-level refusal is not.
- **G7 (P1, fail-open default).** `NIVX_TENANT_REGISTRY_ENFORCE` defaults to OFF
  with a `"default"` compat fallback and acceptance of arbitrary tenant strings.
- **G8 (P1, identity model).** Vendor/MSSP status is inferred from role names
  (`soc_manager`, `mssp_operator`) instead of the registry's
  `organizations.kind` / `tenants.kind`; a customer's own SOC manager becomes a
  cross-tenant identity.
- **G9 (P2, audit).** An EDR customer switch (localStorage + reload) emits no
  audit event; only denials are audited.
- **G10 (P2, residue).** `"default"` pseudo-tenant fallbacks remain in
  `authorised_incident()` / `list_customers()`.

---

## MINIMUM_FIX_PLAN

Smallest change that closes the boundary, reusing what already exists:

1. **One dependency, both questions.** Re-implement `edr_tenancy.edr_tenant()`
   as: `authorize_requested_tenant(principal, X-Tenant-Id)` (existing) →
   `tenant_registry.authoritative(...)` (existing) → return the authorized
   tenant. Authorization then happens for EVERY `/api/edr/*` route by
   construction; the eight G1 routes are fixed without touching them, and the
   surviving `edr_scope()` calls become redundant rather than load-bearing.
   This also auto-binds the single-tenant principal (`SINGLE_AUTHORIZED_TENANT`)
   and keeps `TENANT_REQUIRED` for cross-tenant identities that named nothing.
2. **Non-disclosing tenant refusal.** Collapse `TENANT_NOT_FOUND` /
   `TENANT_NOT_ACTIVE` / `TENANT_NOT_AUTHORIZED_FOR_PRINCIPAL` into one
   indistinguishable 403 for principals without `tenants.read`; keep the precise
   code in the audit record only.
3. **Extend the R4 gate.** Table-drive the cross-principal assertion over EVERY
   TENANT_SCOPED operation (not just `/api/edr/endpoints`): scoped principal +
   other tenant ⇒ refused; scoped principal + own tenant ⇒ 200; zero-tenant
   principal ⇒ refused. This is what would have caught G1.
4. **UI: switching is a server-granted capability.** Render the customer control
   only when the server reports a switchable basis
   (`MULTIPLE_AUTHORIZED_TENANTS` / `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER`) from
   `/api/xdr/rbac/session-context`; otherwise render a static, non-interactive
   customer label. Stop sourcing tenant from `?tenant=` and
   `localStorage["nvx_tenant"]` as authority — at most keep them as a *requested*
   context that the server re-authorizes on every call (and that is ignored for
   a single-tenant principal).
5. **Close the fail-open default.** Make registry enforcement the default (or
   hard-fail at startup when unset outside development) and delete the
   `compat_default="default"` path; remove the `"default"` fallbacks in
   `authorised_incident()` and `list_customers()`.
6. **Separate vendor/MSSP from role names** (follow-up, not required to close
   the read boundary): derive cross-tenant capability from registry
   `organizations.kind`/`tenants.kind` + explicit grant, and audit every
   tenant-context switch.

Sequencing proposal: fix 1 → test 3 → fix 2 → fix 4 → fix 5 → then the deferred
live cross-tenant probe matrix against **preview only**, then return to the
AMP-class trajectory work (DT2-2F).

---

## VERDICT

**FAIL — tenant authority is NOT closed.**

Identity is server-authoritative and object queries are tenant-partitioned, but
(a) eight TENANT_SCOPED EDR operations accept a client-named tenant without
authorizing the principal for it, and (b) the EDR plane structurally depends on
the browser to name the customer, which is why a single-customer user is shown a
"SELECT CUSTOMER" control they must not have. The correct server-side resolver
already exists and is used by the XDR plane; the EDR plane does not call it.
