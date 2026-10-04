# P0 TENANT AUTHORITY — FINAL GATE CLOSURE ASSESSMENT (read-only)

**CODE_CHANGED: NO · DATA_CHANGED: NO.** No credential created, nothing
renamed, nothing deployed, Device Trajectory not started.

---

## ZERO_TENANT_PROOF_ASSESSMENT

What is already proven, deterministically:

| behaviour | proof |
|-----------|-------|
| zero-grant CUSTOMER principal cannot auto-bind any tenant | `tests/edr/test_p0_tenant_authority_fix1.py:218` → `TENANT_NOT_RESOLVED` |
| the refusal is non-disclosing | `tests/edr/test_p0_tenant_authority_fix2.py:208` |
| zero grants + a *role* (`admin`, `soc_manager`, `mssp_operator`) still has no authority | `test_p0_tenant_authority_fix6b2.py::test_f_g_h_role_without_grants_has_no_tenant_authority` (parametrised ×3, both no-header and named-tenant) |
| a zero-grant principal naming a real tenant is refused | same test, second assertion (403) |
| every TENANT_SCOPED route refuses it | `tests/test_edr_route_tenant_authority.py:689` (`_READ_OPS` matrix, env-gated live) |
| browser inputs cannot substitute for a grant | `test_p0_tenant_authority_fix6b2.py` I/J/K + vitest `pickerFromGrants` D/E |

Why the live cell is still blank: the ENTIRE R4 live suite
(`test_edr_route_tenant_authority.py`) skips at module level because
`TEST_ANALYST_NIVXLIVE_PASSWORD` (and the zero-tenant pair) are not exported —
this is the deliberate P0-PROD-1 rule that no credential value is committed.
The zero-tenant cell is therefore **environment-gated, not unproven logic**.

Read-only finding that may interest the owner: **five live zero-grant
principals already exist** in the preview DB — `a05-admin-37051a53@…` and
`a05-notenant-37051a53@…` (no password, fixture residue) and three
`bob-sec003-*` analyst rows **with a password set from a test-file constant**
(`tests/test_sec003_owner_scoping.py:46`, a suite whose cleanup did not run).
So the live cell could be filled by exporting `ZERO_TENANT_EMAIL` /
`ZERO_TENANT_PASSWORD` for an EXISTING account — no credential creation
needed. Post-6B-2 those rows can reach no customer data at all, which is
itself the model holding; they are nevertheless stale accounts with a
known-constant password and should be deleted (data change → owner approval).

### ZERO_TENANT_CLASSIFICATION
**ACCEPTABLE_DEFERRED_LIVE_PROOF.** Every authority behaviour of a zero-grant
principal is proven hermetically in three independent suites; the missing item
is an environment-gated live re-confirmation of behaviour already enforced by
the same code path that the live matrix proves for other principals.

---

## BASIS_TERMINOLOGY_ASSESSMENT

`CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` appears in 9 files / 15 references:
`services/session_context.py` (the locked `SCOPE_BASES` tuple + the
`ScopeDenied` basis for a PLATFORM principal that named no customer), three
backend suites, and four frontend files (`tenantContext.js` `SWITCHABLE_BASES`,
`scopeApi.js`, `XdrContextBar.jsx`, two vitest suites).

Effect on behaviour:

| surface | affected? |
|---------|-----------|
| authorization decision | **No** — the decision is `authority_scope == "PLATFORM"` / grant membership; the basis is produced *after* the decision |
| tenant resolution | No — resolution returns `(tenant, basis)`; only the label is stale |
| customer enumeration | No — `authorized_customers[]` is grant/registry-derived |
| audit correctness | No — the switch row carries `metadata.authority_scope` (`PLATFORM`/`CUSTOMER`) alongside the basis, so the record is unambiguous |
| UI authority | No — the console keys off `customerControlFor()` + `authority_scope`; `isPlatformPrincipal()` reads the scope, not the basis |
| API contract correctness | Compatibility only — the string is part of the published locked six-value `SCOPE_BASES` set consumed by the frontend; renaming is a coordinated contract change |
| security behaviour | No |

Residual risk: a human reading an audit row or refusal could infer that a role
granted the breadth. Mitigated in the same payloads by `authority_scope`.

### BASIS_RENAME_CLASSIFICATION
**NON_BLOCKING_CLEANUP** (terminology/compatibility debt; rename after the
gate, together with the frontend `SWITCHABLE_BASES` consumers).

---

## AUTHORITY_INVARIANTS_A_TO_Y

| # | invariant | verdict | proof |
|---|-----------|---------|-------|
| A | authenticated principal required | **PROVEN** | `deps.get_current_user` per request; `test_edr_context_p0_f13_3::test_context_unauthenticated` (401/403); live `/api/edr/endpoints` 403 unauthenticated |
| B | CUSTOMER authority from explicit server-side grants | **PROVEN** | `dashboard_lenses.resolve_tenant_scope` (grants only); fix6b2 A–E; live: approver → `authorized_customers` = 1 |
| C | role alone cannot create breadth | **PROVEN** | `_CROSS_TENANT_ROLES` deleted; fix6b2 F/G/H + `test_v_role_alone_does_not_create_platform_scope`; live: `p0a-approver` (`soc_manager`) and `approver` (`admin`) now 403 on `nivx-live`/`probe-t-00bf71` |
| D | PLATFORM requires `authority_scope == "PLATFORM"` | **PROVEN** | `authority_scope()` exact-string match; fix6b2 V (9 malformed values incl. `True`, `1`, `"platform_admin"`, lists, dicts) |
| E | `X-Tenant-Id` is request context, never authority | **PROVEN** | `edr_tenancy.edr_tenant` ordering; fix6b2 I; live 403 for the approver naming `nivx-live` |
| F | `?tenant=` is not authority | **PROVEN** | fix6b2 `test_j_query_tenant_is_not_read_by_the_authority_path`; live browser run with `?tenant=probe-t-00bf71` still on `default` |
| G | localStorage/sessionStorage is not authority | **PROVEN** | vitest `pickerFromGrants` D/E + `tenantAuthority` (24 cases); live run with planted `nvx_tenant=nivx-live` |
| H | single grant auto-binds | **PROVEN** | fix6b2 O; live: approver basis `SINGLE_AUTHORIZED_TENANT`, EDR opens directly |
| I | multiple grants require explicit context | **PROVEN** | fix6b2 P (`TENANT_REQUIRED` / `MULTIPLE_AUTHORIZED_TENANTS`) |
| J | zero grants fail closed | **PROVEN** (hermetic; live cell env-gated) | fix1:218, fix2:208, fix6b2 F/G/H |
| K | ungranted tenant refused | **PROVEN** | fix6b2 B/E/I; live approver 403 ×2 |
| L | nonexistent tenant refused / non-disclosing as applicable | **PROVEN** | fix5a E + fix6b2 S; fix2 collapses unheld/unknown/archived into one opaque 403 for non-privileged principals |
| M | inactive tenant refused | **PROVEN** | fix5a F, fix6b2 L/T |
| N | inactive organization refused | **PROVEN** | fix5a G, fix6b2 M/U |
| O | registry failure fails closed | **PROVEN** | fix5a H (503 `REGISTRY_UNAVAILABLE`), fix6b2 N + `authorized_count` → 0 |
| P | PLATFORM never silently picks default/first | **PROVEN** | fix6b2 `test_p_platform_without_a_request_never_auto_binds`; live admin with no header → 403 `TENANT_REQUIRED`; browser shows `◇ SELECT CUSTOMER` |
| Q | PLATFORM target still passes registry validation | **PROVEN** | fix6b2 S/T/U; `authoritative_required()` is unconditional (Fix 5A) |
| R | switching uses the server-authorized endpoint | **PROVEN** | `POST /api/edr/session/active-tenant` with `Depends(edr_tenant)`; vitest F/G (server call precedes local persistence) |
| S | successful switch is audited | **PROVEN** | fix6b2 W (all fields); live: 3 chained `TENANT_CONTEXT_SWITCHED` rows, `source: nivxforge-edr` |
| T | refused switch cannot alter active authority | **PROVEN** | live: approver switch → 403 + `ACCESS_DENIED`/`tenant_scope` row, context unchanged; vitest "a refused selection changes no active customer"; authority is re-evaluated per request regardless of local state |
| U | picker uses only server-authorized customers | **PROVEN** | `authorized_customers()`; vitest B/C/D (no `api.get`, no `/xdr/tenants`, no storage/query/role strings); live menu header + 136 vs 1 |
| V | single-customer user gets no selector | **PROVEN** | Fix 4A `CONTROL_CONTEXT_ONLY`; vitest A; live DOM contains no "SELECT CUSTOMER" |
| W | authority-resolution failure renders no tenant-bound data | **PROVEN** | Fix 4B `GATE_FAILED` → `CustomerAuthorityUnavailable`; vitest J |
| X | Customer Admin cannot become Super Admin via role/browser state | **PROVEN** | `authority_scope` is read only from the server-side principal document (the ONLY `users` write in the backend is the password change at `routers/auth.py:81`); fix6b2 V incl. the `FAKE_PLATFORM` principal confined to its grants |
| Y | PLATFORM does not bypass RBAC / response approval | **PARTIALLY_PROVEN** | scope and RBAC are separate layers and `require_permission` is untouched; fix6b2 stubs permissions to the empty set for every case, and P0-A self-approval refusal + `response.execute` gating are covered by `test_p0a_response_authority_live.py` / `test_p0_response_execution_tenant_scope.py` (25 passed) — but no single test asserts "PLATFORM principal lacking `response.execute` is refused". One focused case would close it; **not a security regression**, since nothing in 6B-2 touched RBAC |

---

## GENUINE_SECURITY_BLOCKERS

**NONE.**

## NON_BLOCKING_DEBT

1. `ZERO_TENANT_LIVE_CELL` — env-gated live re-confirmation
   (`ZERO_TENANT_EMAIL`/`ZERO_TENANT_PASSWORD`); fillable with an EXISTING
   account, no creation required.
2. `BASIS_RENAME` — `CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER` → e.g.
   `PLATFORM_SCOPE_NO_SINGLE_CUSTOMER`, coordinated with the four frontend
   consumers.
3. `G6-7` — `xdr_rbac.authorize_tenant()` (XDR/security-state plane) still
   uses the legacy flag-gated `authoritative()`; separate review.
4. Invariant Y — add one focused "PLATFORM without `response.execute` is
   refused" case.
5. Stale live rows — 3 `bob-sec003-*` zero-grant accounts with a
   test-constant password + 2 `a05-*` residue rows; recommend deletion
   (needs owner approval).
6. PLATFORM picker renders the first 60 of 136 authorized customers (search
   reaches the rest) — superseded by the future Control Center.
7. `users` collection has no schema validator; `authority_scope` is
   convention-enforced by a single reader.

## TENANT_AUTHORITY_FINAL_DECISION

# TENANT_AUTHORITY_CLOSED

All 25 invariants are PROVEN except Y (PARTIALLY_PROVEN, documented above, no
regression). Fixes 1, 1B, 2, 3, 3A, 4A, 4B, 5A, 5B, 6A, 6B-0, 6B-1, 6B-1b,
6B-2 and Picker-From-Grants are accepted; the remaining items are debt, not
security blockers.

## NEXT_IMPLEMENTATION_TASK

**DT2-3 — VISIBLE DEVICE TRAJECTORY RELATIONSHIPS.** Cisco Secure Endpoint /
AMP remains the controlling operational reference (operational clone,
independently implemented — not generic, not merely AMP-inspired): horizontal
time, process lifelines, parent/child relationship rendering, attached DNS /
NETWORK / FILE / REGISTRY activity, detection markers where real evidence
exists, process selection, parent/child navigation, before/after navigation,
exact event/detection focus, evidence-backed WHY/basis, and **no invented
relationships, no invented process exits, no fabricated activity**. The
Trajectory Inspector (raw evidence / provenance) follows DT2-3 as its own
step.

## OTHER RECORDED REQUIREMENTS (kept)

1. Final manual acceptance identities: PLATFORM Super Admin, Customer Admin,
   Customer Analyst, and preferably a second-customer Analyst.
2. Future **NIVX SUPER ADMIN CONTROL CENTER** — parked until after the
   immediate Device Trajectory work.
3. The Cisco Secure Endpoint / AMP Device Trajectory operational-clone
   requirement is permanent and controlling.
