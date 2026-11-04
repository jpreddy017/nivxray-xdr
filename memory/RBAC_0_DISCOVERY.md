# RBAC-0 · READ-ONLY DISCOVERY RETURN PACKAGE

Owner directive: *NIVXRAY XDR ENTERPRISE IDENTITY, RBAC, GROUP ACCESS &
ROLE-AWARE SPA*, §34/§40. **Discovery only. No RBAC-1+ implementation.**
Nothing in this pass was written to any authorization store, no user, role,
group, assignment or permission was created or modified.

Date 2026-06. Read-only methods used: source inspection, live authenticated
`GET` against the preview API as `admin@nivxray.com`, and direct read-only
Mongo counts. No mutation, no exploit execution.

---

## 0 · Repository state

| item | value |
|---|---|
| start HEAD | `git rev-parse HEAD` at session open (recorded in job log) |
| working tree at RBAC-0 completion | only new files under `/app/memory/` and `/app/scripts/` |
| backend files modified | **none** |
| frontend files modified | **none** |
| W1 artefacts | untouched |
| W2 harness / collector | untouched |

---

## 1 · Existing authorities — inventory

### 1.1 Authentication authority — **ONE, ADOPT**
`backend/deps.py`

| fact | location |
|---|---|
| password hash | `hash_password` / `verify_password`, bcrypt — `deps.py:262-270` |
| token mint | `create_token(email)` → HS256 JWT, claims **`sub`, `iat`, `exp` only** — `deps.py:273-279` |
| expiry | `JWT_EXPIRE_HOURS` env, default **24 h** — `deps.py:72` |
| verify | `get_current_user` — decode → **re-read `users` doc on every request** — `deps.py:282-299` |
| forced rotation gate | `must_change_password` → **HTTP 428** — `deps.py:297` |
| raw variant | `get_current_user_raw` (change-password only) — `deps.py:302` |
| optional variant | `get_current_user_optional` — `deps.py:325` |
| coarse role gate | `require_admin` → `user.role != "admin"` → 403 — `deps.py:353` |
| admin seed | `seed_admin()` idempotent, writes `role: "admin"`, **no `tenant_id`** — `deps.py:359` |
| login/me/change-password | `backend/routers/auth.py` |

**Verdict: ADOPT.** The JWT carries no roles, no tenant and no permissions —
which is the correct design, because every request re-reads the persisted user.
There is no second authentication authority anywhere in the backend.

### 1.2 Tenant authority — **ONE PRIMARY + ONE RESOLVER, ADOPT**
| component | location | role |
|---|---|---|
| `tenant_registry.authoritative(tenant_id, purpose=)` | `services/tenant_registry.py` | existence + ACTIVE + org ACTIVE |
| `resolve_tenant_scope(email)` | `services/dashboard_lenses.py` | `{authorized, all_tenants, tenant_ids}` |
| `tenant_context(email)` | `services/session_context.py` | shell customer pill |
| `authorize_tenant(request, tenant_id, purpose=)` | `xdr_rbac.py:665-717` | body-named tenant is a **request, not an authority** |

Live proof (`GET /api/xdr/rbac/session-context` as admin):
`{"principal":{"email":"admin@nivxray.com","role":"admin"},
"tenant_scope":{"authorized":true,"all_tenants":true,"tenant_ids":[]}}`

**Verdict: ADOPT.** `authorize_tenant` already implements the directive's §11
ordering (authenticate → resolve → authorize → operate) and already refuses a
machine credential acting outside its bound tenant.

### 1.3 Authorization authority — **ONE, EXTEND**
`backend/routers/xdr_rbac.py` (1,318 lines) is the single authorization plane.

| element | location | state |
|---|---|---|
| permission catalog | `_ACTIONS` (28) × `_RESOURCES` (33) — `xdr_rbac.py:102-180` | **EXISTS** |
| concrete permissions | `_all_permissions()` — `xdr_rbac.py:183` | **192** live (`GET /permissions` 200) |
| wildcard grammar | `*.*`, `res.*`, `*.action` — `_expand_wildcard` `:342` | **EXISTS** |
| built-in roles | `_BUILTIN_ROLES` — `xdr_rbac.py:203-324` | **11**, code-defined, stable ids |
| custom roles | `xdr_roles` + create/update/clone/delete `:915-1030` | **EXISTS**, clone→custom pattern present |
| built-in role safety | `update_role:952`, `delete_role:1014` → 409 | **ALREADY SAFE** (directive §38 satisfied) |
| users | `xdr_users` + CRUD `:1034-1142` | **EXISTS** |
| role assignment | `xdr_user_roles` + assign/revoke `:1144-1201` | **EXISTS** |
| effective permissions | `GET /users/{id}/effective` `:1203` | **EXISTS** (union of assigned roles) |
| access simulator | `POST /simulate` `:1275` | **EXISTS**, uses the production `check_access` |
| groups | `xdr_groups` + list/create/delete `:1224-1271` | **SHELL ONLY — see G-1** |
| resolver | `check_access()` `:399-466` | **EXISTS**, deterministic, returns a reason |
| enforcement dependency | `require_permission()` `:724-815` | **EXISTS**, fail-closed |
| machine principals | `authenticate_api_key` `:542`, throttle `:492` | **EXISTS**, 10 explicit DENY classes |
| audit actor | `verified_actor()` `:622` | **EXISTS**, client claims never authoritative |
| audit sink | `xdr_audit_log`, `emit_audit(...)` | **EXISTS · 12,254 rows** |

**Verdict: EXTEND, never rebuild.** The directive's §0 warning — *"Do not create
RBAC v2 beside an existing authorization system"* — applies directly. Every
RBAC-1…RBAC-12 gate has an existing seam.

### 1.4 Route / API enforcement — **EXTEND**
`require_permission` is applied as a FastAPI dependency across
**20 routers**: `xdr_rbac`, `xdr_collectors`, `xdr_secrets`, `xdr_api_keys`,
`xdr_webhooks`, `xdr_data_sources`, `xdr_ingest`, `xdr_rule_studio`,
`xdr_detection_content`, `xdr_detection_citations`, `xdr_correlation`,
`xdr_lolbas`, `xdr_cve`, `xdr_audit_log`, `xdr_spread`, `xdr_tenancy`,
`xdr_response_evidence`, `intelligence_policy`, `collector_authz`,
`security_state/routers/router.py`.

`/api/incidents`, `/api/investigations`, `/api/edr/*` are **not** gated by
`require_permission`; they are protected by authentication + tenant-scope
predicates (`resolve_tenant_scope`, `_incident_scope_predicate`). That is a
different, *narrower* model: it answers "which rows" but never "which verb".

### 1.5 Frontend session / route enforcement — **BUILD**
| element | location | state |
|---|---|---|
| auth context | `apps/nivxray-xdr/src/lib/auth.jsx` (57 lines) | `{user, loading, login, logout}` — **`user` is `/auth/me` only: email + role** |
| route guard | `App.jsx:78-88` `<Protected>` | **authentication only**, zero authorization |
| rail | `XdrShell.jsx:289-325` `RAIL` (9 primaries) | **fully static**, `disabled: true` hard-coded per item |
| permission awareness | — | **NONE anywhere in the SPA** |
| admin surface | `xdr/admin/UsersRolesBody.jsx` | reads RBAC APIs; no groups/scope/effective-access UI |

**Verdict: BUILD.** There is no permission plumbing in the frontend at all.

---

## 2 · ADOPT / EXTEND / REPAIR / BUILD matrix

| # | subsystem | verdict | note |
|---|---|---|---|
| 1 | Authentication (bcrypt + JWT + per-request user read) | **ADOPT** | no change needed for RBAC |
| 2 | `must_change_password` 428 gate | **ADOPT** | |
| 3 | Tenant registry + `resolve_tenant_scope` | **ADOPT** | |
| 4 | `authorize_tenant()` body-tenant refusal | **ADOPT** | |
| 5 | Permission catalog (`_ACTIONS` × `_RESOURCES`, 192 perms) | **EXTEND** | rename/align to directive §4 namespaces **by alias, not replacement** |
| 6 | Wildcard expansion | **ADOPT** | |
| 7 | 11 built-in roles | **EXTEND** | directive §5 asks for 7 templates; 9 of them already map |
| 8 | Built-in role immutability (409) | **ADOPT** | §38 already satisfied |
| 9 | Custom role builder + clone | **ADOPT** | |
| 10 | `check_access()` resolver | **EXTEND** | must learn groups, direct grants, explicit DENY, scope kinds |
| 11 | `require_permission()` dependency | **ADOPT** | fail-closed since P0-SEC 2026-09-09 |
| 12 | Machine/API-key principal path | **ADOPT** | |
| 13 | `verified_actor()` | **ADOPT** | |
| 14 | `xdr_audit_log` + `emit_audit` | **EXTEND** | add the §29 event vocabulary |
| 15 | `POST /simulate` | **EXTEND** | must return the full §20 explanation, same resolver |
| 16 | `GET /users/{id}/effective` | **EXTEND** | must gain per-permission provenance (§19) |
| 17 | Groups | **REPAIR → BUILD** | see **G-1** — currently non-functional |
| 18 | Direct user permission grants | **BUILD** | §8 |
| 19 | Explicit DENY / restrictions | **BUILD** | §9 |
| 20 | Resource & data scope (device groups, BUs, data sources) | **BUILD** | §12; only `resource_ids` exists |
| 21 | Identity unification (`users` ⇄ `xdr_users`) | **REPAIR** | see **G-2** — the largest single risk |
| 22 | Self-scoped effective-permissions endpoint | **BUILD** | see **G-3** — blocks role-aware SPA |
| 23 | Frontend permission adapter | **BUILD** | RBAC-7/8 |
| 24 | Frontend route authorization | **BUILD** | RBAC-7 |
| 25 | Privilege-escalation protection on assignment | **BUILD** | see **G-5** |
| 26 | `_principal()` header trust in endpoint bodies | **REPAIR** | see **G-4** |
| 27 | Session revocation / permission-change propagation | **EXTEND** | see **G-6** |
| 28 | Response authority separation (request/approve/execute/verify) | **ADOPT** | already a separate hardened plane; RBAC must not re-implement it |
| 29 | `/api/incidents` verb-level authorization | **EXTEND** | row scoping exists, verb gating does not |
| 30 | Access Management admin UI | **BUILD** | RBAC-9/10 |

---

## 3 · GAPS — the findings that change the plan

### G-1 · P1 · **Groups are decorative — group-based access control does not work**
`xdr_groups` supports only list / create / delete. `CreateGroupBody`
(`:862`) has **no roles, no scope, no members**. `xdr_users.groups` is a free
string array written by `create_user`/`update_user` and **never read by the
resolver**: `_resolve_user_permissions()` (`:381-396`) queries
`xdr_user_roles` **only**.

Consequence: adding a user to a group grants **nothing**. Live: `xdr_groups`
holds 1 document; no group has ever influenced an authorization decision.
The directive's §6 ("adding a user to this group must automatically grant the
group's applicable access") is therefore a **BUILD**, not a wiring task.

### G-2 · P0 · **TWO identity stores, and the RBAC one contains no production identity**
| collection | rows | written by | used for |
|---|---|---|---|
| `users` | **6** | `deps.seed_admin`, `scripts/seed_customer_scoped_analyst.py` | **login**, `role` (`admin`/`analyst`), `tenant_id`, password hash |
| `xdr_users` | **19** | `POST /api/xdr/rbac/users` | RBAC role assignment target |

All 19 `xdr_users` rows belong to **test tenants** (`rbac-tenant-77a8bd44`,
`TEST_intel_rbac_*`, `TEST_intel_allow_*`). Live as admin:
`GET /api/xdr/rbac/users` → **`{"users":[],"count":0}`** for tenant `default`.

`admin@nivxray.com` has **no `xdr_users` row at all**. The RBAC admin surfaces
work for the owner solely because `require_permission` short-circuits on
`role == "admin"` (`xdr_rbac.py:783-784`).

Two hard consequences:
1. `POST /api/xdr/rbac/users` **does not create a login** — no password, no row
   in `users`. An "user" created in Access Management cannot sign in.
2. `PUT /api/xdr/rbac/users/{id}` `enabled: false` does **not** disable
   authentication; `get_current_user` reads `users`, not `xdr_users`.

**Owner decision required (D-1):** unify on `users` as the single identity
record with RBAC facets attached, or keep two collections with an authoritative
join key. This decision gates every later gate and must not be taken by the
agent.

### G-3 · P0 · **No self-scoped effective-permissions contract — the role-aware SPA is blocked**
`GET /api/xdr/rbac/users/{user_id}/effective` is gated on **`users.read`**
(`:1204`). An L1 analyst holds `incidents.read` but not `users.read`, so a
non-admin **cannot read their own permissions**. `GET /session-context`
(`:1315`) returns tenant identity only — no roles, no permissions.

The directive's §27 authoritative session representation
(`{tenant, user, roles, groups, permissions, scopes}`) therefore **does not
exist**. Without it the only ways to build role-aware navigation are (a) hard
coding, or (b) role-name checks — both explicitly forbidden by §23/§4.

**Minimal enabling change proposed (NOT implemented in RBAC-0):**
`GET /api/xdr/rbac/me/effective` — authenticated, self-scoped, read-only,
reusing `_resolve_user_permissions()` and the existing `role == "admin"`
semantics verbatim. Zero new model, zero new permission, zero new store. It is
a *projection* of the existing resolver, not a new authority.

### G-4 · P1 · **`_principal()` trusts client headers inside endpoint bodies**
`_principal(req)` (`:331-338`) resolves the tenant from
`X-Tenant-Id` (fallback `"default"`) and the principal from `X-Principal-Id`
(fallback **`"admin@nivxray.com"`**). `require_permission` correctly ignores
these and takes the tenant from the authenticated `users` record
(`:787`) — but **every endpoint body then calls `_principal()` again**:
`list_users:1039`, `create_user:1057`, `update_user`, `delete_user`,
`assign_role`, `revoke_role`, `effective_permissions:1207`, `list_groups:1229`,
`create_group:1239`, `delete_group:1261`, `simulate:1280`, and all five role
endpoints.

So the tenant that **authorises** and the tenant that is **operated on** are
resolved from two different sources. For a cross-tenant `role == "admin"`
principal this is intended. For a *tenant-scoped* principal holding e.g.
`users.create`, the gate would authorise against their own tenant while the
body writes into the tenant named in the header.

**Classified as a code-path divergence, not an executed exploit.** No
tenant-scoped principal currently holds `users.*` in this environment
(`xdr_users` for tenant `default` is empty), so there is **no live exposure**
today. It must be closed before any tenant-admin identity is provisioned.
Fix shape: resolve the operating tenant from the same authenticated record the
gate used, and pass it into the body — never re-derive it from headers.

### G-5 · P1 · **No privilege-escalation protection on role assignment**
`assign_role` (`:1144`) validates that the role exists and the user exists. It
does **not** check that the caller is authorised to *administer* the
permissions being conferred. A principal holding `roles.read` + `users.*`
(e.g. built-in `tenant_admin`, which holds `users.*` and `roles.*`) can assign
`role_builtin_platform_admin` (`*.*`) to itself or anyone in its tenant.
Directive §37 requires this be impossible. **BUILD**: a
"cannot grant what you do not hold" predicate plus a protected-operation list.

### G-6 · P2 · **Revocation is better than the directive assumes — but not complete**
Because `get_current_user` re-reads the `users` document and `check_access`
re-reads assignments on **every** request, the following are already effective
immediately, with no token invalidation needed:
role assigned/revoked · role permissions edited · `xdr_users.enabled` toggled
(for RBAC-gated routes) · assignment scope changed.

What is **not** bounded:
1. `users.enabled` is **not consulted** by `get_current_user` — a disabled
   login still authenticates until `exp` (≤24 h). *(Confirmed: `deps.py:290-299`
   checks only existence and `must_change_password`.)*
2. There is **no token revocation list and no `jti`**, so a stolen token cannot
   be killed; only a password rotation + `must_change_password` achieves it.
3. The SPA will cache the permission set in memory; a refresh/expiry contract
   must be declared (proposal: re-fetch on navigation + a documented max age),
   and the frontend must never be the authority.

### G-7 · P2 · **Two authorization idioms coexist for analyst data**
Control-plane routes use `require_permission` (verb authority). Incident /
investigation / EDR routes use tenant-scope predicates (row authority). Both
are correct and both are needed, but the directive's §25 component-level
authorization requires a **verb** answer for incidents (`incidents.update`,
`response.approve`). Those permissions already exist in the catalog; they are
simply not enforced on `/api/incidents`. **EXTEND**, and it must not weaken the
existing row scoping.

### G-8 · P3 · Permission-namespace drift vs the directive
Directive §4 proposes `incident.*`, `datasource.*`, `hunting.*`, `group.*`,
`api_key.*`, `user.*`, `role.*`, `audit.read`, `platform.*`.
The live catalog uses the **plural** forms `incidents.*`, `data_sources.*`,
`threat_hunting.*`, `groups.*`, `api_keys.*`, `users.*`, `roles.*`,
`audit.read`, `platform.*`. §4 itself says to ADOPT existing names.
**Recommendation: keep the live names as authoritative** and record the mapping
once, rather than migrating 20 routers and 11 built-in roles for cosmetics.

---

## 4 · What the directive asks for that ALREADY exists (do not rebuild)
- Granular `resource.action` permissions with a rendered matrix (§4, §15) —
  `GET /api/xdr/rbac/permissions` already returns `{actions, resources{group}}`,
  which is exactly the "authoritative permission catalog/metadata contract"
  §15 demands the editor derive from.
- Built-in role templates (§5) — 11 exist; 9 map onto the 7 requested.
- Custom roles (§18) and Clone→Custom (§38).
- Access simulator using the production resolver (§20) — `POST /simulate`
  already calls `check_access`, so there is no second algorithm.
- Audit with actor provenance (§29) and a verified-actor rule (§27).
- Separate response authorities (§26) — `response.recommend` /
  `response.approve` / `response.execute` already distinct, and the
  request→approve→dispatch→execute→verify lifecycle is owned by
  `apps/nivxray-xdr-response` + `edr_plane/response.py`. RBAC must **consume**
  it, never re-create it.

---

## 5 · Proposed authoritative model (for owner review — NOT implemented)

### 5.1 Effective access
```
Effective = ⋃ role_permissions(direct role assignments)
          ∪ ⋃ role_permissions(roles inherited via group membership)
          ∪   direct user grants
          −   explicit user restrictions (DENY)
constrained by  tenant  ∩  resource scope  ∩  data scope
```

### 5.2 Precedence (**owner must ratify before RBAC-1**)
```
1. explicit DENY (user-level)          → deny, terminal
2. explicit DENY (group-level)         → deny, terminal
3. explicit ALLOW (direct user grant)  → allow, subject to scope
4. ALLOW via direct role assignment    → allow, subject to scope
5. ALLOW via group-inherited role      → allow, subject to scope
6. default                             → DENY
```
**Conflict to resolve first:** today `check_access` iterates assignments and
allows on the **first** scope-satisfying match (`:441-460`). Introducing a
terminal DENY changes that from "any-allow" to "deny-overrides". That is a
semantic change to a live authorization path and is exactly why the directive
says not to apply a precedence blindly.

### 5.3 Scope semantics
`ScopeSpec` (`:819`) already has `tenant_ids`, `resource_ids`, `environment`.
Only `resource_ids` is honoured, and only when a route declares a
`resource_id_header`. Proposal: keep `ScopeSpec` and add typed scope sets
(`device_groups`, `business_units`, `data_sources`), with the rule that scope
may only ever **narrow**, and an empty typed set means "no constraint of that
kind" — never "none".

### 5.4 Data model deltas (additive)
`xdr_groups` += `roles[]`, `scope{}`, `members[]` (or a join collection)
`xdr_user_grants` (new) — direct ALLOW
`xdr_user_restrictions` (new) — explicit DENY
`xdr_user_roles.scope` — typed scope sets
`users` ⇄ `xdr_users` join per **D-1**

### 5.5 API deltas (additive)
`GET /me/effective` (G-3) · `GET /users/{id}/effective` with per-permission
provenance · group role/scope/member endpoints · grant & restriction
endpoints · `POST /simulate` returning the §20 explanation · a change-preview
endpoint for §21.

### 5.6 Admin IA
`Administration → Access Management → Users · Groups · Roles · Permissions ·
Assignments · Effective Access · Audit`, on `xdr/nx/` primitives, inside the
same SPA.

---

## 6 · Risks
| risk | mitigation |
|---|---|
| Precedence change breaks a live allow path | freeze the contract, then a differential replay of `check_access` old vs new over every existing assignment before switching |
| `users` ⇄ `xdr_users` migration | D-1 first; migration must be additive and reversible |
| Introducing DENY creates a lockout | protect built-in `platform_admin` from self-denial |
| Scope typing changes row visibility | scope may only narrow; assert set-inclusion in tests |
| Frontend caching stale privilege | declare the refresh bound; backend stays authoritative |

## 7 · Test strategy (RBAC-12)
Reuse and extend the existing suites — do not start a new one:
`test_p0sec_rbac_fail_closed.py` (21) · `test_xdr_rbac.py` (14) ·
`test_xdr_rbac_enforcement.py` · `test_p1_min_scope_enforcement.py` ·
`test_d14_tenant_authority.py` · `test_phase2_1_tenant_isolation.py` ·
`tests/edr/test_cross_tenant.py`.
Add the §32 role matrix × §33 adversarial matrix as a new proof script in the
same style as `scripts/p0_w_incident_tenant_authorization_proof.py`.

---

## 8 · STOP
**RBAC-0 complete. RBAC-1 is NOT self-authorised.**

Owner decisions required before RBAC-1:
- **D-1** identity unification: one `users` record, or two with a join key?
- **D-2** ratify the §5.2 precedence, accepting that DENY changes
  `check_access` from any-allow to deny-overrides.
- **D-3** approve the single additive self-scoped endpoint `GET /me/effective`
  (G-3) so the role-aware SPA can be honest rather than hard-coded.
- **D-4** keep live plural permission names (G-8), or migrate to §4's names?
- **D-5** scope kinds to support in RBAC-4: device groups, business units,
  data sources — which are authoritative today?
- **D-6** revocation bound: is "effective on next request" acceptable given
  `users.enabled` must first be enforced in `get_current_user`?
