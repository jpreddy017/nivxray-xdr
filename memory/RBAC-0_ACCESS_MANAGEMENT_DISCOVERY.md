# RBAC-0 · ACCESS MANAGEMENT DISCOVERY (Program D, Lane 4)

Read-only discovery, 2026-06. **No authorization code was changed to produce
this document.** Every row states what the platform authoritatively has today
and classifies it `ADOPT | EXTEND | REPAIR | BUILD | MIGRATE-LATER`.

Principle being designed to: **No access without authority. No privilege
without provenance.** UI visibility is never enforcement; the backend decides.

Authoritative sources read: `backend/routers/xdr_rbac.py` (1,600 lines),
`backend/routers/auth.py`, `backend/routers/collector_authz.py`,
`apps/nivxray-xdr/src/xdr/access/*`, `XdrShell` rail gating.

---

## 1 · WHAT EXISTS TODAY

| Concern | Authoritative today | Verdict | Notes |
|---|---|---|---|
| **Authentication authority** | `routers/auth.py` — JWT bearer, `/api/auth/login`; collector plane authenticates separately (`collector_authz.py`, API key/HMAC) | **ADOPT** | Two planes deliberately: a human principal and a machine collector are different authorities and must stay different |
| **Tenant authority** | Server-resolved scope (`/api/xdr/scope/authorized`, `/scope/select`); header spoofing rejected; `TENANT_REQUIRED` fail-closed 403 observed live on `/api/xdr/cve/*` | **ADOPT** | Tenant resolution already happens BEFORE privilege evaluation, which is the required order |
| **User model** | `xdr_rbac` users collection · `{id, email, enabled, tenant_id}` · full CRUD (`/rbac/users`) | **EXTEND** | Needs group membership + direct grants + restrictions on the read model |
| **Role model** | 11 built-in roles (`role_builtin_platform_admin`, `tenant_admin`, `soc_manager`, `l3_investigator`, `l2_investigator`, `l1_analyst`, `threat_hunter`, `detection_sme`, `responder`, `auditor`, `read_only`) + custom roles, clone, enable/disable | **ADOPT** | Wildcards (`users.*`, `*.*`) expand through `_expand_wildcard`; `_NO_WILDCARD_PERMISSIONS` already fences the dangerous ones |
| **Permission catalog** | 33 resources × declared actions, `CONSOLE_PERMISSIONS` for console access, `/rbac/permissions` publishes it | **ADOPT → FREEZE** | The catalog exists and is served; it must be frozen as the contract every surface cites |
| **Assignments** | `user → role` with `scope.resource_ids` | **EXTEND** | Scope is a resource-id allow-list only; tenant/resource-class scope needs modelling |
| **Groups** | `xdr_groups` collection + `/rbac/groups` list/create/delete | **REPAIR** | **VERIFIED GAP.** A group document is `{id, tenant_id, name, description, created_at, created_by}` — it has **no members field and no roles field**, and `_resolve_user_permissions()` reads the assignments collection only. A group therefore cannot contain anyone and cannot grant anything: it is a label that *looks* like authority. This is the single biggest correctness gap in Program D |
| **Direct grants** | — | **BUILD** | No `direct_grant` / `additional_access` concept anywhere |
| **Direct restrictions** | — | **BUILD** | No `restriction` concept anywhere; there is therefore no way to express DENY |
| **Effective access resolver** | `_resolve_user_permissions()` → union of enabled roles' expanded permissions; `check_access()` returns `{allow, reason, matched_role, matched_permission, effective_permissions, scope_ok}` | **EXTEND** | Already returns a REASON and the matched role — the provenance spine exists. Must grow: group path, direct grant path, restriction precedence |
| **Route/API enforcement** | `require_permission()` dependency; fails closed (P0-SEC suites 21/21 + 14/14) | **ADOPT** | Do not touch without a separate security decision |
| **Component/route authorization (UI)** | `AccessProvider` + `useAccess`, rail `requires` metadata | **ADOPT** | Presentation only — already correct in principle |
| **Response authorization** | `response.execute` / `response.approve` separated; P0-1 gates 37 PASS | **ADOPT · FENCED** | Separation of duties proven. **Do not modify while doing Access Management work** |
| **Access Simulator** | `/rbac/simulate` — non-mutating, emits `ACCESS_SIMULATED` audit | **ADOPT → SURFACE** | The backend capability already exists; there is no UI for it |
| **Audit** | `xdr_audit_log`, hash-chained; RBAC changes and simulations emit events | **ADOPT** | Needs a surface, not a rebuild |
| **Session context** | `/rbac/me/effective`, `/rbac/session-context` | **ADOPT** | The SPA can render explainable access without a new endpoint |
| **Revocation behaviour** | `enabled=false` denies at check time (`user-disabled`) | **EXTEND** | Token lifetime vs revocation instant is not yet proven; needs a test |
| **Tenant isolation** | Cross-tenant incident IDOR closed; cross-tenant RBAC regression suites pass | **ADOPT** | Admin is a functional superset, NOT a tenant bypass — keep it that way |

---

## 2 · THE FOUR-SENTENCE EXPLANATION (target contract)

`check_access()` already carries `reason` + `matched_role`, so the required
explanation shape is reachable without inventing a second engine:

```
ALLOWED   ↳ SOC Analysts (group)  ↳ SOC Analyst Role  ↳ alerts.update
ALLOWED   ↳ Direct grant          ↳ granted by admin@… on 2026-06-04
DENIED    ↳ Explicit restriction  ↳ response.execute withheld
DENIED    ↳ No applicable grant
```

Required resolver precedence (to be frozen before any UI consumes it):

1. tenant resolution (already first — keep it first);
2. explicit **restriction** → DENY, always wins;
3. **direct grant** → ALLOW;
4. **group → role → permission** → ALLOW;
5. **direct role assignment → permission** → ALLOW;
6. otherwise DENY `no-applicable-grant`.

Every decision must return the path that produced it. A decision without a
path is a bug, not a default.

---

## 3 · WORK ORDER (no checkbox UI first)

| # | Item | Class | Why first |
|---|---|---|---|
| D-A | **Freeze the permission catalog** as the published contract (`/rbac/permissions`) | ADOPT | Every later surface cites it; freezing prevents each page inventing labels |
| D-B | **Give groups membership + role binding, then resolve through them** | REPAIR | Verified: the group document has no members and no roles, so it grants nothing today. Until this is repaired, no Access Management UI may show a group as a source of access. Correctness defect, not a feature |
| D-C | Extend the resolver to return the **decision path** | EXTEND | Prerequisite for every "explain this permission" view |
| D-D | Model **direct grants** and **direct restrictions** with restriction precedence | BUILD | The only way to express DENY |
| D-E | Resource/tenant **scope model** beyond a resource-id allow-list | EXTEND | Needed for MDR-style per-customer analysts |
| D-F | Administration ▸ **Access Management** IA: Users · Groups · Roles · Permissions · Assignments · Effective Access · Audit | BUILD | UI comes AFTER the contract |
| D-G | User detail: Overview · Groups · Roles · Additional Access · Restrictions · Scope · Effective Access · Audit History | BUILD | |
| D-H | Surface the existing **Access Simulator** | SURFACE | Backend already non-mutating + audited |
| D-I | **Revocation / session** proof: disabled user and revoked role deny within one request | EXTEND | Must be a test, not a claim |
| D-J | Privilege-escalation protection: no principal may grant itself more than it holds | BUILD | Explicit test required |
| D-K | Cross-tenant regression on every new grant path | EXTEND | Reuse the existing suites |

---

## 4 · FENCES FOR THIS LANE

- `require_permission()` and the response-authority gates are **NOT** in scope
  for refactoring; extending the resolver must not weaken either.
- Response permissions stay distinct (`response.read | request | approve |
  execute | verify`) per the catalog that gets frozen in D-A.
- T-RISK-3 remains **HELD**; T-RISK-4/T-RISK-5 remain tracked and are **not**
  to be mixed into Access Management changes.
- No UI gate may be presented as enforcement anywhere in the delivered work.
