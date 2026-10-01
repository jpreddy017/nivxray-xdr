# Analyst RBAC provisioning — proven in preview, runbook for production

**Date**: 2026-09-09 · Preview only, by owner ruling. **No production user was
created and no collector was enrolled.**

## What was done (preview)

`POST /api/xdr/rbac/users` as authenticated admin, targeting tenant
`nivx-live` via `X-Tenant-Id` (the header now selects the *target tenant* for
an admin operation — it can no longer establish identity, P0-SEC):

```json
{"email": "analyst@nivx-live.com",
 "display_name": "NivX Live L1 Analyst",
 "initial_roles": ["l1_analyst"]}
```
Result: `usr_3b5131f04d96447dada7`, `tenant_id: nivx-live`, `enabled: true`,
assignment `asg_0aebedc246154082a64b` → `role_builtin_l1_analyst`.
No code change was required.

## Before / after evidence

| request (as `analyst@nivx-live.com`) | before | after |
|---|---|---|
| `GET /api/xdr/rule-studio/rules` (`detections.read`) | **403** `user-not-provisioned` | **200** rules returned |
| `GET /api/incidents` (`incidents.read`) | 200 (different gate) | **200** |
| `GET /api/xdr/collectors` (`collectors.read`) | **403** `user-not-provisioned` | **403** `permission-not-granted` |
| `GET /api/xdr/secrets` (`secrets.read`) | **403** `user-not-provisioned` | **403** `permission-not-granted` |

The denial *reason* changing from `user-not-provisioned` to
`permission-not-granted` is the least-privilege proof: the principal is now
known to RBAC and is refused precisely the permissions `l1_analyst` lacks.

Effective permissions (11, exactly the built-in set): `alerts.ack`,
`alerts.assign`, `alerts.read`, `correlation.read`, `detections.read`,
`evidence.read`, `incidents.read`, `intel.read`, `investigations.annotate`,
`investigations.read`, `lolbas.read`.

## Tenant isolation — verified, not assumed

- `admin@nivxray.com` sees **327** incidents; `analyst@nivx-live.com` sees
  **1**. Direct Mongo count of `workspace_cases{doc_type:"xdr_incident"}` by
  tenant: `default` 272, `p0f-vt` 2, **`nivx-live` 1**, `p0f-d9950a8a` 1,
  `p0f-832e5ddd` 1 — the analyst sees exactly its own tenant's single incident.
- Cross-tenant attempt `GET /api/incidents?customer=default` as the nivx-live
  analyst → `200` with `count: 0` and
  `scope: {"authorized": true, "cross_tenant_denied": true}`.
- `analyst@default.com` (other tenant) is **unaffected**: still `403
  user-not-provisioned` on rule-studio. The grant did not leak.
- Response bodies do not project `tenant_id` (it read as `null`), so isolation
  was proven by counts and the DB distribution rather than that field.

## Production runbook (owner-driven UI, agent stays unauthenticated)

Prerequisite that does **not** exist yet: production has **no analyst users**.
`seed_admin()` creates only `admin@nivxray.com`, and there is no registration
or admin-create-user API — so production user lifecycle is a separate,
deliberate decision.

Once a production analyst account exists:
1. Sign in to `xdr.nivxforge.com` as `admin@nivxray.com` →
   **Administration → RBAC → Users**.
2. Create the user with the tenant set to that analyst's tenant, assigning
   **`l1_analyst`**.
3. Confirm the effective-permissions panel lists the 11 permissions above.
4. Send screenshots; the agent verifies read-only/unauthenticated only.

Do not grant `tenant_admin` (30 permissions) for a SOC L1. Escalate to
`l2_investigator` (16) only when respond-lite is genuinely required.
