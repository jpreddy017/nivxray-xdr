# XDR RBAC-2 — Selected-Customer Permission Repair

Date: 2026-10-12. Isolated branch: `security/xdr-rbac2-selected-customer`.
Authoritative base: GitHub `c4ab8526a61b446794533d84f3a29650fd27b2e0`, reference branch `security/xdr-ia1-navigation-state`. Its source tree `cd85bd17cbb3ad37969f9a5cc8ed47de38800be3` matches local authored counterpart `d00e3fc809c5f2995c16d9899775afa9f4df901e`; local worktree uses the identical source counterpart because shell GitHub authentication is unavailable. Published repair has the authoritative GitHub commit as its parent. No merge into any existing branch.

## Exact defect

`require_permission` previously called `check_access(user.tenant_id, ...)`, while tenant-scoped handlers separately resolved caller-selected customer through `resolve_principal`. A verified principal entitled to A+B could therefore operate on B using A's grants. `/api/xdr/rbac/me/effective` likewise projected home-tenant permissions irrespective of selected customer. A stored `role=admin` shortcut skipped granular permission evaluation entirely in both paths.

## Repair

Changed source: **backend/routers/xdr_rbac.py**.

- Shared `selected_customer` resolves the authenticated subject's request before permission or projection lookup. Header, query and top-level JSON tenant/customer claims must agree; duplicates with different values, blank/non-string claims, unauthorized customers and invalid JSON are rejected. Nested role-assignment scope fields are constraints, not customer selectors, and are not repurposed as authority.
- Customer requests are intersected with persisted identity grants through existing `authorize_requested_tenant`, then checked against the mandatory ACTIVE tenant/organization registry using `authoritative_required`. No default tenant or role-derived customer breadth is introduced. Registry failure fails closed.
- No explicit selector uses the stored home tenant as a compatibility *request*; it must still be granted and ACTIVE. A single explicit grant without a home resolves to that customer. Multiple grants without a selector/home fail closed. This preserves legitimate single-customer behavior, not legacy unregistered/default customers.
- The validated principal/customer are stamped in server-owned request state. Tenant-scoped handlers using `resolve_principal` consume exactly this context; verified actor attribution and non-authoritative client identity claims remain distinct.
- `require_permission` evaluates selected-customer membership, roles, direct/group grants and restrictions using the existing `check_access`/access-authority resolver. `/me/effective` uses that same selected customer and returns the existing response shape/basis fields. It returns empty permissions for missing/disabled memberships; protected operations deny them. Disabled authenticated records are denied.
- Human `role=admin` shortcuts are removed from these two paths. Explicit PLATFORM designation determines customer breadth only; it does not replace local RBAC membership/grants. Existing bootstrap/global-admin identities lacking those grants will be denied and require explicit migration before rollout. No workaround or provisioning occurred.
- An unambiguous route resource ID is the permission target. An optional resource header cannot substitute another route ID. Resource-ID-limited role/direct grants cannot authorize unbounded calls by omitting the ID. Ambiguous multi-target endpoints need explicit migration, not guessed ownership.
- Tenant/permission/claim denials retain audit paths. Tests replace audit persistence only with an in-memory recorder; actual audit backend availability/tamper verification is not certified here.
- API-key authentication, signature/digest verification, binding, scopes, quotas and credential-ambiguity rejection are unchanged. Agent/service code is unchanged.

## Test evidence

Changed tests: **backend/tests/test_rbac_selected_customer.py**.

Executed:

```text
MONGO_URL='' PYTHONPATH=backend python -m pytest --noconftest -o addopts='' \
  backend/tests/test_rbac_selected_customer.py \
  backend/tests/edr/test_p0_tenant_authority_fix6b2.py \
  backend/tests/edr/test_p0_tenant_authority_fix5a.py \
  backend/tests/test_d14_tenant_authority.py -q
```

**210 passed**: 36 new RBAC tests and 174 existing tenant-authority/normalization regressions. One Starlette/httpx deprecation warning; no failures. Syntax compilation and `git diff --check` passed. Existing EDR regression files were run, not modified.

The new tests use real JWT subject verification, the actual RBAC dependency/projection, the existing tenant-authority and access resolvers, and an actual tenant-scoped RBAC membership/effective handler. Storage, audit recorder and registry records are synthetic in-memory data; rate limiter is stubbed for key-binding tests. Socket connection attempts are blocked in the new suite. No application-server startup, external service, production credentials, actual account/tenant creation, persistent records or customer evidence.

Coverage: A allowed/B denied for the same permission; A/B projections differ; C/unknown/forged customer denial; header/query/body conflicts; duplicate headers; missing/disabled memberships and roles; principal disablement; role-label and signed-token claim spoofing; revoked grants/restrictions without stale permissions; registry/organization/store failure; foreign/nonexistent membership IDs with equivalent 404s; foreign membership mutation leaving records unchanged; resource scopes/header conflicts; unchanged valid-key binding, foreign-key tenant denial and ambiguous credentials; audit path retention.

Baseline sensitivity: the same A/B negative test was run against the unchanged IA1 source counterpart. It **fails because the B request returns 200 instead of 403**, while A succeeds. No live cross-tenant exploit is claimed.

## Call-site review and migration limits

| Existing area | Effect / outstanding work |
| --- | --- |
| RBAC membership endpoints; xdr_access actor resolver | Shared dependency/context now aligns selected permission and actor customer. The real user-effective handler is covered by deterministic ownership tests. Broader group/grant management still needs Mongo-backed negative integration. |
| xdr_secrets, xdr_api_keys, xdr_webhooks, xdr_collectors, xdr_data_sources | Existing require_permission + resolve_principal handlers inherit the shared context. Existing tenant-filtered resource lookup must remain intact. Full CRUD integration was not executed. |
| xdr_detection_content, xdr_correlation and other require_permission consumers | Dependency now checks selected customer. Handlers must still be reviewed for actual query/resource ownership; dependency alone does not certify their data access. |
| xdr_rbac role definitions (`_role_by_id`, create/update/clone/delete roles) | Definitions are stored globally without tenant ownership; a selected local grant cannot itself establish authority to mutate a global/shared definition. Review ownership and global-governance policy separately. Role creation validates permission names but needs independent grant-escalation review. **Do not treat global role mutation as tenant-isolation-closed.** |
| deps.require_admin; routers/admin.py; admin_aggregations.py | Legacy role-based global operations remain unmigrated. Global /admin/users and statistics do not become tenant-scoped through this patch. Customer admin compatibility remains incomplete. |
| xdr_rbac.console_authorization; xdr_scope console projection; legacy session/context consumers | Their separate home/role-based projection remains unchanged and may disagree with stricter require_console/permission enforcement. Must migrate before claiming full multi-customer console consistency. |
| Incident read/write helpers | Existing tenant authority is separate. `_require_incident_write` calls check_access with incident customer but without a resource ID; resource-limited grants now deny such unbounded calls. Pass authoritative incident IDs in a separately reviewed migration. |
| xdr_mss and other get_current_user/get_current_user_optional-only aggregate/read routes | Do not automatically acquire selected-customer RBAC by this patch. All-authorized cross-customer aggregation needs per-customer permission enforcement; no union/intersection projection is invented here. |
| xdr_tenancy organization/tenant management | Global registry operations need explicit global ownership/governance review; membership in a selected tenant is not proof of authority over every organization. |
| Singular collector ownership; standalone collector; webhook | A4/A5 remain independent branches. Their fixes were not merged and their broader ownership/replay gates are not closed here. |
| Agent/service authentication | Unmodified; machine branch retained. Endpoint acceptance, service infrastructure and key quota behavior remain separate validation gates. |

## Rollout requirements / compatibility

This is an isolated engineering fix, not production approval. Existing bootstrap admins without tenant-local membership/console grants will no longer bypass the repaired dependency; users pointing at unregistered legacy customers will fail mandatory registry validation. Resource-limited callers omitting authoritative target IDs may now be denied. These are deliberate fail-closed behavior changes requiring an approved migration/negative-test plan, not a reason to restore a bypass.

Mongo-backed RBAC CRUD, audit-chain persistence, full backend regression, legacy global-admin and role-definition ownership, global registry policy, selected-customer console projection and cross-customer aggregate endpoints remain outstanding. Existing Mongo/live suites were not run because no approved isolated database/environment exists and those suites can seed/delete records or use live credentials.

Frontend unchanged. IA1 already sends selected tenant headers and invalidates its cached projection; actual browser behavior with A/B roles remains unverified. Protected preview/application access and safe test provisioning remain blocked prerequisites. XDR-S1 ATT&CK repair stays separate and its integration HOLD remains. No accounts, tenants, seed scripts, EDR branches, PR #7, production configuration, merge, deployment or security HOLDs were changed.

STOP after RBAC-2. Independent review and migration validation must precede staging account provisioning or production consideration.
