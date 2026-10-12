# NivXRay XDR — Combined RC1 Integration

Date: 2026-10-12. Branch: `release/xdr-rc1-integration`. **Release status: NO-GO.** This is a review candidate with one deliberately retained failing negative test, not an approved deployment.

## Production and ancestry

Vercel inspection in this task confirms `xdr.nivxforge.com` aliases READY production deployment `dpl_7f2hrNr5pwTpEqJiJCyavPBJQVrP`, project `nivxray-xdr-production`, commit `e2f15a252630e478c5667f9e1d883a02acad1a1c` on `release/xdr-b8-selector-candidate`. Domain: https://xdr.nivxforge.com/. No production alias, deployment or configuration was changed.

| Source | Verified published HEAD | Relationship / RC treatment |
|---|---|---|
| Production release | e2f15a252630e478c5667f9e1d883a02acad1a1c | Direct RC parent; preserves production-only B8 changes |
| Dashboard | 860dc2acaea8efcc25d2bd5747cacb4849f22638 | Six dashboard commits above E3 258c8854; only their 14-file XDR delta adopted |
| IA1 | c4ab8526a61b446794533d84f3a29650fd27b2e0 | Parent dashboard; approved XDR guards/state files adopted once |
| RBAC2 | bce968b19ab33a19df4b7d8bba7ba2014c262359 | Parent IA1; one backend repair/test/report delta adopted once |
| Investigation loader | 4c94e40f5d5f886e49e234883624ff364020ddee | Parent IA1; separate loader/test/report delta adopted once |
| XDR-S1 | f98c964c59e0e85f4bfba6fbbcd3285901317a5a | Parent dashboard; excluded, MITRE frontend guard stays unavailable |

Production and dashboard diverge at `6523ba1d229004abc38f23a9d36be8d278e65e99`. The four production-only B8 commits modify only AdminTenantGate and XdrScopeNavigator. Their authority-derived `authorized_tenants` selector behavior and display labels already exist in the IA1 versions and are preserved together with request fencing.

A wholesale merge of dashboard/E3 into the release branch would also introduce hundreds of unrelated agent, EDR and experimental files. RC1 instead composes the approved XDR file deltas onto production. Published repair commit ancestry is recorded above, not falsely claimed as Git merge ancestry. Local counterparts were verified against published tree identities; no duplicate cherry-picks or upstream branch rewrites.

## Integration decisions and dependencies

- Dashboard queue/KPI/Preview/grid changes retained; IA1 request/privacy infrastructure retained; RBAC2 and loader repairs touch separate files and do not overwrite each other.
- App.jsx uses IA1's guards but retains production's existing `EdrDeviceTrajectoryPage` import and destination. No E3 contract-preview entry is imported.
- All route path declarations match production and IA1 in order. Fresh extraction counts **90 literal paths including root**; earlier reports called the inventory 89. This is a counting discrepancy, not a new/removed route.
- Shared prerequisites reused from verified E3 source: `dashboard_lenses.py` retires role-name tenant breadth; `session_context.py` supplies active authority-derived customers; `xdr_scope.py` publishes `authorized_tenants`. Without them the production B8 selector expects a field absent from the old scope endpoint, and RBAC would retain an incompatible role-derived authority substrate.
- `tenant_registry.py` gains only the existing mandatory `authoritative_required` entry and constant, needed by RBAC2 and the authorized-customer projection. The production legacy `authoritative` function's AST is unchanged; its environment-gated behavior is not silently migrated.
- Existing package.json/yarn.lock test tooling is reused. No new packages or dependency versions were designed for RC1.
- No source changes in agents/, backend EDR planes/services/routers, frontend nivxforge/, collector/response services, CI workflows or production configuration. Shared customer-context functions have existing EDR consumers; their integration impact still requires review even though EDR implementation files and branches are unchanged.
- IA1's E3-only request wrapper is excluded because the experimental E3 module is absent from production. An E3-only tenant test depending on an absent EDR module was not adopted; existing production tests were not deleted. New XDR integration tests cover the shared tenant binding.

No textual merge conflict required a new security-policy choice. One contract mismatch remains intentionally unresolved below; no authorization bypass was added to make tests pass.

## Fresh validation

| Check | Result |
|---|---|
| Full frontend suite on production-based RC | **117 passed, 9 suites** |
| New frontend cross-feature suite | **5 passed**; direct engine-route projection A/B/C, 401/403, delayed scope invalidation and locked tenant binding |
| Investigation loader regressions | **31 passed**, included above |
| Backend RBAC2 + D14 + new cross-feature tests | **117 passed, 1 failed**, 118 total |
| Existing RBAC2/D14 subset | **112 passed** |
| New backend cross-feature suite | **5 passed, 1 failed** |
| Frontend production build | **PASS** |
| Changed Python source AST parsing | **PASS** |
| Whitespace/diff checks | **PASS** |
| Route paths and production EDR destination preservation | **PASS**, source-level comparison |
| Mongo/live backend integration | **NOT RUN** |
| Authenticated browser / desktop-mobile visual acceptance | **BLOCKED / NOT VERIFIED** |

The frontend count is not 358: the production-based RC excludes E3's unrelated EDR implementation/test suites. This is a different test inventory, not a claim that those tests failed or were rerun.

Commands:

```text
npm test --prefix apps/nivxray-xdr
npm run build --prefix apps/nivxray-xdr
MONGO_URL='' PYTHONPATH=backend python -m pytest --noconftest -o addopts='' backend/tests/test_xdr_rc1_integration.py backend/tests/test_rbac_selected_customer.py backend/tests/test_d14_tenant_authority.py --tb=short -q
```

Backend fixtures replace data stores with synthetic A/B/C records, use test-generated authentication and block socket connections. Frontend clients are mocked; React server rendering verifies direct guards and verdict presentation. These do not certify a full browser-to-live-Mongo flow. One Starlette/httpx deprecation warning occurred.

## Confirmed blocker: inactive scope disagrees with permissions

**P1 contract/security inconsistency.** `backend/services/session_context.py::effective_scope` builds a validated active `universe`, but its selected-tenant branch authorizes against raw `tenant_ids` grants instead. A granted but SUSPENDED Tenant B is therefore selectable, while `xdr_rbac.selected_customer` rejects it using mandatory registry authority.

Safe deterministic reproduction: `backend/tests/test_xdr_rc1_integration.py::test_inactive_customer_selection_and_rbac_must_agree` sets only synthetic B's state to SUSPENDED. `/api/xdr/rbac/me/effective` for B returns 403; POST `/api/xdr/scope/select` for B returns 200 instead of expected 403. The negative test remains failing, without skip/xfail or relaxed assertions. This proves a projection mismatch, not a live data leak.

Recommended separate minimum repair: align selected/group/all-authorized/incident-bound scope authorization in `backend/services/session_context.py` with the active authorized universe, fail closed on registry failures, and preserve locked incident behavior. Add inactive/unknown customer and organization-down cases for each scope kind; ensure the existing RBAC dependency and projection agree. Requires explicit follow-up implementation instruction and independent review; not silently repaired during RC assembly.

Incident-bound scope tests confirm that requesting B while in an A incident is rejected (403, locked); explicitly requesting A succeeds. The initial test expected automatic A substitution; that expectation was corrected to the actual, safer denial contract, with no application change.

## Remaining HOLDs and preview requirements

- Independent authorization review and the failing scope-selection gate.
- Mongo-backed membership/resource ownership, negative A/B/C cases, group grants, audit persistence and broader backend regression.
- RBAC2's legacy/global-admin, global role mutation, console projection and all-authorized aggregate migration gaps remain open. The frontend guard is not backend enforcement.
- XDR-S1 remains separate. The RC backend still has the baseline observation query; the UI remains blocked. Direct API exposure is not secured by a frontend HOLD. Independent S1/Mongo review is required before enabling observations or making a release claim.
- IOC authentication gap, credential hygiene and response security HOLDs are not closed by RC1. EDR A4/A5 and PR #7 are excluded and untouched.
- Provisioning must use a dedicated approved staging backend/database and synthetic A/B/C. Login `users` records and RBAC `xdr_users` memberships are separate; creating one alone is insufficient. Use existing supported roles/grants, explicit customer entitlements and no role-name authority shortcut. No accounts were created.
- Protected preview requires the approved Vercel project/team connection, deployment linked to this exact RC commit, and approved application test sessions. Vercel access and application login are separate. Do not disable protection or paste credentials. Verify backend origin and synthetic database bindings before testing.
- Administrator, Analyst-A and MSSP-A/B browser acceptance must include refresh/history, direct routes, denied APIs, scope changes, session expiration, pending replies and genuine desktop/mobile screenshots. C remains unauthorized. No browser acceptance or screenshots claimed.

RC has **no manual deployment**. Publishing the branch/draft PR may trigger normal Git preview builds; their existence is not production promotion or browser approval. The verified production deployment remains the e2f15a25 deployment above.

## Rollback / promotion contract

Before any future promotion, record the exact approved staged production deployment, frontend/backend pairing, test-account isolation, owner/security approvals and production configuration revision. Preserve deployment `dpl_7f2hrNr5pwTpEqJiJCyavPBJQVrP` and SHA e2f15a25 as the currently observed frontend rollback reference. RC1 contains no data migrations; any later backend release needs its own compatible rollback plan. Never restore weakened authentication merely to regain access after grant migration.

No-Go until the failing scope contract, security review, Mongo tests, approved account provisioning and authenticated UI acceptance are satisfied. A future production promotion requires explicit owner approval of the exact release commit/build. STOP after RC preparation.

## Exact changed-file inventory

- `apps/nivxray-xdr/package.json`
- `apps/nivxray-xdr/src/App.jsx`
- `apps/nivxray-xdr/src/lib/__tests__/securityState.test.js`
- `apps/nivxray-xdr/src/lib/api.js`
- `apps/nivxray-xdr/src/lib/auth.jsx`
- `apps/nivxray-xdr/src/lib/customerSelection.js`
- `apps/nivxray-xdr/src/lib/requestFence.js`
- `apps/nivxray-xdr/src/lib/secureRequests.js`
- `apps/nivxray-xdr/src/lib/securityState.js`
- `apps/nivxray-xdr/src/lib/tenant.js`
- `apps/nivxray-xdr/src/main.jsx`
- `apps/nivxray-xdr/src/xdr/XdrShell.jsx`
- `apps/nivxray-xdr/src/xdr/access/AccessProvider.jsx`
- `apps/nivxray-xdr/src/xdr/access/RequirePermission.jsx`
- `apps/nivxray-xdr/src/xdr/access/__tests__/Rc1CrossFeature.test.jsx`
- `apps/nivxray-xdr/src/xdr/access/__tests__/RouteSafety.test.jsx`
- `apps/nivxray-xdr/src/xdr/access/routePermissions.js`
- `apps/nivxray-xdr/src/xdr/admin/AdminTenantGate.jsx`
- `apps/nivxray-xdr/src/xdr/admin/ApiKeysBody.jsx`
- `apps/nivxray-xdr/src/xdr/admin/CollectorsBody.jsx`
- `apps/nivxray-xdr/src/xdr/admin/CustomerContextInput.jsx`
- `apps/nivxray-xdr/src/xdr/admin/collectorApi.js`
- `apps/nivxray-xdr/src/xdr/components/XdrScopeNavigator.jsx`
- `apps/nivxray-xdr/src/xdr/nx/NxDataTable.jsx`
- `apps/nivxray-xdr/src/xdr/nx/NxFlyout.jsx`
- `apps/nivxray-xdr/src/xdr/nx/nx-cc.css`
- `apps/nivxray-xdr/src/xdr/pages/PriorityIncidentQueue.jsx`
- `apps/nivxray-xdr/src/xdr/pages/SecurityOverviewKpis.jsx`
- `apps/nivxray-xdr/src/xdr/pages/SelectedIncidentContext.jsx`
- `apps/nivxray-xdr/src/xdr/pages/XdrClientManagementPage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/XdrControlCenterPage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/IncidentPreviewFocus.test.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/InvestigationWorkspaceState.test.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/PriorityIncidentQueue.test.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/SecurityOverviewKpis.test.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/SelectedIncidentContext.test.jsx`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/controlCenterState.test.js`
- `apps/nivxray-xdr/src/xdr/pages/controlCenterState.js`
- `apps/nivxray-xdr/src/xdr/pages/investigationLoader.js`
- `apps/nivxray-xdr/src/xdr/respond/responseEngineApi.js`
- `apps/nivxray-xdr/yarn.lock`
- `backend/routers/xdr_rbac.py`
- `backend/routers/xdr_scope.py`
- `backend/services/dashboard_lenses.py`
- `backend/services/session_context.py`
- `backend/services/tenant_registry.py`
- `backend/tests/test_rbac_selected_customer.py`
- `backend/tests/test_xdr_rc1_integration.py`
- `docs/releases/XDR_RC1_INTEGRATION_2026-10-12.md`
- `docs/security/XDR_IA_PHASE1_NAVIGATION_STATE_2026-10-12.md`
- `docs/security/XDR_INVESTIGATION_LOADER_STATE_REPAIR_2026-10-12.md`
- `docs/security/XDR_RBAC2_SELECTED_CUSTOMER_2026-10-12.md`
