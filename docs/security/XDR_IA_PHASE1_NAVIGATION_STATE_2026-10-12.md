# XDR IA Phase 1 — Navigation Authorization and Customer-State Safety

Date: 2026-10-12. Base: dashboard branch at `860dc2acaea8efcc25d2bd5747cacb4849f22638` (GitHub and local verified). Isolated branch: `security/xdr-ia1-navigation-state`.

## Result

Existing route declarations, sidebar and Administration taxonomy are retained. Direct XDR destinations now check the existing effective-permissions projection before mounting protected content. Unknown authorization is an unavailable state, never an allow. The undefined guard shell is removed. No role-name comparison grants access in this frontend change.

Console and resource permission checks are separate: Administration requires `console.admin.access`; SOC destinations require `console.soc.access`; Documentation accepts either console. EDR keeps its existing product/session boundary. Existing backend authorization remains authoritative; these checks do not repair a backend bypass.

A shared security context invalidates protected page state on customer changes, session changes and 401/403 responses. Changing its key remounts page-local records, selections, drawers and reveal dialogs, while stale network responses are aborted/fenced. Existing main, collector, response-client and retained E3-preview fetch transports use the same invalidation. Request contracts and credentials are unchanged. A client abort does not undo a server-side mutation; no automatic mutation retries are added.

The effective-permissions cache clears before rereading. A tenant-local result cannot authorize another selected tenant. Authentication no longer optimistically accepts a stored email before `/auth/me` resolves. Login/logout and cross-tab session changes invalidate context. The customer selector uses latest-request-wins fencing and cannot apply a denied result. Server-bound customers cannot be relabeled by an ignored switch. Existing collector/API-key context inputs validate committed edits with the existing scope-selection API; on Enter/blur they request scope before changing context. Client Management row navigation now follows the same authorized selection as its explicit customer-entry action.

Investigation 401/403/cancelled requests stop without fallback to the incident registry. The existing compatibility fallback for non-authorization failures remains. Generic admin section transitions are remounted by destination path, preventing old section payloads or conditional hook state from being reused.

## Permission mapping and limits

The authoritative name catalogue is `backend/routers/xdr_rbac.py::_RESOURCES`. The frontend map is `src/xdr/access/routePermissions.js` (frontend paths are relative to `apps/nivxray-xdr`). Explicit backend `require_permission` checks were inspected for Secrets, Audit, API Keys, Webhooks, Users/Roles, Collectors, Data Sources, Detection Content and Correlation. Other core read mappings use existing resource/action names from the effective permission catalogue; this does NOT certify that every backend endpoint enforces the corresponding resource permission.

| Destinations | Existing capability mapped |
| --- | --- |
| Control Center / incident records / retained dashboard and SOC prototypes | incidents.read |
| Investigations | investigations.read |
| Evidence views | evidence.read |
| Hunting / Event Explorer / legacy search | threat_hunting.read |
| Customers | tenants.read |
| Reports | reports.read |
| Data Sources / Windows | data_sources.read |
| Detections / rule editor / tuning | detections.read |
| Playbooks / automation rules | playbooks.read |
| Approvals | response.approve |
| Intelligence / KB | intel.read |
| Admin audit / secrets / keys / webhooks | audit.read / secrets.read / api_keys.read / webhooks.read |
| Admin content / registry / correlation | lolbas.read / detections.read / correlation.read |
| Admin roles/users | users.read OR roles.read; individual backend operations still enforce their own permission |
| Admin collectors / telemetry health / data onboarding / parsers / normalization | collectors.read / data_sources.read / parsers.read / normalization.read |
| Admin overview / platform health / engines / extensions / intelligence policy / response strategies | platform.read / engines.read / extensions.read / intelligence_policy.read / response.read |

The following admin mappings are intentionally **unavailable**, not guessed from role labels: `corpus`, `agents`, `telemetry-studio`, `response-policies`, `edr-enrollment`, `edr-response`, `edr-capability-truth`. They retain their routes but their page loaders do not mount until a compatible backend capability projection is defined/reviewed. Some are already explicitly disconnected; others have existing functionality but insufficient safe page-capability mapping. UI grouping is not implemented.

Assets, exposure, documentation and legacy EDR pivots lack a compatible asset/endpoint resource-read mapping in the existing XDR permission catalogue. Their existing authentication/product/tenant boundaries remain; XDR console access is checked, but a new backend resource permission is not fabricated. Independent backend review is required for their resource ownership and action authorization.

`/xdr/intelligence/mitre` stays unavailable because XDR-S1 at `f98c964c59e0e85f4bfba6fbbcd3285901317a5a` has not been independently reviewed or integrated into this baseline. No potentially unscoped ATT&CK request was made and XDR-S1 was not merged.

Important backend limitation: `/api/xdr/rbac/me/effective` resolves the user's stored tenant; it does not publish effective permissions for every selected MSSP customer. The frontend now refuses mismatched tenant-local permission reuse, but legitimate multi-customer permission resolution still needs backend work. The backend also retains its declared legacy admin break-glass projection; frontend consumption of that server projection is not independent proof of safe tenant authority. Resource-ID/environment restrictions still require backend enforcement.

## Validation actually run

- `npm test -- --reporter=dot`: **327 passed across 20 suites**. Existing 301 tests plus 26 new tests.
- `npm run build`: **passed**, Vite 5.4.21, 2,276 modules, 4.79 seconds.
- `git diff --check`: passed.
- AST comparison: all **89 route declarations preserved in order** against the verified dashboard base.
- New deterministic tests cover allowed/denied/loading/unknown direct routes without mounting sensitive child content; separate console authority; mapped/unmapped destinations; memory-history Back/Forward; 401/403 and same/cross-tab invalidation; A/B request cancellation and old-denial fencing; latest selection; incident-bound context; locked/denied/applied customer selection; delayed fetch body parsing; tenant-local permission mismatch; investigation denial/cancellation without fallback.
- Existing queue, Preview context, focus, KPI, tenant authority and EDR frontend suites pass.

These tests use synthetic principals/results and in-process adapters; no production credentials, customer data, external API calls, enrollment or endpoint actions were used. The route-rendering tests use server rendering and memory history, not a real browser. They verify gating and invalidation primitives; actual mounted DOM lifecycle, focus, visual behavior and live API integration remain unverified. No claim of authenticated browser acceptance is made.

## Remaining gates

1. Independently review direct-route policy and backend resource ownership, including console access and action permissions.
2. Add/validate a selected-customer effective-permission projection for MSSP operators; validate resource-scoped permissions. Do not silently broaden grants to restore unavailable pages.
3. Independently validate/integrate XDR-S1; keep ATT&CK observations gated meanwhile.
4. Restore approved protected-preview/application test access and verify real mounted pages, drawers, reveal dialogs, rapid changes, direct URLs, refresh/history and keyboard behavior with permitted synthetic tenants/accounts.
5. Mongo-backed negative and integration tests remain separate from these frontend tests. EDR A4/A5 integration and credential hygiene remain separate security gates.

No sidebar regrouping, design changes, new endpoint, backend contract change, agent change, merge, deployment, production configuration change, PR #7 change or security-HOLD removal. STOP after this task.
