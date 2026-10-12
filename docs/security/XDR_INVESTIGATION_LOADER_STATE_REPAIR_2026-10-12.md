# Investigation Engine Security and State Repair

Date: 2026-10-12. Branch: `security/xdr-investigation-loader-state`.
Published parent: `c4ab8526a61b446794533d84f3a29650fd27b2e0` (`security/xdr-ia1-navigation-state`). Verified local baseline tree matches published IA1 tree `cd85bd17cbb3ad37969f9a5cc8ed47de38800be3`. No S1, RBAC2 or EDR integration.

## Change

The case-engine loader previously attempted `/incidents/:id` after any primary failure and manufactured benign/zero defaults for missing verdict data. Secondary evidence failures collapsed into empty results, and local state did not independently fence old asynchronous completions.

The repaired controller:

- Allows compatibility fallback only for the standard absent-route FastAPI response: HTTP 404 with `detail: "Not Found"`. Resource-specific 404 (`case not found`, used by the existing v2 case router), 401/403, cancelled and unknown errors cannot initiate an alternate incident or secondary evidence request. A denied fallback also stops loading.
- Checks fallback incident identity and rejects explicit mismatched case/customer response identity. Missing primary customer context issues no requests. The backend remains responsible for authorization; this frontend check does not replace resource ownership enforcement.
- Preserves real zero scores/confidence; missing verdict, score, confidence and graph counts remain unavailable. Removes the invented fallback engine version. Fixes risk-display operator precedence so zero incident score does not incorrectly disappear or select the device score.
- Tracks primary loading, empty, denied, unavailable, error and ready states. Secondary trajectory/process/artifact/security loaders distinguish loading, confirmed empty collections, unavailable schemas/endpoints, denied and errors.
- Aborts obsolete requests and checks a private controller lifetime plus shared security epoch before committing any result. Scope/session/401/403 invalidation clears records, evidence, drawers and explanation state. Case/profile/customer changes cancel the previous loader. Render-time context masking prevents cached records from rendering in the interval before effect cleanup.
- Keeps routes, tab/profile query contracts, incident pivots, embedded capabilities and API endpoints unchanged. All existing eight engine tab keys remain.

## Files

- `apps/nivxray-xdr/src/xdr/pages/XdrInvestigationWorkspacePage.jsx`
- `apps/nivxray-xdr/src/xdr/pages/investigationLoader.js`
- `apps/nivxray-xdr/src/xdr/pages/__tests__/InvestigationWorkspaceState.test.jsx`
- This validation record.

## Deterministic validation

31 new focused tests cover denied/cancelled/unknown failures; documented compatibility fallback; foreign/missing identity; missing versus genuine zero rendering; secondary loading/empty/denied/error/unavailable states; empty primary; malformed response; missing customer; profile encoding; delayed primary and secondary completion; rapid A/B case/customer switching; logout; shared security invalidation.

Full frontend Vitest run: **358 tests passed in 21 suites** (327 existing plus 31 new). Includes route authorization/history, customer-state, Priority Queue, KPI and incident Preview regressions. Production frontend build: **PASS**. `git diff --check`: PASS. Dependency files unchanged; existing dependency cache was reused after confirming an identical frontend yarn.lock.

Tests use synthetic records, mocked request clients and React server rendering for the actual verdict summary. They do not contact backend/provider/customer services. They test the shared loader controller's asynchronous contract; they do not establish authenticated browser behavior or a live multi-tenant backend result.

## Remaining gates

- Authenticated browser acceptance **BLOCKED / NOT VERIFIED**: no approved test session and protected-preview access remains unavailable. No UI screenshots or visual acceptance claimed.
- Backend resource authorization, selected-customer permissions and Mongo-backed integration remain separate gates. Some payloads do not include customer metadata; stale-response fencing cannot prove backend ownership of such records.
- The narrow absent-route fallback assumes the standard FastAPI response. Other legacy/proxy response formats deliberately fail closed until their contracts are reviewed.
- IOC authentication, MITRE/S1 HOLD, RBAC2, richer graph adoption, landing-page redesign and EDR work remain untouched. No merges, manual deployments or security HOLD changes.

STOP after this repair and its publication.
