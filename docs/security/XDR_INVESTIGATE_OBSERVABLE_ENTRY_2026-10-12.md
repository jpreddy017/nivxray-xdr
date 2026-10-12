# Investigate Phase 1 — Observable Entry

Date: 2026-10-12. Branch: `feature/xdr-investigate-observable-entry`.
Baseline: `security/xdr-investigation-loader-state` at `4c94e40f5d5f886e49e234883624ff364020ddee`, verified through GitHub's branch ref and local fetch. Work isolated in a new worktree. No repository AGENTS.md was present.

## Result

- `/xdr/investigations` presents **Search Evidence** and **Open Existing Investigation**. Existing list, verdict filters, refresh, table and engine workspace routes remain available.
- The labeled native form accepts hostname, endpoint ID, SHA-256, IP, rule ID, incident reference, process name/ID and evidence ID. It opens the existing `/xdr/hunting?q=…` workflow through encoded URL parameters. Identifier type guides input; it does not add a backend type filter.
- Entry requires effective `threat_hunting.read`; unavailable or denied permission disables submission. Existing route permission guards are unchanged. Backend authorization remains authoritative.
- Unsupported domain, URL, email, identity and vulnerability indexes are identified. Hostname inventory search is distinguished from DNS search. No match is not a benign verdict. No external enrichment is requested.
- Reused existing shell, design tokens, card/table components and responsive form wrapping. Reviewed the saved Enterprise UI Blueprint's guidance on compact hierarchy, accessible controls, honest states, and reuse; this does not establish pixel-level acceptance of an Investigate mockup.

## Request and state protections

Both list and Hunting reads now use a cancelable controller and security-epoch fencing. Cached data is masked during render when query/revision, selected customer or security epoch changes. Delayed completions cannot publish after cleanup or scope/session invalidation, even if a transport ignores abort. Denied/expired/session states prevent automatic retry in the same invalidated context. The new entry resets with list context changes.

Hunting clears old results during a new query, retains direct `q` links, supports retrying the same term, resets selection/type filters with search context and keeps capability failures distinct from an empty capability set. Malformed search payloads fail visibly. Empty/denied search states never expose returned rows. Existing result links continue through existing routes and permission checks.

The list retains its successful-empty-case-list incident projection. Failure-triggered compatibility fallback is now allowed only for the documented FastAPI `404` with `detail: Not Found`; 401/403, other 404s, server/transport failures, cancellations and malformed responses fail closed. Incident-read failures remain visible instead of becoming empty lists. Two assertion shapes and the documented 404 fixture were updated in the existing route regression suite; permission logic was not changed.

## Validation

- Full frontend Vitest: **403 tests passed, 22 suites**, including **45 new tests**.
- Production frontend build: **PASS**.
- `git diff --check`: **PASS**.
- Tests cover supported/unsupported inputs, SHA validation, encoded direct links, labeled native form markup and unavailable/denied permission notices, delayed completion after scope/session/denial/expiry, cancellation, rapid replacement, HTTP failures without alternate requests, empty/denied/malformed results, list fallback and genuine zero preservation.
- Tests use synthetic fixtures, mocked clients and React server rendering. They do not establish mounted-hook/browser behavior, backend ownership or live two-tenant isolation.
- Dependency manifests/lockfiles unchanged. Reused a local dependency cache after confirming identical frontend yarn.lock.

## Browser acceptance and remaining gaps

**BLOCKED / NOT VERIFIED.** Local Playwright launch failed because its Chromium headless-shell executable is absent. No approved authenticated preview session was established. No desktop/mobile screenshots were produced; interactive Tab/Enter navigation, back/forward behavior, responsive layout and mounted customer switching remain browser acceptance items. Native form semantics and labeled controls are implemented and statically tested, not claimed as keyboard acceptance.

The existing backend search resolves the principal's authorized customer scope; it does not narrow results to the selected customer header. The UI states this explicitly. Client-side invalidation does not prove backend isolation. Search remains bounded by the existing backend's per-group limits (10); there is no new pagination, external intelligence, saved hunt or query language.

Graph relationships, richer timelines and observable-specific workspaces remain future work. No fabricated nodes/events, IOC endpoint integration, MITRE unlock, backend contract, RBAC-2 implementation, EDR implementation or security HOLD changes. No merge or manual deployment. Publication is an engineering milestone, not release approval.

STOP after this phase and publication.
