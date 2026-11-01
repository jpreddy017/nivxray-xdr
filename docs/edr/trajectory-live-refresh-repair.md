# Device Trajectory live refresh — 2026-11-01

## Problem and behaviour

The production V3 page only read trajectory on mount, range changes or manual retries, and captured its default end time once. Newly processed activity could remain invisible after the initial page read. Polling the old fixed end time alone would still miss later activity.

The page now refreshes ten seconds after a completed read while visible and advances the default live time range. Explicit historical bounds remain fixed and refresh within that range, allowing recovered historical activity to appear. Navigator selections touching the current time opt into following now; event deep links retain a fixed inspection range.

Background reads preserve displayed evidence. Request generation and cancellation guards reject stale responses on scope changes. Polling pauses for details, loaded older pages, hidden tabs and read failures; it resumes when returning to the list, removing older pages through Latest in range, returning to a visible tab, or retrying an error. Pause/Resume updates provides explicit user control. Failed reads retain previous evidence and expose the failure. Last-read time is labelled; this does not claim sensor freshness or completed detection evaluation.

This is bounded near-real-time polling, not server push. It adds at most one primary trajectory read per successful read plus ten seconds per active page, excluding existing user-driven and navigator/detail requests. It cannot clear the processing backlog or repair a silent endpoint. API, authentication, tenant filtering, evidence semantics and backend processing are unchanged.

## Validation

Isolated V3 suite: 5 files / 79 tests pass. Includes 10 mounted tests of this page: retaining activity while polling; advancing live bounds; fixed historical bounds; pause/resume; stable inspection; hidden-tab behaviour; no overlapping slow polling requests; older-page preservation; stale range response rejection; retained evidence and explicit background failure. Existing auth rendering, incomplete deep links, banner rendering and TI field tests remain unchanged and pass.

Vercel production target is nivxray-edr-production, project prj_KrtnUHko9opTWHv0cbXS1a2EAKV4, production branch phase2/edr-production, backend origin https://nivxray.nivxforge.com. Verify production release status and browser behaviour after merge. Do not change env vars or release another product to compensate for a failed build.

## Rollback

Restore only apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/TrajectoryPage.jsx from backend repair merge 0de8b40ae5aa4c226459e9db5ef813f93d6ea761. No data or schema rollback is involved. Keep the backend canonical-write correction.
