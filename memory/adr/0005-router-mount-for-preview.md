# ADR 0005 — Mount NivXForge Router for Read-Only Preview

- **Status:** Accepted  (approved 2026-02-28 alongside ADR-0001 and ADR-0004 · Preview UI directive)
- **Date:** 2026-02-28
- **Author(s):** e1
- **Supersedes:** Decision A1 (partial — read-only preview only)
- **Superseded by:** —

## 1 · Problem Statement

The NivXForge Preview UI directive requires the frontend to render
Evidence Inventory, ADR status, governance state, and pattern
statistics. Those artefacts live in `/app/memory/` and cannot be
served to the browser without a backend endpoint. Decision A1 (Phase 0)
kept the NivXForge router dormant. This ADR narrowly reverses A1 for
**read-only preview endpoints only**.

## 2 · Supporting Evidence

- User directive (2026-02-28): "proceed with implementing the NivXForge Preview user interface" + "Consume existing evidence reports and approved governance artifacts only."
- ADR-0001 and ADR-0004 acceptance in the same directive.

## 3 · Proposed Change

- Mount `nivxforge_router` in `server.py` under `/api` so its routes
  live at `/api/nivxforge/*`.
- All mounted endpoints in Phase-of-this-ADR are **GET-only,
  read-only, no side effects**.
- Mount is limited to the preview sub-router; write endpoints for
  future NivXForge capabilities require separate ADRs.

## 4 · Alternatives Considered

- **(a) Do nothing — keep A1 in force.** Rejected. Preview UI cannot function.
- **(b) Serve `/app/memory/*.md` as static files.** Rejected. Bypasses the API namespace, weakens the isolation boundary, no auth possible.
- **(c) Read-through Workspace endpoints.** Rejected. Violates isolation.

## 5 · Workspace Impact

- **Files modified:** `/app/backend/server.py` — **one line appended** (`api.include_router(nivxforge_router)`).
- **Files added:** none in Workspace tree.
- **Compatibility test amendment:** `nivxforge/tests/test_workspace_compatibility.py::test_nivxforge_router_not_registered_in_workspace_server` is renamed and inverted to `test_nivxforge_router_registered_exactly_once_and_read_only`. This is the ONLY test amendment required.

## 6 · Success Criteria

- `curl /api/nivxforge/health` returns 200.
- `curl /api/nivxforge/preview/*` returns 200 with JSON payloads.
- Workspace suite remains green.
- No POST/PUT/DELETE/PATCH routes registered under `/nivxforge/*` in this ADR.

## 7 · Consequences

- Enables the Preview UI.
- Any future write endpoint or engine-facing endpoint requires its own ADR referencing evidence and impact.
