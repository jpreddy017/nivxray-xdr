# Agent learnings · NivXRay programme

## 2026-06 · Context management
- **NEVER call the asset-listing tool unfiltered on this job.** It returns
  **1 480 artefacts / ~320 KB** and blew the context budget mid-turn,
  pausing execution. Ask the owner for the specific asset URLs (or "my
  last N uploads") and read only those.

## 2026-06 · Debugging lessons that cost real time
- **An unresolved lookup is not missing evidence.** The P0-F.13.5
  "data-lineage gap" was a **paging-cursor bug** (`out["page"]["next_cursor"]`
  vs top-level `next_cursor`) that capped the search at the first 4 000 of
  6 356 observations. Verify the join in the DB before declaring a gap.
- **A resolver that names an observation is only half a handoff.** The row
  viewport must move to `focus.lane_index`, or the windowed request never
  asks for that row and a server-resolved event is still absent from the
  canvas.
- **Explicit identifiers must beat context-derived ones.** Adding an
  incident's campaign detections to the wanted set made a URL naming one
  raw event land on a different (also-detected) observation.
- **Detections are not stored on observations.** They live in
  `edr_raw_events.derivations[outcome=DETECTION_MATCHED]`; the trajectory
  projection has to join `raw_id == ingest_job_id` and
  `derivations[].event_id == canonical_event_id`, or real detections render
  `Unknown · not assessed`.
- **`event.raw.sha256` is an event-content digest, NOT a file hash.** Never
  offer it as a hash to search or pivot on.
- **Check the route exists before linking to it.** I shipped a search
  result pointing at `/xdr/fleet-file-trajectory`, which does not exist;
  the real route is `/xdr/intelligence/files/:key`.
- **Never render two banners for one outcome.** The endpoint-level and
  focus-level handoff states must not stack.
- **JSX is not Python**: adjacent string literals do not concatenate —
  use template literals. Cost one broken page in iteration_105.
- **Envelope awareness**: `/api/xdr/rbac/session-context` answers inside
  `{ok, data}`; use `edrApi.getSessionContext()` rather than raw `api.get`.

## Programme rules that must not be relaxed
- Evidence-first: if a field has no record, say so; never infer from
  hostname, pid, process name or timestamp proximity.
- Diagnostic counts (observations searched, pages searched) are diagnostics,
  never evidence that a thing exists.
- Absence of a detection/incident is never a verdict of clean.
- Tenant boundary is decided server-side from the authorised endpoint
  inventory; query parameters are never trusted.
