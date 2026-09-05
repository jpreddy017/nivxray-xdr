/**
 * Rule R24 · Frontend Performance Telemetry Emitter
 * ─────────────────────────────────────────────────
 * Reports client-side render / layout / paint timings back to the
 * server so every investigation gets an immutable performance record
 * covering both halves of the pipeline (backend + frontend).
 *
 * Usage:
 *   import { reportRenderTiming } from "@/lib/telemetry";
 *   reportRenderTiming({ caseId, backendMs, behaviorsCount, tacticsCount });
 *
 * Reads `window.__NIVXRAY_TRAJ_TELEM__` (populated by TrajectoryDiagram)
 * to include layout / render counts + last layout cost.
 *
 * Non-blocking: fires POST asynchronously; never throws to the caller.
 */
import api from "@/lib/api";

let _lastPaintTs = 0;

/** Called on every investigation-panel paint to seed the paint clock. */
export function markPaintStart() {
  _lastPaintTs = (typeof performance !== "undefined") ? performance.now() : Date.now();
}

/** Fire-and-forget performance report to /api/telemetry/frontend. */
export function reportRenderTiming(fields = {}) {
  try {
    const paintMs = _lastPaintTs
      ? ((typeof performance !== "undefined") ? performance.now() : Date.now()) - _lastPaintTs
      : null;
    const traj = (typeof window !== "undefined" && window.__NIVXRAY_TRAJ_TELEM__) || {};
    const payload = {
      case_id:         fields.caseId         ?? null,
      session_id:      fields.sessionId      ?? null,
      backend_ms:      fields.backendMs      ?? null,
      layout_ms:       fields.layoutMs       ?? (traj.lastLayoutMs ?? null),
      render_ms:       fields.renderMs       ?? null,
      paint_ms:        fields.paintMs        ?? (paintMs != null ? Math.round(paintMs) : null),
      total_ms:        fields.totalMs        ?? null,
      renders:         fields.renders        ?? (traj.renders ?? null),
      layouts:         fields.layouts        ?? (traj.layouts ?? null),
      behaviors_count: fields.behaviorsCount ?? null,
      tactics_count:   fields.tacticsCount   ?? null,
      notes:           fields.notes          ?? "",
    };
    // Fire-and-forget; NEVER let telemetry break the workspace.
    api.post("/telemetry/frontend", payload).catch(() => {});
  } catch {
    /* swallow — telemetry must never crash the app */
  }
}
