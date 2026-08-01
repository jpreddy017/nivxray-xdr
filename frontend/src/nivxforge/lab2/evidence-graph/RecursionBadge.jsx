import React from "react";
import { CheckCircle2, AlertCircle, Clock, Layers } from "lucide-react";

/**
 * RecursionBadge — projects cio.metadata.recursion_report as a compact
 * one-line strip that lives on top of the canvas. Closes GAP-01 from the
 * integration audit: the recursive orchestrator's outcome is now visible.
 */
export function RecursionBadge({ report }) {
  if (!report) return null;
  const status = (report.status || "").toLowerCase();
  const done = report.fixed_point_reached === true || status === "complete";
  const partial = status === "partial";

  const Icon = partial ? AlertCircle : done ? CheckCircle2 : Clock;

  return (
    <div
      className={`eg-recursion${done ? " eg-rec-done" : ""}${partial ? " eg-rec-partial" : ""}`}
      data-testid="eg-recursion-badge"
      title={report.reason_no_new || report.stop_reason || ""}
    >
      <Icon size={14} />
      <span className="eg-rec-label">
        {done ? "Fixed point reached" : partial ? "Partial · budget exhausted" : "Investigating"}
      </span>
      <span className="eg-rec-sep">·</span>
      <span><b>{report.iterations ?? 0}</b> iterations</span>
      <span className="eg-rec-sep">·</span>
      <span><b>{report.artifacts_processed ?? report.artifacts_discovered ?? 0}</b> artifacts</span>
      {report.max_depth_reached != null ? (
        <>
          <span className="eg-rec-sep">·</span>
          <span title="Recursion depth"><Layers size={12} style={{ verticalAlign: "text-bottom", marginRight: 3 }} />depth {report.max_depth_reached}</span>
        </>
      ) : null}
      {report.duration_ms != null ? (
        <>
          <span className="eg-rec-sep">·</span>
          <span title="Budget consumed">{Math.round(report.duration_ms)}ms</span>
        </>
      ) : null}
      {report.policy ? (
        <>
          <span className="eg-rec-sep">·</span>
          <span className="eg-rec-policy">{report.policy}</span>
        </>
      ) : null}
    </div>
  );
}
