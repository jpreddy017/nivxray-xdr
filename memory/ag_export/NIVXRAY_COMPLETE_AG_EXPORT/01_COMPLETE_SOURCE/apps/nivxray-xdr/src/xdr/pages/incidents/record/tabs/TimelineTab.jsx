/**
 * TimelineTab · Layer 3.
 *
 * Combines two authoritative surfaces:
 *   · Lifecycle state history (`incident.state_history` — already
 *     persisted by /api/incidents/:id/state).
 *   · Canonical activity inventory (via the existing ActivityTab
 *     which consumes /api/activity/inventory).
 *
 * The rendering is honest: an incident without transitions or
 * activity gets an explicit empty state rather than fabricated
 * events.
 */
import React from "react";
import { CircleDot, ArrowRight } from "lucide-react";

import ActivityTab from "@/components/incidents/tabs/ActivityTab";

function fmtISO(iso) {
  if (!iso) return "—";
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}

export default function TimelineTab({ incident }) {
  const history = incident.state_history || [];

  return (
    <div data-testid="xdr-record-timeline">
      {/* Lifecycle state history */}
      <div className="rl-section">
        <div className="rl-section-title">Lifecycle state history</div>
        {history.length === 0
          ? <div className="rl-empty">
              NO TRANSITIONS — this incident is still in its initial
              state; no state transitions have been recorded.
            </div>
          : <table className="rl-table">
              <thead><tr>
                <th style={{ width: 160 }}>Timestamp</th>
                <th>Transition</th>
                <th>Actor</th>
                <th>Note</th>
              </tr></thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i} data-testid={`xdr-record-timeline-hist-${i}`}>
                    <td className="mono">{fmtISO(h.at || h.ts)}</td>
                    <td className="mono">
                      <CircleDot size={11} style={{ display: "inline",
                                                        verticalAlign: "-1px",
                                                        marginRight: 4,
                                                        color: "var(--rl-muted)" }} />
                      {h.from || "—"}
                      <ArrowRight size={11} style={{ display: "inline",
                                                         verticalAlign: "-2px",
                                                         margin: "0 6px",
                                                         color: "var(--rl-purple)" }} />
                      <span style={{ color: "var(--rl-purple)", fontWeight: 700 }}>
                        {h.to || "—"}
                      </span>
                    </td>
                    <td className="mono">{h.by || h.actor || "—"}</td>
                    <td>{h.note || h.reason || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>}
      </div>

      {/* Canonical activity inventory (reused) */}
      <div className="rl-section" data-testid="xdr-record-timeline-activity">
        <div className="rl-section-title">Canonical activity inventory</div>
        <div className="canvas-inner"
              style={{ background: "transparent", padding: 0 }}>
          <div className="xdr-console" style={{
            background: "transparent",
            padding: 0, minHeight: 0,
          }}>
            <ActivityTab incident={incident} />
          </div>
        </div>
      </div>
    </div>
  );
}
