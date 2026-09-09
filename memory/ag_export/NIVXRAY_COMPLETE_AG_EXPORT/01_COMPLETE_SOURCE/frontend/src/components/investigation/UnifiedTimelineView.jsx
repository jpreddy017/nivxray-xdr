/**
 * UnifiedTimelineView — Phase 4 · P1.
 *
 * Merged chronological view of every case-analyzed event and every
 * correlation-link event across the investigation.
 */
import { Link } from "react-router-dom";
import { Clock3, Link2, ExternalLink } from "lucide-react";

const VERDICT_COLOR = {
  Malicious: "#f87171", Suspicious: "#fbbf24", Partial: "#fbbf24",
  Benign: "#86efac", Unknown: "#94a3b8",
};

export default function UnifiedTimelineView({ timeline, onOpenEvidence }) {
  if (!timeline || !timeline.events || timeline.events.length === 0) {
    return (
      <div data-testid="timeline-empty"
           style={{ padding: 40, textAlign: "center", color: "#64748b",
                    background: "rgba(2,6,23,0.5)",
                    border: "1px dashed rgba(148,163,184,0.14)",
                    borderRadius: 10, fontSize: 12 }}>
        Timeline is empty.
      </div>
    );
  }
  return (
    <div data-testid="unified-timeline"
         style={{ background: "rgba(2,6,23,0.65)",
                  border: "1px solid rgba(148,163,184,0.14)",
                  borderRadius: 10, padding: 14 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 12,
                    color: "#94a3b8",
                    fontFamily: "JetBrains Mono, monospace",
                    fontSize: 10, letterSpacing: "0.12em",
                    textTransform: "uppercase" }}>
        <Clock3 size={12} /> Unified Timeline · {timeline.count} events
      </div>
      <div style={{ position: "relative", paddingLeft: 22 }}>
        <div aria-hidden style={{ position: "absolute", top: 4, bottom: 4, left: 8,
                                  width: 1, background: "rgba(148,163,184,0.20)" }} />
        {timeline.events.map((ev, i) => <Event key={i} ev={ev} idx={i}
                                                onOpenEvidence={onOpenEvidence} />)}
      </div>
    </div>
  );
}

function Event({ ev, idx, onOpenEvidence }) {
  const isCase = ev.kind === "case_analyzed";
  const vcol = VERDICT_COLOR[ev.verdict] || "#94a3b8";
  const ts = ev.ts ? new Date(ev.ts) : null;
  return (
    <div data-testid={`timeline-event-${idx}`}
         style={{ position: "relative", marginBottom: 12, paddingLeft: 6 }}>
      <div aria-hidden
           style={{ position: "absolute", left: -18, top: 4,
                    width: 10, height: 10, borderRadius: "50%",
                    background: isCase ? vcol : "#c4b5fd",
                    boxShadow: `0 0 6px ${isCase ? vcol : "rgba(139,92,246,0.45)"}`,
                    border: "2px solid rgba(2,6,23,0.9)" }} />
      <div style={{ fontSize: 10, color: "#64748b",
                    fontFamily: "JetBrains Mono, monospace",
                    letterSpacing: "0.08em" }}>
        {ts ? ts.toLocaleString() : "—"}
        <span style={{ marginLeft: 8, padding: "1px 6px",
                       background: isCase ? "rgba(103,232,249,0.10)"
                                          : "rgba(139,92,246,0.14)",
                       color: isCase ? "#67e8f9" : "#c4b5fd",
                       borderRadius: 3, textTransform: "uppercase" }}>
          {isCase ? "case" : "link"}
        </span>
      </div>
      {isCase ? (
        <div style={{ marginTop: 4, display: "flex", alignItems: "center",
                      gap: 8, fontSize: 12, color: "#e2e8f0",
                      fontFamily: "JetBrains Mono, monospace" }}>
          <span aria-hidden style={{ width: 6, height: 6, borderRadius: "50%",
                                     background: vcol }} />
          {ev.label || ev.case_id}
          {ev.artifact_type && (
            <span style={{ padding: "1px 5px", fontSize: 9,
                           background: "rgba(103,232,249,0.10)",
                           color: "#67e8f9", borderRadius: 3,
                           textTransform: "uppercase" }}>
              {ev.artifact_type}
            </span>
          )}
          {ev.interpreter && (
            <span style={{ padding: "1px 5px", fontSize: 9,
                           background: "rgba(139,92,246,0.10)",
                           color: "#c4b5fd", borderRadius: 3 }}>
              {ev.interpreter}
            </span>
          )}
          {ev.case_id && (
            <Link to={`/history?id=${ev.case_id}`}
                  data-testid={`timeline-event-open-${idx}`}
                  style={{ marginLeft: "auto", color: "#94a3b8",
                           display: "inline-flex", alignItems: "center" }}>
              <ExternalLink size={12} />
            </Link>
          )}
          {onOpenEvidence && (
            <button data-testid={`timeline-event-evidence-${idx}`}
                    onClick={() => onOpenEvidence(ev)}
                    title="Open evidence drill-down"
                    style={{ marginLeft: ev.case_id ? 4 : "auto",
                             padding: "1px 6px", fontSize: 9,
                             background: "rgba(56,189,248,0.10)",
                             color: "#7dd3fc",
                             border: "1px solid rgba(56,189,248,0.30)",
                             borderRadius: 3, cursor: "pointer",
                             fontFamily: "JetBrains Mono, monospace",
                             letterSpacing: "0.08em" }}>
              EVIDENCE
            </button>
          )}
        </div>
      ) : (
        <div style={{ marginTop: 4, fontSize: 11, color: "#cbd5e1",
                      fontFamily: "JetBrains Mono, monospace",
                      display: "flex", alignItems: "center", gap: 6 }}>
          <Link2 size={12} style={{ color: "#c4b5fd" }} />
          <span style={{ color: "#94a3b8" }}>
            {(ev.source || "linked").toUpperCase()}
          </span>
          <span style={{ color: "#64748b" }}>·</span>
          <span>{ev.relationship || "linked"}</span>
          {onOpenEvidence && (
            <button data-testid={`timeline-event-evidence-${idx}`}
                    onClick={() => onOpenEvidence(ev)}
                    title="Open evidence drill-down"
                    style={{ marginLeft: "auto",
                             padding: "1px 6px", fontSize: 9,
                             background: "rgba(56,189,248,0.10)",
                             color: "#7dd3fc",
                             border: "1px solid rgba(56,189,248,0.30)",
                             borderRadius: 3, cursor: "pointer",
                             fontFamily: "JetBrains Mono, monospace",
                             letterSpacing: "0.08em" }}>
              EVIDENCE
            </button>
          )}
        </div>
      )}
    </div>
  );
}
