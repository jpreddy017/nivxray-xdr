/**
 * IncidentPreviewDrawer · right-side dark drawer opened when an
 * analyst clicks a row (but not the incident name).
 *
 * Renders authoritative fields from the queue-row projection ONLY.
 * Missing engine data ⇒ NOT_RUN / NOT AVAILABLE / NO EVIDENCE / —.
 * The drawer NEVER calls an engine — Open Investigation is the only
 * path into the full workspace.
 */
import React, { useEffect } from "react";
import { X, ChevronUp, ChevronDown, ArrowRight } from "lucide-react";
import {
  PriorityChip, SeverityChip, VerdictChip, StateChip, DomainTag,
} from "@/xdr/components/chips";

const dash = <span className="v dash">—</span>;
const notRun = <span className="v mono" style={{ color: "#6b7280" }}>NOT_RUN</span>;
const na = <span className="v dash">NOT AVAILABLE</span>;

function fmtISO(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}

function fmtAging(sec) {
  if (sec == null) return null;
  if (sec < 60)    return `${sec}s`;
  if (sec < 3600)  return `${Math.floor(sec/60)}m`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h`;
  return `${Math.floor(sec/86400)}d`;
}

export default function IncidentPreviewDrawer({
  incident, onClose, onOpen, onPrev, onNext, hasPrev, hasNext,
}) {
  // Escape-to-close.
  useEffect(() => {
    if (!incident) return undefined;
    const h = (e) => {
      if (e.key === "Escape")     onClose();
      if (e.key === "ArrowUp"   && hasPrev) onPrev();
      if (e.key === "ArrowDown" && hasNext) onNext();
    };
    document.addEventListener("keydown", h);
    return () => document.removeEventListener("keydown", h);
  }, [incident, hasPrev, hasNext, onClose, onPrev, onNext]);

  if (!incident) return null;
  const r = incident;

  const ai = r.auto_investigation || {};
  const aiStatus = ai.status || "NOT_RUN";

  return (
    <>
      <div
        className="ql-drawer-scrim"
        onClick={onClose}
        data-testid="ql-drawer-scrim"
      />
      <aside className="ql-drawer" data-testid="ql-drawer" role="dialog"
              aria-label="Incident preview">
        <div className="ql-drawer-head">
          <span className="ql-inc-id">
            {r.number || (r.id?.slice(0, 12) + "…")}
          </span>
          <div className="ql-drawer-head-actions">
            <button
              type="button"
              className="ql-drawer-icon-btn"
              onClick={onPrev}
              disabled={!hasPrev}
              title="Previous incident (↑)"
              data-testid="ql-drawer-prev"
            >
              <ChevronUp size={13} />
            </button>
            <button
              type="button"
              className="ql-drawer-icon-btn"
              onClick={onNext}
              disabled={!hasNext}
              title="Next incident (↓)"
              data-testid="ql-drawer-next"
            >
              <ChevronDown size={13} />
            </button>
            <button
              type="button"
              className="ql-drawer-icon-btn"
              onClick={onClose}
              title="Close (Esc)"
              data-testid="ql-drawer-close"
            >
              <X size={13} />
            </button>
          </div>
        </div>

        <div className="ql-drawer-body">
          <h4 data-testid="ql-drawer-name">{r.name || "(unnamed)"}</h4>

          <div className="ql-drawer-badges" data-testid="ql-drawer-badges">
            {r.priority?.code && <PriorityChip code={r.priority.code} />}
            <SeverityChip value={r.severity || "unknown"} />
            <VerdictChip value={r.verdict?.stage2_label || "unknown"} />
            <StateChip   value={r.state || "new"} />
          </div>

          {/* Key facts */}
          <div className="ql-drawer-section">
            <div className="ql-drawer-section-title">Key facts</div>
            <div className="ql-drawer-kv">
              <span className="k">Customer</span>
              {r.customer
                ? <span className="v mono" data-testid="ql-drawer-customer">{r.customer}</span>
                : na}
              <span className="k">Detection</span>
              {r.detection_source
                ? <span className="v mono" data-testid="ql-drawer-source">{r.detection_source}</span>
                : na}
              <span className="k">Owner</span>
              {r.assignee
                ? <span className="v mono" data-testid="ql-drawer-owner">{r.assignee}</span>
                : <span className="v mono" style={{ color: "#F59E0B" }}>UNASSIGNED</span>}
              <span className="k">Confidence</span>
              {r.confidence
                ? <span className="v mono">{String(r.confidence).toUpperCase()}</span>
                : notRun}
              <span className="k">Risk score</span>
              {r.verdict?.risk_score != null
                ? <span className="v mono">{r.verdict.risk_score}</span>
                : na}
              <span className="k">Aging</span>
              {r.aging_seconds != null
                ? <span className="v mono">{fmtAging(r.aging_seconds)}</span>
                : dash}
              <span className="k">SLA due</span>
              {r.sla_due_at
                ? <span className="v mono">{fmtISO(r.sla_due_at)}</span>
                : dash}
              <span className="k">Last activity</span>
              {r.last_activity
                ? <span className="v mono">{fmtISO(r.last_activity)}</span>
                : dash}
            </div>
          </div>

          {/* Auto-Investigation status */}
          <div className="ql-drawer-section" data-testid="ql-drawer-ai">
            <div className="ql-drawer-section-title">Auto-Investigation status</div>
            <div className="ql-drawer-metrics">
              <div className="ql-drawer-metric">
                <div className="m-k">Status</div>
                <div className="m-v" style={{
                  color: aiStatus === "COMPLETE" ? "#3CE8B8"
                    : aiStatus === "PARTIAL"  ? "#F5A623"
                    : aiStatus === "FAILED"   ? "#EF5B5B"
                    : aiStatus === "RUNNING"  ? "#3FC1E8"
                    : "#78808F",
                  fontSize: 12,
                }}>
                  {aiStatus}
                </div>
              </div>
              <div className="ql-drawer-metric">
                <div className="m-k">Engines OK</div>
                <div className={`m-v ${ai.engines_total ? "" : "dim"}`}>
                  {ai.engines_total > 0
                    ? `${ai.engines_ok}/${ai.engines_total}`
                    : "—"}
                </div>
              </div>
              <div className="ql-drawer-metric">
                <div className="m-k">Duration</div>
                <div className={`m-v ${ai.duration_ms ? "" : "dim"}`}>
                  {ai.duration_ms != null
                    ? `${Math.round(ai.duration_ms/100)/10}s`
                    : "—"}
                </div>
              </div>
            </div>
          </div>

          {/* Evidence / techniques */}
          <div className="ql-drawer-section" data-testid="ql-drawer-evidence">
            <div className="ql-drawer-section-title">Evidence &amp; techniques</div>
            <div className="ql-drawer-metrics">
              <div className="ql-drawer-metric">
                <div className="m-k">Evidence</div>
                <div className={`m-v ${r.evidence_count ? "" : "dim"}`}>
                  {r.evidence_count > 0 ? r.evidence_count : "NO EVIDENCE"}
                </div>
              </div>
              <div className="ql-drawer-metric">
                <div className="m-k">MITRE</div>
                <div className={`m-v ${r.techniques_total ? "" : "dim"}`}>
                  {r.techniques_total > 0 ? r.techniques_total : "—"}
                </div>
              </div>
              <div className="ql-drawer-metric">
                <div className="m-k">Engine results</div>
                <div className={`m-v ${ai.engines_total ? "" : "dim"}`}>
                  {ai.engines_total > 0 ? ai.engines_total : "NOT_RUN"}
                </div>
              </div>
            </div>
            {r.techniques_top?.length ? (
              <div style={{ marginTop: 8, fontFamily: "var(--qs-mono)",
                            fontSize: 11, color: "#B4B9C6", lineHeight: 1.7 }}>
                {r.techniques_top.join(" · ")}
                {r.techniques_total > r.techniques_top.length
                  && ` +${r.techniques_total - r.techniques_top.length}`}
              </div>
            ) : null}
          </div>

          {/* Executive summary excerpt — only if backend provided one */}
          {r.executive_summary && (
            <div className="ql-drawer-section" data-testid="ql-drawer-exec">
              <div className="ql-drawer-section-title">Executive summary</div>
              <div style={{ fontSize: 12, lineHeight: 1.55, color: "#B4B9C6" }}>
                {String(r.executive_summary).slice(0, 320)}
                {String(r.executive_summary).length > 320 && "…"}
              </div>
            </div>
          )}
        </div>

        <div className="ql-drawer-foot">
          <span style={{ fontFamily: "var(--qs-mono)", fontSize: 10.5,
                          color: "#78808F" }}>
            projection · never runs an engine
          </span>
          <button
            type="button"
            className="ql-drawer-open"
            onClick={onOpen}
            data-testid="ql-drawer-open-investigation"
          >
            Open Investigation <ArrowRight size={13} />
          </button>
        </div>
      </aside>
    </>
  );
}
