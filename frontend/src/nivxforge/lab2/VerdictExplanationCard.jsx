/**
 * P1-02c · Sprint 4 · Verdict Explanation Card
 *
 * The SINGLE canonical explanation of a verdict. Rendered identically
 * inside X-Lab (Verdict panel, Ledger sidebar), Workspace (Executive
 * card), and the Report Composer (verdict section). Every surface
 * projects the same `cio.verdict` payload — zero drift.
 *
 * Consumes the shape emitted by `labv2.projector.js::view.verdict`:
 *   { label, pct, bucket, reason, escalationRule,
 *     breakdown: {critical, high, medium, low, context, mitigating},
 *     timeline: [{stage, contributor_label, contributor_kind, class, confidence_pct, source}],
 *     positive: VerdictContribution[],
 *     counter:  VerdictContribution[] (mitigating),
 *     notCounted: VerdictContribution[],
 *     supportingNodeIds: string[],
 *     engine }
 *
 * No new data. No new engine call. Pure projection.
 */
import React from "react";
import "./verdict-explanation-card.css";

const LABEL_TONE = {
  MALICIOUS: "malicious",
  SUSPICIOUS: "suspicious",
  "RUNTIME DEPENDENT": "runtime",
  INFORMATIONAL: "info",
  UNDETERMINED: "unknown",
};

const CLASS_ORDER = ["critical", "high", "medium", "low", "context", "mitigating"];
const CLASS_LABEL = {
  critical:   "Critical",
  high:       "High",
  medium:     "Medium",
  low:        "Low",
  context:    "Context",
  mitigating: "Mitigating",
};

function classBarSegments(breakdown) {
  return CLASS_ORDER.map((cls) => ({
    cls,
    pct: Math.max(0, Math.min(100, breakdown?.[cls] ?? 0)),
  }));
}

function EvChip({ id, onEnter, onLeave, onClick }) {
  return (
    <span
      className="vec-chip"
      role="button"
      tabIndex={0}
      data-testid={`vec-chip-${id}`}
      onMouseEnter={(e) => onEnter && onEnter(id, e.currentTarget)}
      onMouseLeave={() => onLeave && onLeave()}
      onClick={() => onClick && onClick(id)}
    >
      {id}
    </span>
  );
}

export default function VerdictExplanationCard({
  verdict,
  compact = false,
  onEvHover,
  onEvLeave,
  onEvClick,
}) {
  if (!verdict) return null;
  const tone = LABEL_TONE[verdict.label] || "unknown";
  const bars = classBarSegments(verdict.breakdown);
  const positive = verdict.positive || [];
  const counter = verdict.counter || [];

  return (
    <section
      className={`verdict-card tone-${tone}${compact ? " compact" : ""}`}
      data-testid="verdict-explanation-card"
    >
      {/* HEADER — label · confidence · escalation-rule tag */}
      <header className="vec-head">
        <div className="vec-label" data-testid="vec-label">
          <span className="vec-arrow">▲</span> {verdict.label}
        </div>
        <div className="vec-conf" data-testid="vec-confidence">
          <span className="pct">{verdict.pct}%</span>
          <span className="bucket">{verdict.bucket}</span>
        </div>
        {verdict.escalationRule ? (
          <div className="vec-rule" data-testid="vec-rule">
            <span className="rule-label">Escalation rule</span>
            <span className="rule-name mono">{verdict.escalationRule}</span>
          </div>
        ) : null}
      </header>

      {/* REASON — one sentence */}
      {verdict.reason ? (
        <p className="vec-reason" data-testid="vec-reason">{verdict.reason}</p>
      ) : null}

      {/* CLASS BREAKDOWN — one bar per evidence class */}
      <div className="vec-breakdown" data-testid="vec-breakdown">
        {bars.map(({ cls, pct }) => (
          <div key={cls} className={`vec-bar ${cls}`} data-testid={`vec-bar-${cls}`}>
            <span className="bar-label">{CLASS_LABEL[cls]}</span>
            <span className="bar-track">
              <span className="bar-fill" style={{ width: `${pct}%` }} />
            </span>
            <span className="bar-pct mono">{pct}%</span>
          </div>
        ))}
      </div>

      {/* POSITIVE EVIDENCE */}
      <div className="vec-section">
        <div className="vec-sh">Evidence</div>
        {positive.length === 0 ? (
          <div className="vec-empty" data-testid="vec-positive-empty">
            No positive evidence recorded by the engine.
          </div>
        ) : (
          <ul className="vec-list" data-testid="vec-positive">
            {positive.slice(0, compact ? 5 : 12).map((c, i) => (
              <li key={i} className={`vec-item cls-${c.evidence_class || "unknown"}`}
                  data-testid={`vec-positive-${i}`}>
                <span className="glyph">✓</span>
                <span className="body">
                  <span className="label">{c.label || c.kind}</span>
                  <span className="meta">
                    <span className="kind mono">{c.kind}</span>
                    <span className="class">{c.evidence_class}</span>
                    <span className="weight mono">w {c.weight}</span>
                    <span className="src mono">{c.source}</span>
                    {c.escalated_by ? <span className="rule-tag">{c.escalated_by}</span> : null}
                  </span>
                </span>
                <EvChip id={c.node_id} onEnter={onEvHover} onLeave={onEvLeave} onClick={onEvClick} />
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* COUNTER EVIDENCE (MITIGATING) */}
      <div className="vec-section counter">
        <div className="vec-sh">Counter Evidence</div>
        {counter.length === 0 ? (
          <div className="vec-empty" data-testid="vec-counter-empty">None recorded.</div>
        ) : (
          <ul className="vec-list" data-testid="vec-counter">
            {counter.slice(0, 6).map((c, i) => (
              <li key={i} className="vec-item cls-mitigating"
                  data-testid={`vec-counter-${i}`}>
                <span className="glyph">−</span>
                <span className="body">
                  <span className="label">{c.label || c.kind}</span>
                  <span className="meta">
                    <span className="kind mono">{c.kind}</span>
                    <span className="src mono">{c.source}</span>
                  </span>
                </span>
                <EvChip id={c.node_id} onEnter={onEvHover} onLeave={onEvLeave} onClick={onEvClick} />
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* CONFIDENCE TIMELINE — shown always (abbreviated in compact) */}
      {verdict.timeline && verdict.timeline.length > 0 ? (
        <div className="vec-section timeline" data-testid="vec-timeline">
          <div className="vec-sh">Confidence Timeline</div>
          <ol className="vec-tl">
            {(compact ? verdict.timeline.slice(-4) : verdict.timeline).map((s, i) => (
              <li key={i} className={`vec-tl-step cls-${s.class || "unknown"}`}
                  data-testid={`vec-tl-step-${i}`}>
                <span className="tl-stage mono">{s.stage}</span>
                <span className="tl-conf mono">{s.confidence_pct}%</span>
                <span className="tl-lbl">{s.contributor_label || s.contributor_kind}</span>
                <span className="tl-cls">{s.class}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}

      {/* SUPPORTING NODES */}
      {verdict.supportingNodeIds && verdict.supportingNodeIds.length ? (
        <footer className="vec-foot" data-testid="vec-supporting-nodes">
          <span className="foot-label">Supporting nodes</span>
          <span className="foot-chips">
            {verdict.supportingNodeIds.slice(0, compact ? 6 : 12).map((id) => (
              <EvChip key={id} id={id} onEnter={onEvHover} onLeave={onEvLeave} onClick={onEvClick} />
            ))}
          </span>
        </footer>
      ) : null}

      <div className="vec-engine mono" data-testid="vec-engine">
        {verdict.engine}
      </div>
    </section>
  );
}
