// EDR Device Trajectory · Verdict Explainability Card
// Owner rule #7: show WHY, not just label + score.
import React from "react";

const LABEL_STYLES = {
  malicious:  { bg: "#4c0f16", border: "#a03040", chip: "#e04c60" },
  suspicious: { bg: "#4a340a", border: "#9a7020", chip: "#eab040" },
  benign:     { bg: "#0f4a24", border: "#209650", chip: "#40d080" },
  unknown:    { bg: "#2a2a30", border: "#505060", chip: "#a0a0b0" },
};

const CONF_LABEL = {
  high:          "HIGH CONFIDENCE",
  medium:        "MEDIUM CONFIDENCE",
  low:           "LOW CONFIDENCE",
  insufficient:  "INSUFFICIENT",
};

export const VerdictExplainabilityCard = ({ verdict, onRowClick }) => {
  if (!verdict) {
    return (
      <div data-testid="verdict-explainability-empty" style={styles.emptyBox}>
        <div style={{ opacity: 0.6, fontSize: 12 }}>
          No Stage-2 verdict yet — compute a verdict from the current
          Timeline + Intent.
        </div>
      </div>
    );
  }

  const style = LABEL_STYLES[verdict.label] || LABEL_STYLES.unknown;
  const signals = verdict.contributing_signals || [];
  const rows    = verdict.evidence_rows || [];

  return (
    <div data-testid="verdict-explainability-card" style={{
      ...styles.card,
      background: style.bg,
      borderColor: style.border,
    }}>
      <div style={styles.headerRow}>
        <div>
          <div data-testid="verdict-label" style={{
            ...styles.label,
            color: style.chip,
          }}>
            {String(verdict.label || "unknown").toUpperCase()}
          </div>
          <div style={styles.confidence}>{CONF_LABEL[verdict.confidence] || "—"}</div>
        </div>
        <div style={{ textAlign: "right" }}>
          <div style={styles.riskLabel}>Risk Score</div>
          <div data-testid="verdict-risk-score" style={styles.riskScore}>
            {verdict.risk_score ?? 0}
          </div>
        </div>
      </div>

      <div style={styles.sectionTitle}>Contributing Evidence</div>

      <div style={styles.rowsList}>
        {rows.length === 0 && (
          <div style={{ opacity: 0.6, fontSize: 12 }}>
            No contributing signals — verdict is {verdict.label}.
          </div>
        )}
        {rows.map((r) => (
          <button
            key={r.row_id}
            data-testid={`verdict-row-${r.row_id}`}
            onClick={() => onRowClick && onRowClick(r)}
            style={{
              ...styles.rowBtn,
              borderLeftColor: r.weight_contribution > 0
                ? "#e04c60" : "#40d080",
            }}
          >
            <div style={styles.rowTop}>
              <span style={styles.rowRuleId}>{r.rule_id}</span>
              <span style={{
                ...styles.rowWeight,
                color: r.weight_contribution > 0 ? "#e04c60" : "#40d080",
              }}>
                {r.weight_contribution > 0 ? "+" : ""}{r.weight_contribution}
              </span>
            </div>
            <div style={styles.rowSummary}>{r.display_summary}</div>
            <div style={styles.rowMeta}>
              <span>{r.canonical_field_matched}</span>
              <span style={{ margin: "0 8px", opacity: 0.4 }}>·</span>
              <span>lane: {r.lane}</span>
              {r.event_ids && r.event_ids.length > 0 && (
                <>
                  <span style={{ margin: "0 8px", opacity: 0.4 }}>·</span>
                  <span>evidence: {r.event_ids.slice(0, 3).join(", ")}
                    {r.event_ids.length > 3 ? ` +${r.event_ids.length - 3}` : ""}
                  </span>
                </>
              )}
            </div>
          </button>
        ))}
      </div>

      <div style={styles.footer}>
        <span title={verdict.fingerprint}>fp: {(verdict.fingerprint || "").slice(0, 12)}…</span>
        <span style={{ margin: "0 8px", opacity: 0.4 }}>·</span>
        <span>{signals.length} rules fired · {rows.length} rows</span>
      </div>
    </div>
  );
};

const styles = {
  card: {
    border: "1px solid",
    borderRadius: 8,
    padding: 16,
    color: "#e0e0e5",
    fontFamily: "ui-monospace, monospace",
    fontSize: 13,
  },
  emptyBox: {
    border: "1px dashed #333",
    borderRadius: 8,
    padding: 24,
    textAlign: "center",
    color: "#888",
  },
  headerRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 12,
  },
  label:    { fontSize: 20, fontWeight: 700, letterSpacing: 1.2 },
  confidence: { fontSize: 10, opacity: 0.7, marginTop: 2, letterSpacing: 1 },
  riskLabel:{ fontSize: 10, opacity: 0.7, textTransform: "uppercase" },
  riskScore:{ fontSize: 32, fontWeight: 800, lineHeight: 1 },
  sectionTitle:{ fontSize: 11, textTransform: "uppercase",
                  letterSpacing: 1, opacity: 0.7, marginBottom: 8 },
  rowsList: { display: "flex", flexDirection: "column", gap: 6 },
  rowBtn: {
    all: "unset",
    cursor: "pointer",
    background: "rgba(0,0,0,0.3)",
    borderLeft: "4px solid",
    padding: "8px 12px",
    borderRadius: 4,
  },
  rowTop: { display: "flex", justifyContent: "space-between", marginBottom: 4 },
  rowRuleId: { fontSize: 11, opacity: 0.9, fontWeight: 600 },
  rowWeight: { fontSize: 12, fontWeight: 700 },
  rowSummary: { fontSize: 13, marginBottom: 4 },
  rowMeta: { fontSize: 10, opacity: 0.6 },
  footer: {
    marginTop: 12, fontSize: 10, opacity: 0.5,
    display: "flex", justifyContent: "flex-end",
  },
};

export default VerdictExplainabilityCard;
