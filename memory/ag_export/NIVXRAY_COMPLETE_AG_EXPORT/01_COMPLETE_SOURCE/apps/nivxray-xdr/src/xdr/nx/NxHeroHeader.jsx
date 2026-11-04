/**
 * NxHeroHeader · §16.5 first-5-seconds hero.
 *
 * Answers within 5 seconds:
 *   1. What am I looking at?  → title
 *   2. What is important?     → attention numbers
 *   3. What can I do?         → right-side action
 *
 * Sits on the canvas surface, NOT on a card.  Attention numbers
 * are integrated inline into the hero — not a KPI card wall.
 * Provenance is intentionally quiet.
 */
import React from "react";

export default function NxHeroHeader({
  eyebrow, title, description, chips, metrics = [], action, provenance,
}) {
  return (
    <header className="nx-hero" data-testid="nx-hero" style={heroStyle}>
      <div style={{ minWidth: 0, flex: 1 }}>
        {eyebrow && (
          <div className="nx-t-eyebrow" style={{ marginBottom: 4 }}>
            {eyebrow}
          </div>
        )}
        <h1 className="nx-t-h1" style={{ margin: 0, marginBottom: description ? 2 : 6 }}>
          {title}
        </h1>
        {description && (
          <div className="nx-t-body" style={{ color: "var(--nx-text-dim)", marginBottom: chips ? 10 : 10 }}>
            {description}
          </div>
        )}
        {chips && (
          <div style={chipRowStyle} data-testid="nx-hero-chips">
            {chips}
          </div>
        )}
        {metrics.length > 0 && (
          <div style={metricRowStyle}>
            {metrics.map((m, i) => (
              <MetricInline key={i} {...m} />
            ))}
          </div>
        )}
        {provenance && <div className="nx-prov">{provenance}</div>}
      </div>
      {action && (
        <div style={{ flex: "0 0 auto", display: "flex",
                        alignItems: "flex-start", gap: 6 }}>
          {action}
        </div>
      )}
    </header>
  );
}

function MetricInline({ label, value, tone = "neutral", onClick, testid }) {
  const toneCol = TONE[tone] || TONE.neutral;
  const Tag = onClick ? "button" : "span";
  return (
    <Tag
      type={onClick ? "button" : undefined}
      onClick={onClick}
      data-testid={testid}
      style={{
        ...metricStyle,
        cursor: onClick ? "pointer" : "default",
        color: onClick ? "var(--nx-text)" : "inherit",
      }}
      onMouseEnter={onClick ? (e) => { e.currentTarget.style.background = "var(--nx-surf-hover)"; } : undefined}
      onMouseLeave={onClick ? (e) => { e.currentTarget.style.background = "transparent"; } : undefined}
    >
      <span style={{
        font: "800 22px/1 var(--mono)",
        letterSpacing: "-0.4px",
        color: toneCol,
      }}>{value ?? "—"}</span>
      <span style={{
        font: "800 10px/1 var(--sans)",
        letterSpacing: 0.5,
        textTransform: "uppercase",
        color: "var(--nx-muted)",
        marginTop: 4,
      }}>{label}</span>
    </Tag>
  );
}

const TONE = {
  neutral:  "var(--nx-text)",
  critical: "var(--nx-critical)",
  high:     "var(--nx-high)",
  medium:   "var(--nx-medium)",
  low:      "var(--nx-low)",
  purple:   "var(--nx-purple)",
  benign:   "var(--nx-benign)",
  teal:     "var(--nx-teal)",
};

const heroStyle = {
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "space-between",
  gap: 24,
  padding: "20px 24px 18px",
  borderBottom: "1px solid var(--nx-bd-quiet)",
};

const metricRowStyle = {
  display: "flex",
  gap: 28,
  alignItems: "flex-end",
  flexWrap: "wrap",
};

const chipRowStyle = {
  display: "flex",
  gap: 6,
  alignItems: "center",
  flexWrap: "wrap",
  marginBottom: 12,
};

const metricStyle = {
  display: "inline-flex",
  flexDirection: "column",
  alignItems: "flex-start",
  gap: 0,
  padding: "6px 10px 6px 0",
  background: "transparent",
  border: "none",
  borderRadius: 4,
  transition: "background 120ms ease",
};
