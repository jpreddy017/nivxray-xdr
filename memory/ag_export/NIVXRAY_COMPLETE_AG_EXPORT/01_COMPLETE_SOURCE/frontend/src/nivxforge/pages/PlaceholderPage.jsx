/**
 * NivXForge · Generic placeholder page for platform-shell sections that are
 * not yet built. Establishes the section's presence in the platform IA
 * without introducing analytical behaviour.
 *
 * No backend calls. No new capabilities.
 */
import NivxForgeLayout from "../components/NivxForgeLayout";
import { Link } from "react-router-dom";

const S = {
  page: { padding: "28px 32px 72px", color: "var(--text)", minHeight: "calc(100vh - 60px)" },
  hero: { marginBottom: 28 },
  eyebrow: { fontSize: 11, letterSpacing: "0.28em", color: "var(--accent, #7dd3fc)", textTransform: "uppercase", fontWeight: 600 },
  h1: { fontSize: 32, margin: "6px 0 4px", fontWeight: 700, color: "var(--text, #e2e8f0)" },
  sub: { color: "var(--text-secondary, #94a3b8)", fontSize: 14, maxWidth: 760 },
  card: {
    background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 10, padding: "28px 24px", maxWidth: 720,
  },
  soonChip: {
    display: "inline-block", padding: "3px 10px", borderRadius: 12,
    fontSize: 11, letterSpacing: "0.14em", fontWeight: 700,
    color: "#facc15", border: "1px solid rgba(250,204,21,0.4)",
    background: "rgba(250,204,21,0.08)", textTransform: "uppercase",
  },
  bodyH: { fontSize: 12, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", marginBottom: 10, textTransform: "uppercase", fontWeight: 600, marginTop: 20 },
  list: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 13, color: "var(--text, #e2e8f0)", paddingLeft: 20, lineHeight: 1.9 },
  note: {
    marginTop: 22, padding: "12px 14px",
    background: "rgba(125,211,252,0.05)", border: "1px solid rgba(125,211,252,0.25)",
    borderRadius: 8, fontSize: 12, color: "var(--text-secondary, #94a3b8)",
    fontFamily: "ui-monospace",
  },
  backLink: {
    display: "inline-block", marginTop: 22, padding: "9px 14px",
    background: "transparent", color: "var(--text, #e2e8f0)",
    border: "1px solid var(--border, #1e293b)", borderRadius: 5,
    fontFamily: "ui-monospace", fontSize: 12, letterSpacing: "0.08em",
    fontWeight: 600, textTransform: "uppercase", textDecoration: "none",
  },
};

export default function PlaceholderPage({ testid, eyebrow, title, description, plannedFeatures, evidenceGate }) {
  return (
    <NivxForgeLayout>
      <div style={S.page} data-testid={testid}>
        <div style={S.hero}>
          <div style={S.eyebrow}>{eyebrow}</div>
          <h1 style={S.h1}>{title}</h1>
          <p style={S.sub}>{description}</p>
        </div>

        <div style={S.card}>
          <span style={S.soonChip} data-testid="placeholder-soon">Coming in a future release</span>

          <div style={S.bodyH}>Planned capabilities</div>
          <ul style={S.list}>
            {plannedFeatures.map((f, i) => (
              <li key={i} data-testid={`placeholder-feature-${i}`}>{f}</li>
            ))}
          </ul>

          <div style={S.note}>
            <strong>Governance gate:</strong> {evidenceGate}
          </div>

          <Link to="/nivxforge/investigate" style={S.backLink} data-testid="placeholder-back-investigate">← Back to Investigate</Link>
        </div>
      </div>
    </NivxForgeLayout>
  );
}
