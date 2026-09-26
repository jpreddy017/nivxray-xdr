/**
 * NivXForge · Dashboard. Landing page. Presentation-only aggregation of
 * existing platform-health state — no new backend calls, no new analytical
 * logic. Reads:
 *   GET /api/nivxforge/preview/platform-health
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import NivxForgeLayout from "../components/NivxForgeLayout";
import api from "../../lib/api";

const S = {
  page: { padding: "28px 32px 72px", color: "var(--text)", minHeight: "calc(100vh - 60px)" },
  hero: { marginBottom: 28 },
  eyebrow: { fontSize: 11, letterSpacing: "0.28em", color: "var(--accent, #7dd3fc)", textTransform: "uppercase", fontWeight: 600 },
  h1: { fontSize: 32, margin: "6px 0 4px", fontWeight: 700, color: "var(--text, #e2e8f0)" },
  sub: { color: "var(--text-secondary, #94a3b8)", fontSize: 14, maxWidth: 780 },
  grid: { display: "grid", gap: 18, gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" },
  card: {
    background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)",
    borderRadius: 10, padding: 18,
  },
  cardH: { fontSize: 11, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", marginBottom: 8, textTransform: "uppercase", fontWeight: 600 },
  metric: { fontSize: 28, fontWeight: 700, color: "var(--text, #e2e8f0)", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace" },
  metricSub: { fontSize: 11, color: "var(--text-secondary, #94a3b8)", marginTop: 4, fontFamily: "ui-monospace" },
  ok: { color: "#4ade80" },
  warn: { color: "#facc15" },
  quickBar: { marginTop: 28, padding: 18, background: "var(--panel, #0f172a)", border: "1px solid var(--border, #1e293b)", borderRadius: 10 },
  quickTitle: { fontSize: 11, letterSpacing: "0.22em", color: "var(--text-secondary, #94a3b8)", marginBottom: 12, textTransform: "uppercase", fontWeight: 600 },
  quickBtn: {
    display: "inline-block", padding: "10px 16px", background: "var(--accent, #7dd3fc)", color: "#020617",
    border: "1px solid var(--accent, #7dd3fc)", borderRadius: 5,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 12, letterSpacing: "0.08em", fontWeight: 700, textTransform: "uppercase",
    textDecoration: "none", marginRight: 10,
  },
  quickBtnGhost: {
    display: "inline-block", padding: "10px 16px", background: "transparent", color: "var(--text, #e2e8f0)",
    border: "1px solid var(--border, #1e293b)", borderRadius: 5,
    fontFamily: "ui-monospace", fontSize: 12, letterSpacing: "0.08em", fontWeight: 600,
    textTransform: "uppercase", textDecoration: "none", marginRight: 10,
  },
  err: { color: "#f87171", fontSize: 13 },
  banner: {
    marginTop: 16, padding: "10px 14px", background: "rgba(125,211,252,0.06)",
    border: "1px solid rgba(125,211,252,0.25)", borderRadius: 8, fontSize: 12,
    color: "var(--text-secondary, #94a3b8)", fontFamily: "ui-monospace",
  },
};

export default function DashboardPage() {
  const [h, setH] = useState(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    api.get("/nivxforge/preview/platform-health")
      .then((r) => setH(r.data))
      .catch((e) => setErr(e?.friendlyMessage || String(e?.message || e)));
  }, []);

  const s   = h?.situational || {};
  const reg = h?.regression || {};

  return (
    <NivxForgeLayout>
      <div style={S.page} data-testid="nivxforge-dashboard">
        <div style={S.hero}>
          <div style={S.eyebrow}>Lab · Dashboard</div>
          <h1 style={S.h1}>Analyst Investigation Console</h1>
          <p style={S.sub}>
            Real-time platform status derived from the frozen evidence corpus and governance state.
            Read-only · no backend duplication · same analytical results as Workspace.
          </p>
          {err ? <div style={{ ...S.banner, borderColor: "#f87171", color: "#f87171" }}>{err}</div> : null}
        </div>

        <div style={S.grid}>
          <div style={S.card} data-testid="dash-card-status">
            <div style={S.cardH}>Platform Status</div>
            <div style={{ ...S.metric, ...(s.workspace_protection === "ACTIVE" ? S.ok : {}) }}>
              {s.workspace_protection || "—"}
            </div>
            <div style={S.metricSub}>Workspace Protection</div>
          </div>

          <div style={S.card} data-testid="dash-card-preview">
            <div style={S.cardH}>Preview</div>
            <div style={{ ...S.metric, ...(s.preview_health === "HEALTHY" ? S.ok : {}) }}>
              {s.preview_health || "—"}
            </div>
            <div style={S.metricSub}>Lab preview state</div>
          </div>

          <div style={S.card} data-testid="dash-card-regression">
            <div style={S.cardH}>Regression Suite</div>
            <div style={{ ...S.metric, ...(/PASS/.test(s.regression_suite || "") ? S.ok : S.warn) }}>
              {s.regression_suite || "unverified"}
            </div>
            <div style={S.metricSub}>{reg.suite || "—"} · {reg.duration_seconds != null ? `${reg.duration_seconds}s` : ""}</div>
          </div>

          <div style={S.card} data-testid="dash-card-adrs">
            <div style={S.cardH}>Accepted ADRs</div>
            <div style={S.metric}>{s.accepted_adrs ?? "—"}</div>
            <div style={S.metricSub}>{s.pending_handler_adrs ?? 0} pending decision</div>
          </div>

          <div style={S.card} data-testid="dash-card-handlers">
            <div style={S.cardH}>Registered Handlers</div>
            <div style={S.metric}>{s.registered_handlers ?? "—"}</div>
            <div style={S.metricSub}>ADR-0001 framework · zero-handler baseline by design</div>
          </div>

          <div style={S.card} data-testid="dash-card-cases">
            <div style={S.cardH}>SOC Cases Logged</div>
            <div style={S.metric}>{s.soc_cases_logged ?? "—"}</div>
            <div style={S.metricSub}>Corpus v1 · frozen 2026-02-28</div>
          </div>
        </div>

        <div style={S.quickBar}>
          <div style={S.quickTitle}>Quick Start</div>
          <Link to="/nivxforge/investigate" style={S.quickBtn} data-testid="dash-quick-investigate">Investigate an Artifact</Link>
          <Link to="/nivxforge/governance" style={S.quickBtnGhost} data-testid="dash-quick-governance">Open Governance</Link>
        </div>

        <div style={S.banner}>
          Metrics derived from <code>/api/nivxforge/preview/platform-health</code>.
          Analytical results are shared with Workspace — parity contract enforced (ADR-0006 §2.1).
        </div>
      </div>
    </NivxForgeLayout>
  );
}
