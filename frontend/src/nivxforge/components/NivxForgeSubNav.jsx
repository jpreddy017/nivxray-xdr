/**
 * NivXForge · sub-navigation strip.
 *
 * Sits at the top of every /nivxforge/* page. Purely presentational —
 * routes to Investigate (analyst surface) and Governance (existing
 * preview cards). Reads a compact health pill from
 * /api/nivxforge/preview/platform-health if available; falls back to
 * silent absence.
 */
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import api from "../../lib/api";

const S = {
  wrap: {
    display: "flex", alignItems: "center", justifyContent: "space-between",
    padding: "10px 28px", borderBottom: "1px solid var(--border, #1e293b)",
    background: "var(--panel, #0f172a)",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    fontSize: 12, letterSpacing: "0.06em",
  },
  tabs: { display: "flex", gap: 4 },
  tab: {
    padding: "6px 14px", textDecoration: "none",
    color: "var(--text-secondary, #94a3b8)",
    border: "1px solid transparent", borderRadius: 4,
    textTransform: "uppercase", letterSpacing: "0.12em", fontWeight: 500,
  },
  tabActive: {
    color: "var(--accent, #7dd3fc)", borderColor: "var(--accent, #7dd3fc)",
    background: "rgba(125,211,252,0.05)",
  },
  pill: {
    display: "inline-flex", alignItems: "center", gap: 8,
    padding: "4px 10px", borderRadius: 12, fontSize: 11,
    border: "1px solid rgba(74,222,128,0.35)",
    color: "#4ade80", background: "rgba(34,197,94,0.08)",
    textDecoration: "none",
  },
  pillMuted: {
    display: "inline-flex", alignItems: "center", gap: 8,
    padding: "4px 10px", borderRadius: 12, fontSize: 11,
    border: "1px solid var(--border, #1e293b)",
    color: "var(--text-secondary, #94a3b8)",
    textDecoration: "none",
  },
};

export default function NivxForgeSubNav({ active }) {
  const location = useLocation();
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let alive = true;
    api.get("/nivxforge/preview/platform-health")
      .then((r) => { if (alive) setHealth(r.data); })
      .catch(() => { /* silent — pill just disappears */ });
    return () => { alive = false; };
  }, []);

  const isInvestigate = active === "investigate"
    || location.pathname === "/nivxforge"
    || location.pathname.startsWith("/nivxforge/investigate");
  const isGovernance = active === "governance"
    || location.pathname.startsWith("/nivxforge/governance");

  const pill = health?.situational
    ? { text: `${health.situational.regression_suite} · ${health.situational.workspace_protection}`, ok: true }
    : null;

  return (
    <div style={S.wrap} data-testid="nivxforge-subnav">
      <div style={S.tabs}>
        <Link
          to="/nivxforge/investigate"
          style={{ ...S.tab, ...(isInvestigate ? S.tabActive : {}) }}
          data-testid="subnav-investigate"
        >Investigate</Link>
        <Link
          to="/nivxforge/governance"
          style={{ ...S.tab, ...(isGovernance ? S.tabActive : {}) }}
          data-testid="subnav-governance"
        >Governance</Link>
      </div>
      {pill ? (
        <Link to="/nivxforge/governance" style={pill.ok ? S.pill : S.pillMuted} data-testid="subnav-health-pill">
          <span style={{ width: 6, height: 6, borderRadius: "50%", background: pill.ok ? "#4ade80" : "#94a3b8" }} />
          {pill.text}
        </Link>
      ) : null}
    </div>
  );
}
