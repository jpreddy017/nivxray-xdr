/**
 * NivXForge · Persistent left sidebar. Makes NivXForge feel like a platform
 * rather than a single page. All 8 top-level sections are visible.
 *
 * Presentation-only. No backend contract changes.
 */
import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import api from "../../lib/api";

const SECTIONS = [
  { key: "dashboard",      to: "/nivxforge/dashboard",      label: "Dashboard",         hint: "Overview & metrics" },
  { key: "investigate",    to: "/nivxforge/investigate",    label: "Investigate",       hint: "Decode · Verdict · IOCs" },
  { key: "threat-intel",   to: "/nivxforge/threat-intel",   label: "Threat Intelligence", hint: "IOC & infra lookup" },
  { key: "hunting",        to: "/nivxforge/hunting",        label: "Threat Hunting",    hint: "IOC / YARA / ATT&CK search" },
  { key: "knowledge",      to: "/nivxforge/knowledge",      label: "Knowledge Base",    hint: "Families · LOLBAS · ATT&CK" },
  { key: "reports",        to: "/nivxforge/reports",        label: "Reports",           hint: "SOC · IR · Executive" },
  { key: "history",        to: "/nivxforge/history",        label: "History",           hint: "Previous investigations" },
  { key: "governance",     to: "/nivxforge/governance",     label: "Governance",        hint: "Registry · ADRs · Corpus" },
];

const S = {
  aside: {
    width: 240, minHeight: "calc(100vh - 60px)",
    background: "var(--panel, #0f172a)",
    borderRight: "1px solid var(--border, #1e293b)",
    padding: "22px 12px 22px",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
    display: "flex", flexDirection: "column", gap: 6, boxSizing: "border-box",
  },
  brand: {
    padding: "0 10px 18px", marginBottom: 6,
    borderBottom: "1px solid var(--border, #1e293b)",
  },
  eyebrow: { fontSize: 10, letterSpacing: "0.28em", color: "var(--accent, #7dd3fc)", textTransform: "uppercase", fontWeight: 600 },
  brandName: { fontSize: 18, marginTop: 4, color: "var(--text, #e2e8f0)", fontWeight: 700, letterSpacing: "0.02em" },
  brandSub: { fontSize: 11, color: "var(--text-secondary, #94a3b8)", marginTop: 2 },
  item: {
    display: "block", padding: "10px 12px", borderRadius: 6,
    textDecoration: "none",
    color: "var(--text-secondary, #94a3b8)",
    border: "1px solid transparent",
    transition: "background 0.12s, color 0.12s, border-color 0.12s",
  },
  itemActive: {
    color: "var(--accent, #7dd3fc)",
    borderColor: "rgba(125,211,252,0.35)",
    background: "rgba(125,211,252,0.06)",
  },
  itemLabel: { fontSize: 13, letterSpacing: "0.06em", fontWeight: 600, textTransform: "uppercase" },
  itemHint: { fontSize: 10, color: "var(--text-secondary, #94a3b8)", marginTop: 3, letterSpacing: "0.02em", opacity: 0.75 },
  placeholderChip: {
    marginLeft: 6, display: "inline-block", padding: "1px 6px", borderRadius: 8,
    fontSize: 9, letterSpacing: "0.10em", color: "#facc15",
    border: "1px solid rgba(250,204,21,0.35)", background: "rgba(250,204,21,0.06)",
    verticalAlign: "middle",
  },
  footer: {
    marginTop: "auto", padding: "12px 10px 0", fontSize: 11,
    color: "var(--text-secondary, #94a3b8)",
    borderTop: "1px solid var(--border, #1e293b)",
  },
  healthLine: { display: "flex", alignItems: "center", gap: 8 },
  dot: { width: 6, height: 6, borderRadius: "50%" },
};

function isActive(section, pathname) {
  // /nivxforge or /nivxforge/ → Dashboard
  if (section.key === "dashboard" && (pathname === "/nivxforge" || pathname === "/nivxforge/" || pathname === "/nivxforge/dashboard")) return true;
  return pathname === section.to || pathname.startsWith(section.to + "/");
}

export default function NivxForgeSidebar() {
  const { pathname } = useLocation();
  const [health, setHealth] = useState(null);
  useEffect(() => {
    let alive = true;
    api.get("/nivxforge/preview/platform-health")
      .then((r) => { if (alive) setHealth(r.data); })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  const suite = health?.situational?.regression_suite || "unverified";
  const ok = /PASS/i.test(suite);

  return (
    <aside style={S.aside} data-testid="nivxforge-sidebar">
      <div style={S.brand}>
        <div style={S.eyebrow}>Platform</div>
        <div style={S.brandName}>Lab</div>
        <div style={S.brandSub}>Analyst Investigation Console</div>
      </div>

      {SECTIONS.map((s) => (
        <Link
          key={s.key}
          to={s.to}
          data-testid={`sidebar-${s.key}`}
          style={{ ...S.item, ...(isActive(s, pathname) ? S.itemActive : {}) }}
        >
          <div style={S.itemLabel}>
            {s.label}
            {s.placeholder ? <span style={S.placeholderChip} data-testid={`sidebar-${s.key}-soon`}>Soon</span> : null}
          </div>
          <div style={S.itemHint}>{s.hint}</div>
        </Link>
      ))}

      <div style={S.footer} data-testid="sidebar-footer">
        <div style={S.healthLine}>
          <span style={{ ...S.dot, background: ok ? "#4ade80" : "#94a3b8" }} />
          <span>{suite}</span>
        </div>
        <div style={{ marginTop: 4, opacity: 0.7 }}>read-only · derived</div>
      </div>
    </aside>
  );
}
