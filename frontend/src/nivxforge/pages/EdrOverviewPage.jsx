/**
 * NivXForge EDR Overview page · `/edr`
 *
 * When arrived from an Incident, shows the endpoint context first
 * (device / user / time / customer) so the analyst never loses their
 * operational anchor.  Content otherwise is a landing page pointing
 * at the surfaces available inside this console.
 */
import React from "react";
import { Link } from "react-router-dom";
import { Radar, ShieldAlert, GitBranch, FileText, Wifi, ArrowRight } from "lucide-react";

import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";

const QUICK_LINKS = [
  { key: "trajectory",   label: "Device Trajectory", to: "/edr/trajectory",  icon: Radar,        available: true,
    hint: "Temporal canvas for endpoint activity — the primary EDR investigation surface." },
  { key: "detections",   label: "Detections",        to: "/edr/detections",  icon: ShieldAlert,  available: false,
    hint: "Detection engine output for this endpoint." },
  { key: "process-tree", label: "Process Tree",      to: "/edr/process-tree", icon: GitBranch,   available: false,
    hint: "Parent → child process relationships for the incident window." },
  { key: "files",        label: "Files",             to: "/edr/files",       icon: FileText,     available: false,
    hint: "File-system evidence: writes, drops, signers, hashes." },
  { key: "network",      label: "Network",           to: "/edr/network",     icon: Wifi,         available: false,
    hint: "Endpoint-observed network connections + DNS." },
];

export default function EdrOverviewPage() {
  const ctx = useIncidentContext();
  return (
    <NivXForgeConsole activeTab="overview">
      <h1 className="page-h1" data-testid="edr-overview-heading">Endpoint Overview</h1>
      <div className="page-sub">
        {ctx.incident_id
          ? "Opened from an operational incident — endpoint context is pinned at the top of every page in this console."
          : "Endpoint state, recent detections, and pivots into the operational surfaces of NivXForge EDR."}
      </div>

      <div className="stat-grid" data-testid="edr-overview-stats">
        <Stat label="Device"       value={ctx.device || "Not provided"}  tone={ctx.device ? "cyan"  : "faint"} />
        <Stat label="Customer"     value={ctx.tenant || "Not provided"}  tone={ctx.tenant ? "cyan"  : "faint"} />
        <Stat label="User"         value={ctx.user   || "Not provided"}  tone={ctx.user   ? "cyan"  : "faint"} />
        <Stat label="Agent Status" value="Reserved · later slice"                            tone="faint" />
        <Stat label="Isolation"    value="Not isolated"                                       tone="mint" />
        <Stat label="Risk"         value={ctx.incident_id ? "See Incident" : "—"}             tone="faint" />
      </div>

      <div className="section-title" style={{ marginBottom: 8 }}>Console Surfaces</div>
      <div style={{
        display: "grid",
        gap: 10,
        gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
      }} data-testid="edr-overview-surface-cards">
        {QUICK_LINKS.map((q) => (
          <QuickCard key={q.key} q={q} carry={ctx} />
        ))}
      </div>
    </NivXForgeConsole>
  );
}

function Stat({ label, value, tone = "cyan" }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="lbl">{label}</div>
      <div className="val">{value}</div>
    </div>
  );
}

function QuickCard({ q, carry }) {
  const Icon = q.icon;
  const carryQs = React.useMemo(() => {
    const p = new URLSearchParams();
    if (carry.incident_id) p.set("incident_id", carry.incident_id);
    if (carry.device)      p.set("device", carry.device);
    if (carry.tenant)      p.set("tenant", carry.tenant);
    if (carry.user)        p.set("user", carry.user);
    return p.toString();
  }, [carry.incident_id, carry.device, carry.tenant, carry.user]);

  const to = carryQs ? `${q.to}?${carryQs}` : q.to;

  return (
    <div className="panel" style={{ padding: 14, opacity: q.available ? 1 : 0.7 }}
         data-testid={`edr-overview-card-${q.key}`}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
        <Icon size={14} style={{ color: q.available ? "var(--mint)" : "var(--faint)" }} />
        <span style={{
          fontSize: 10.5, letterSpacing: ".3px",
          textTransform: "uppercase", fontWeight: 800,
          color: q.available ? "var(--mint)" : "var(--faint)",
        }}>
          {q.available ? "Available" : "Reserved · later slice"}
        </span>
      </div>
      <div style={{ fontSize: 14, fontWeight: 700, color: "var(--text)" }}>{q.label}</div>
      <div style={{ marginTop: 4, fontSize: 11, color: "var(--muted)", lineHeight: 1.55 }}>
        {q.hint}
      </div>
      {q.available ? (
        <Link
          to={to}
          className="btn mint"
          style={{ marginTop: 10, alignSelf: "flex-start", textDecoration: "none" }}
          data-testid={`edr-overview-open-${q.key}`}
        >
          Open <ArrowRight size={11} />
        </Link>
      ) : (
        <button className="btn" disabled style={{ marginTop: 10 }}>Not available</button>
      )}
    </div>
  );
}
