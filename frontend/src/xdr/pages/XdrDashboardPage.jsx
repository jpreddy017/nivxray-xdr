/**
 * XdrDashboardPage · `/xdr` — Security Operations dashboard.
 *
 * KPI cards + Incident queue.  Backed by /api/incidents.
 */
import React, { useEffect, useState, useMemo, useCallback } from "react";
import { useAuth } from "@/lib/auth";
import { listIncidents } from "@/lib/incidentsApi";
import XdrShell        from "@/xdr/XdrShell";
import IncidentQueue   from "@/xdr/components/IncidentQueue";

export default function XdrDashboardPage() {
  const { user } = useAuth();
  const [rows, setRows]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [q, setQ]               = useState("");
  const [stateFilter, setState] = useState("all");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await listIncidents({ limit: 200 });
      setRows(res.incidents || []);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load incidents.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const kpi = useMemo(() => {
    const k = {
      open: 0, critical: 0, high: 0, medium: 0, low: 0,
      unassigned: 0, mine: 0, active_response: 0, resolved: 0,
    };
    const myEmail = user?.email;
    rows.forEach((r) => {
      if (r.state !== "closed" && r.state !== "resolved") k.open += 1;
      if (r.state === "resolved") k.resolved += 1;
      if (r.priority?.code === "P1") k.critical += 1;
      else if (r.priority?.code === "P2") k.high += 1;
      else if (r.priority?.code === "P3") k.medium += 1;
      else if (r.priority?.code === "P4") k.low += 1;
      if (!r.assignee || r.assignee === "Unassigned") k.unassigned += 1;
      if (r.assignee && myEmail && r.assignee === myEmail) k.mine += 1;
      if (r.state === "in_progress") k.active_response += 1;
    });
    return k;
  }, [rows, user?.email]);

  return (
    <XdrShell activeTop="dashboards">
      <h1 className="page-h1" data-testid="xdr-dashboard-heading">Security Operations</h1>
      <div className="page-sub">What requires attention now.</div>

      <div className="stat-grid" data-testid="xdr-dashboard-stats">
        <Stat label="Open Incidents"  value={kpi.open}            tone="info" />
        <Stat label="Critical"        value={kpi.critical}        tone="crit" />
        <Stat label="High"            value={kpi.high}            tone="high" />
        <Stat label="Unassigned"      value={kpi.unassigned}      tone="med" />
        <Stat label="My Queue"        value={kpi.mine}            tone="ok" />
        <Stat label="Active Response" value={kpi.active_response} tone="ok" />
        <Stat label="SLA at Risk"     value="N/A"                 tone="na"
               sub="No SLA model configured" />
        <Stat label="Resolved"        value={kpi.resolved}        tone="ok" />
      </div>

      {loading && <div className="x-empty">LOADING INCIDENTS…</div>}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}>{String(error)}</div>
      )}
      {!loading && !error && (
        <IncidentQueue
          rows={rows}
          q={q} onQChange={setQ}
          stateFilter={stateFilter} onStateChange={setState}
          title="Incident Queue"
        />
      )}
    </XdrShell>
  );
}

function Stat({ label, value, tone = "info", sub }) {
  return (
    <div className={`stat-card ${tone}`}>
      <div className="lbl">{label}</div>
      <div className="val">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}
