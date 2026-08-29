/**
 * IncidentsListPage · `/incidents` — NivXRay ONE XDR Console skin.
 *
 * Dense operational queue.  Reads workspace_cases through /api/incidents.
 * Matches the owner-supplied XDR console reference exactly (colours,
 * chip styles, table densities, filter toolbar).
 */
import React, { useEffect, useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, Search, AlertOctagon, Inbox } from "lucide-react";

import Header from "@/components/Header";
import { listIncidents } from "@/lib/incidentsApi";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";
import "./xdr.css";

// ── Chip helpers (severity + priority) ─────────────────────────────
const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious:  "Malicious",
  suspicious: "Suspicious",
  benign:     "Benign",
  unknown:    "Unknown",
};

const QUEUE_FILTERS = [
  { key: "all",         label: "All" },
  { key: "new",         label: "New" },
  { key: "in_progress", label: "In Progress" },
  { key: "on_hold",     label: "On Hold" },
  { key: "resolved",    label: "Resolved" },
  { key: "closed",      label: "Closed" },
];

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z";
  } catch { return iso; }
}

export default function IncidentsListPage() {
  const navigate = useNavigate();
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

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (stateFilter !== "all" && r.state !== stateFilter) return false;
      if (!needle) return true;
      const hay = [r.number, r.name, r.assignee, r.tenant, r.severity]
                    .filter(Boolean).join(" ").toLowerCase();
      return hay.includes(needle);
    });
  }, [rows, q, stateFilter]);

  const counts = useMemo(() => {
    const c = { total: rows.length, new: 0, in_progress: 0,
                  on_hold: 0, resolved: 0, closed: 0, p1: 0, p2: 0 };
    rows.forEach((r) => {
      if (c[r.state] != null) c[r.state] += 1;
      if (r.priority?.code === "P1") c.p1 += 1;
      if (r.priority?.code === "P2") c.p2 += 1;
    });
    return c;
  }, [rows]);

  return (
    <div className="xdr-scope">
      <Header />
      <main data-testid={T.listPage} className="x-container">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <div className="grow">
            <div className="section-title">Operations · Incidents</div>
            <h1 className="x-h1">Incident Queue</h1>
            <div className="x-subtle">
              Dense operational view of every saved incident.
              Row → canonical Incident shell. Backed by <span className="mono" style={{ color: "var(--xcyan)" }}>workspace_cases</span> — no parallel model.
            </div>
          </div>
          <button
            className="btn"
            data-testid={T.listRefresh}
            onClick={load}
            disabled={loading}
          >
            <RefreshCw size={12} className={loading ? "spin" : ""} />
            REFRESH
          </button>
        </div>

        {/* KPI stat grid (reference §stat-grid) */}
        <div className="stat-grid">
          <StatCard label="Total" value={counts.total} />
          <StatCard label="P1 Critical" value={counts.p1} accent="var(--xred)" />
          <StatCard label="P2 High" value={counts.p2} accent="var(--xamber)" />
          <StatCard label="New" value={counts.new} accent="var(--xcyan)" />
          <StatCard label="In Progress" value={counts.in_progress} accent="var(--xamber)" />
          <StatCard label="Resolved" value={counts.resolved} accent="var(--xmint)" />
        </div>

        <section className="panel" style={{ overflow: "hidden" }}>
          <div className="queue-toolbar">
            <Search size={13} style={{ color: "var(--xmuted)" }} />
            <input
              placeholder="Search by number, name, assignee, tenant…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              data-testid="incidents-list-search"
            />
            <div style={{ flex: 1 }} />
            {QUEUE_FILTERS.map((f) => (
              <button
                key={f.key}
                className={`btn qf ${stateFilter === f.key ? "primary" : ""}`}
                data-testid={`incidents-list-filter-${f.key}`}
                onClick={() => setState(f.key)}
              >
                {f.label}
              </button>
            ))}
          </div>

          {loading && (
            <div data-testid={T.listLoading} className="x-empty">LOADING INCIDENTS…</div>
          )}
          {!loading && error && (
            <div data-testid={T.listError} className="x-empty" style={{ color: "#ff9494" }}>
              <AlertOctagon size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
              {String(error)}
            </div>
          )}
          {!loading && !error && filtered.length === 0 && (
            <div data-testid={T.listEmptyState} className="x-empty">
              <Inbox size={16} style={{ opacity: .6, verticalAlign: "middle", marginRight: 6 }} />
              {rows.length === 0
                ? "No incidents yet. Save a case from the Workspace to create one."
                : "No incidents match the current filter."}
            </div>
          )}
          {!loading && !error && filtered.length > 0 && (
            <table className="x-table" data-testid={T.listTable}>
              <thead>
                <tr>
                  <th>Number</th>
                  <th>Priority</th>
                  <th>Severity</th>
                  <th>Name</th>
                  <th>Tenant</th>
                  <th>Assigned To</th>
                  <th>State</th>
                  <th>Latest Updated</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => {
                  const sevCls = SEV_CLASS[r.severity] || "sev-info";
                  const prioCls = (r.priority?.code || "P5").toLowerCase();
                  return (
                    <tr
                      key={r.id}
                      className="rowlink"
                      data-testid={T.listRow(r.id)}
                      onClick={() => navigate(`/incidents/${r.id}`)}
                    >
                      <td className="inc-id">{r.number}</td>
                      <td><span className={`prio ${prioCls}`}>{r.priority?.code}</span></td>
                      <td><span className={`badge ${sevCls}`}>{SEV_LABEL[r.severity] || r.severity}</span></td>
                      <td style={{ color: "var(--xtext)", fontWeight: 600 }}>{r.name}</td>
                      <td className="mono">{r.tenant}</td>
                      <td className="mono">{r.assignee || "—"}</td>
                      <td><span className={`status-pill state-${r.state}`}>{r.state.replace("_", " ")}</span></td>
                      <td className="mono" style={{ color: "var(--xmuted)" }}>{fmtDate(r.updated_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </main>
    </div>
  );
}

function StatCard({ label, value, accent }) {
  return (
    <div className="stat-card">
      <div className="lbl">{label}</div>
      <div className="val" style={accent ? { color: accent } : undefined}>{value}</div>
    </div>
  );
}
