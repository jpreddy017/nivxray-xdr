/**
 * IncidentQueue — dense operational table shared by the XDR Dashboard
 * and `/xdr/incidents`.
 */
import React, { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Search } from "lucide-react";

const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious: "Malicious", suspicious: "Suspicious",
  benign: "Benign",       unknown:    "Unknown",
};
const FILTERS = [
  { key: "all",         label: "All" },
  { key: "new",         label: "New" },
  { key: "in_progress", label: "In Progress" },
  { key: "on_hold",     label: "On Hold" },
  { key: "resolved",    label: "Resolved" },
  { key: "closed",      label: "Closed" },
];

function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z"; }
  catch { return iso; }
}

export default function IncidentQueue({
  rows,
  q, onQChange,
  stateFilter, onStateChange,
  showToolbar = true,
  title = "Incident Queue",
  countHint,
}) {
  const navigate = useNavigate();
  const filtered = useMemo(() => {
    const needle = (q || "").trim().toLowerCase();
    return rows.filter((r) => {
      if (stateFilter && stateFilter !== "all" && r.state !== stateFilter) return false;
      if (!needle) return true;
      const hay = [r.number, r.name, r.assignee, r.tenant, r.severity]
                    .filter(Boolean).join(" ").toLowerCase();
      return hay.includes(needle);
    });
  }, [rows, q, stateFilter]);

  return (
    <section className="panel" style={{ overflow: "hidden" }} data-testid="xdr-incident-queue">
      <div className="row" style={{
        justifyContent: "space-between", padding: "10px 14px",
        borderBottom: "1px solid var(--border)", background: "var(--panel2)",
      }}>
        <div className="section-title">{title}</div>
        <div className="mono" style={{ color: "var(--faint)", fontSize: 10.5 }}>
          {countHint ?? `${filtered.length} of ${rows.length}`}
        </div>
      </div>

      {showToolbar && (
        <div className="queue-toolbar">
          <Search size={13} style={{ color: "var(--muted)" }} />
          <input
            placeholder="Search ID, title, device, user, owner…"
            value={q || ""}
            onChange={(e) => onQChange?.(e.target.value)}
            data-testid="xdr-queue-search"
          />
          <div style={{ flex: 1 }} />
          {FILTERS.map((f) => (
            <button
              key={f.key}
              className={`btn qf ${stateFilter === f.key ? "primary" : ""}`}
              onClick={() => onStateChange?.(f.key)}
              data-testid={`xdr-queue-filter-${f.key}`}
            >
              {f.label}
            </button>
          ))}
        </div>
      )}

      {filtered.length === 0 && (
        <div className="x-empty">No incidents match the current filter.</div>
      )}
      {filtered.length > 0 && (
        <table className="x-table" data-testid="xdr-queue-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Priority</th>
              <th>Severity</th>
              <th>Customer</th>
              <th>State</th>
              <th>Owner</th>
              <th>Updated</th>
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
                  onClick={() => navigate(`/xdr/incidents/${r.id}`)}
                  data-testid={`xdr-queue-row-${r.id}`}
                >
                  <td className="inc-id">{r.number}</td>
                  <td style={{ color: "var(--text)", fontWeight: 600 }}>{r.name}</td>
                  <td><span className={`prio ${prioCls}`}>{r.priority?.code}</span></td>
                  <td><span className={`badge ${sevCls}`}>{SEV_LABEL[r.severity] || r.severity}</span></td>
                  <td className="mono">{r.tenant}</td>
                  <td><span className={`status-pill state-${r.state}`}>{r.state.replace("_", " ")}</span></td>
                  <td className="mono">{r.assignee || "Unassigned"}</td>
                  <td className="mono" style={{ color: "var(--muted)" }}>{fmtDate(r.updated_at)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}
