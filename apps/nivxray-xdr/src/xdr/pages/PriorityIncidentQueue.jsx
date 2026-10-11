import React, { useEffect, useState } from "react";
import { NxDataTable } from "@/xdr/nx";
import { projectionState } from "./controlCenterState";

const missing = <span className="cc-pq__missing">Not available</span>;
const known = (value) => value && !["unknown", "unset", "default"].includes(value);
const time = (value) => {
  const date = new Date(value || "");
  return Number.isFinite(date.getTime()) ? date.toISOString().replace("T", " ").slice(0, 19) + " UTC" : null;
};
export const investigationHref = (row) => typeof row?.id === "string" && row.id.trim()
  ? `/xdr/incidents/${encodeURIComponent(row.id)}` : null;

export function queueView(data, loading, now) {
  const state = projectionState(data);
  if (loading) return "loading";
  if (state === "loading") return "unavailable";
  if (state !== "ready" && state !== "empty") return state;
  const generated = Date.parse(data.generated_at || "");
  // A local freshness warning, not a server SLA or a telemetry health claim.
  if (!Number.isFinite(generated)) return "freshness_unknown";
  if (now - generated > 5 * 60 * 1000 || generated > now + 60 * 1000) return "stale";
  return state;
}

export const priorityQueueColumns = [
  { key: "priority", header: "Priority", value: (r) => known(r.priority) ? r.priority : null,
    render: (r) => known(r.priority) ? <span className="cc-pq__priority" data-priority={r.priority}>{r.priority}</span> : missing },
  { key: "incident", header: "Incident ID / title", value: (r) => `${r.id || ""} ${r.name || ""}`,
    render: (r) => <span className="cc-pq__incident"><strong>{r.name && r.name !== "(unnamed)" ? r.name : missing}</strong><span>{r.id || missing}</span></span> },
  // This projection does not expose entity fields. Do not infer them from a title.
  { key: "entity", header: "Affected entity", sortable: false, value: () => null, render: () => missing },
  { key: "source", header: "Detection source", value: (r) => known(r.detection_source) ? r.detection_source : null,
    render: (r) => known(r.detection_source) ? r.detection_source : missing },
  { key: "updated", header: "Updated (UTC)", value: (r) => time(r.updated_at) ? Date.parse(r.updated_at) : null,
    render: (r) => time(r.updated_at) || missing },
  { key: "state", header: "Status", value: (r) => r.state || null,
    render: (r) => r.state ? <span className="cc-pq__status">{String(r.state).replace(/_/g, " ")}</span> : missing },
  { key: "assignee", header: "Reported owner", value: (r) => r.assignee || null, render: (r) => r.assignee || missing },
  { key: "customer", header: "Tenant", value: (r) => known(r.customer) ? r.customer : null, render: (r) => known(r.customer) ? r.customer : missing },
];

export default function PriorityIncidentQueue({ data, loading, onNavigate }) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);
  const view = queueView(data, loading, now);
  const readable = ["ready", "empty", "stale", "freshness_unknown"].includes(view);
  const rows = readable ? data.rows : [];
  const open = (row) => {
    const href = investigationHref(row);
    if (readable && href) onNavigate(href);
  };
  const notices = {
    denied: "Access denied. The priority queue is not authorized for this request.",
    unavailable: data?.error ? "The priority queue could not load. Use Refresh to retry." : "Priority queue data is not available.",
    no_scope: "No authorized incident scope was returned. This is not a confirmed zero count.",
    loading: "Loading priority incidents… Previous results are hidden while the request refreshes.",
    stale: "Stale snapshot — generated more than 5 minutes ago or timestamp ahead of this browser. Refresh before relying on this queue.",
    freshness_unknown: "Snapshot freshness is not available. Refresh to request current results.",
  };
  return (
    <section className="cc-card cc-pq" aria-labelledby="cc-pq-title" aria-busy={loading} data-testid="cc-priority-queue">
      <div className="cc-card__h">
        <h2 className="cc-card__t" id="cc-pq-title">Priority incident queue</h2>
        <button type="button" className="cc-card__a cx-pill" onClick={() => onNavigate("/xdr/incidents?lens=high_priority")}>Open full queue</button>
      </div>
      <p className="cc-pq__scope">Open P1 / P2 incidents · Latest {readable ? rows.length : "—"} returned (up to 14). Search and sort apply to this snapshot only.</p>
      <p className="cc-pq__scope">{readable && time(data.generated_at) ? `Snapshot generated ${time(data.generated_at)}. ` : ""}Updated is the incident update time. Reported owner may be the submitting user; analyst assignment and affected entity are not independently provided.</p>
      {notices[view] && <p className="cc-pq__notice" role={view === "denied" || data?.error ? "alert" : "status"} data-testid={`cc-pq-${view}`}>{notices[view]}</p>}
      {readable && <div role="region" aria-label="Priority incident results">
        <label className="cc-pq__search-label" htmlFor="cc-pq-search">Search returned incidents</label>
        <NxDataTable rows={rows} columns={priorityQueueColumns} pageSize={7}
          rowKey={(r, i) => r.id || `missing-id-${i}`} onRowClick={open}
          searchPlaceholder="Search ID, title, priority, source, status, owner or tenant"
          searchInputId="cc-pq-search"
          testid="cc-priority-table"
          emptyTitle={rows.length ? "No matching incidents in this snapshot" : "No open P1/P2 incidents returned"}
          emptyHint="Other priorities or unassigned work may still exist. Open the full queue to investigate further."
          rowActions={(row) => <button type="button" className="cc-pq__open" disabled={!investigationHref(row)}
            aria-label={`Open investigation ${row.id || "unavailable"}`}
            onKeyDown={(event) => event.stopPropagation()}
            onClick={(event) => { event.stopPropagation(); open(row); }}>Open investigation</button>} />
      </div>}
    </section>
  );
}
