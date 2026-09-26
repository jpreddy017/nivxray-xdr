/**
 * QueryHuntPanel — Workspace Query/Hunt MVP (2026-08-11).
 *
 * Optional entry point for a SCOPED sub-view over the same canonical
 * investigation evidence the Timeline MVP consumes.
 *
 * Contract (locked as regression):
 *   · Additive UI · does NOT modify the default Workspace investigation
 *     experience.  Original investigation stays exactly as it was.
 *   · Consumes `POST /api/die/query`.  No parallel event model.
 *   · Result rows share the same shape as Timeline events so future
 *     Process-Tree / Graph views can consume the same records.
 *   · No fabrication · every visible row carries a real timestamp
 *     and (when a MITRE mapping applies) the P0.2 evidence_ref.
 */
import React, { useMemo, useState } from "react";
import api from "@/lib/api";

const S = {
  wrap:   { padding: 12, background: "var(--bg-card, #0f1420)", borderRadius: 8,
            border: "1px solid var(--border-subtle, #1f2937)", color: "var(--fg, #e5e7eb)" },
  head:   { display: "flex", justifyContent: "space-between", alignItems: "flex-start",
            gap: 12, marginBottom: 10, flexWrap: "wrap" },
  title:  { fontSize: 15, fontWeight: 600, letterSpacing: 0.2 },
  sub:    { fontSize: 12, opacity: 0.7 },
  formGrid: { display: "grid", gap: 8, marginBottom: 10,
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))" },
  field:  { display: "flex", flexDirection: "column", gap: 3 },
  label:  { fontSize: 11, opacity: 0.6 },
  input:  { padding: "6px 8px", borderRadius: 4, fontSize: 12,
            background: "rgba(0,0,0,0.25)",
            border: "1px solid var(--border-subtle, #1f2937)",
            color: "inherit", outline: "none" },
  actions: { display: "flex", gap: 8, marginBottom: 8, alignItems: "center" },
  btn:    { padding: "6px 14px", borderRadius: 4, fontSize: 12, fontWeight: 600,
            cursor: "pointer", border: "1px solid #374151",
            background: "rgba(59,130,246,0.15)", color: "#93c5fd" },
  btnAlt: { padding: "6px 14px", borderRadius: 4, fontSize: 12,
            cursor: "pointer", border: "1px solid var(--border-subtle, #374151)",
            background: "transparent", color: "inherit" },
  status: { fontSize: 12, opacity: 0.7 },
  err:    { fontSize: 12, color: "#f87171" },
  summary: { fontSize: 12, opacity: 0.85, margin: "4px 0 8px" },
  view:   { display: "flex", gap: 4, marginLeft: "auto" },
  viewBtn: (active) => ({
    padding: "4px 10px", borderRadius: 4, fontSize: 11, cursor: "pointer",
    border: "1px solid " + (active ? "#3b82f6" : "var(--border-subtle, #374151)"),
    background: active ? "rgba(59,130,246,0.15)" : "transparent",
    color: active ? "#93c5fd" : "inherit",
  }),
  table:  { width: "100%", borderCollapse: "collapse", fontSize: 11.5 },
  th:     { textAlign: "left", padding: "6px 8px", borderBottom: "1px solid var(--border-subtle, #1f2937)",
            opacity: 0.7, fontWeight: 500 },
  td:     { padding: "6px 8px", borderBottom: "1px solid rgba(255,255,255,0.04)",
            verticalAlign: "top", fontFamily: "ui-monospace, SFMono-Regular, monospace",
            whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
            maxWidth: 240 },
  row:    { display: "grid", gridTemplateColumns: "150px 80px 1fr",
            gap: 10, padding: "8px 10px", borderRadius: 6,
            background: "rgba(255,255,255,0.02)",
            border: "1px solid var(--border-subtle, #1f2937)" },
  badge: (level) => {
    const c = { high:  { bg:"rgba(239,68,68,0.20)",  fg:"#fca5a5" },
                medium:{ bg:"rgba(234,179,8,0.20)",  fg:"#fde68a" },
                low:   { bg:"rgba(148,163,184,0.20)",fg:"#cbd5e1" } }[level]
             || { bg:"rgba(148,163,184,0.20)", fg:"#cbd5e1" };
    return { padding:"2px 8px", borderRadius:999, fontSize:10.5, fontWeight:600,
             letterSpacing:0.3, textAlign:"center", background:c.bg, color:c.fg };
  },
  ts:     { fontSize: 11.5, fontFamily: "ui-monospace, SFMono-Regular, monospace",
            color: "var(--fg-muted, #9ca3af)" },
  empty:  { fontSize: 12, opacity: 0.7, padding: "6px 0" },
};

const FIELDS = [
  { key: "host",       label: "Host / Src Host",                  hint: "partial match, e.g. DMZ01" },
  { key: "user",       label: "User",                              hint: "partial match" },
  { key: "action",     label: "Action",                            hint: "block / blocked / detect / detected / quarantine / allow" },
  { key: "category",   label: "Category",                          hint: "partial match" },
  { key: "process",    label: "Process / File name",               hint: "partial match, e.g. winlogon" },
  { key: "parent",     label: "Parent process",                    hint: "partial match" },
  { key: "file_path",  label: "File path",                         hint: "partial path" },
  { key: "file_hash",  label: "SHA-256 hash",                      hint: "partial hash OK (first 12+ chars)" },
  { key: "mitre",      label: "MITRE technique",                   hint: "exact id, e.g. T1055 or T1055.012" },
  { key: "confidence", label: "Confidence",                        hint: "high / medium / low" },
  { key: "date_from",  label: "Date from",                          hint: "ISO-8601 e.g. 2026-08-03" },
  { key: "date_to",    label: "Date to",                            hint: "ISO-8601 e.g. 2026-08-04" },
];


function ConfidenceBadge({ level }) {
  return <span style={S.badge(level)} data-testid={`qh-conf-${level}`}>{level || "unknown"}</span>;
}

function ScopedTimelineView({ rows }) {
  if (!rows?.length) return <div style={S.empty} data-testid="qh-scoped-timeline-empty">No events in result set.</div>;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}
         data-testid="qh-scoped-timeline">
      {rows.map((r, i) => (
        <div key={`${r.timestamp}-${r.evidence_ref || i}`} style={S.row}
             data-testid={`qh-scoped-timeline-row-${i}`}>
          <div style={S.ts}>{r.timestamp}</div>
          <ConfidenceBadge level={r.confidence} />
          <div>
            <div style={{ fontSize: 12.5, fontWeight: 500 }}>
              {r.event_type}{r.process ? ` · ${r.process}` : ""}{r.host ? ` · ${r.host}` : ""}
            </div>
            <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11, opacity: 0.75 }}>
              {r.user && <span>user {r.user}</span>}
              {r.mitre?.length ? <span>mitre {r.mitre.map(m => m.id).join(", ")}</span> : null}
              {r.evidence_ref && <span>ev {r.evidence_ref}</span>}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}


function ProcessTreeView({ rows }) {
  // Group rows into parent-child chains.  Each observed edge is
  // (parent_process → process) from a single event.  We NEVER
  // manufacture edges — the tree only shows relationships the
  // underlying evidence explicitly recorded.
  const edges = rows.filter(r => (r.parent_process || "").trim() && (r.process || "").trim());
  if (!edges.length) {
    return (
      <div style={S.empty} data-testid="qh-process-tree-empty">
        No parent-process evidence in the result set. Process Tree cannot be
        constructed from this query.
      </div>
    );
  }
  // Group by (host + parent).
  const groups = {};
  edges.forEach(r => {
    const key = `${r.host || "(unknown host)"} ▸ ${r.parent_process}`;
    (groups[key] = groups[key] || []).push(r);
  });
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}
         data-testid="qh-process-tree">
      {Object.entries(groups).map(([groupKey, kids], gi) => (
        <div key={groupKey} data-testid={`qh-process-tree-group-${gi}`}
             style={{ padding: 10, borderRadius: 6,
                      background: "rgba(255,255,255,0.02)",
                      border: "1px solid var(--border-subtle, #1f2937)" }}>
          <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
            {groupKey}
          </div>
          <div style={{ paddingLeft: 14, borderLeft: "2px dashed rgba(255,255,255,0.15)",
                        display: "flex", flexDirection: "column", gap: 4 }}>
            {kids.map((k, i) => (
              <div key={`${k.timestamp}-${i}`}
                   data-testid={`qh-process-tree-child-${gi}-${i}`}
                   style={{ display: "flex", gap: 10, fontSize: 11.5, alignItems: "center" }}>
                <span style={{ opacity: 0.55, fontFamily: "ui-monospace, SFMono-Regular, monospace" }}>
                  ↳ {k.timestamp}
                </span>
                <span style={{ fontWeight: 500 }}>{k.process}</span>
                <ConfidenceBadge level={k.confidence} />
                {k.mitre?.length ? (
                  <span style={{ opacity: 0.75 }}>{k.mitre.map(m => m.id).join(", ")}</span>
                ) : null}
                {k.evidence_ref && (
                  <span style={{ opacity: 0.6,
                                 fontFamily: "ui-monospace, SFMono-Regular, monospace" }}>
                    ev {k.evidence_ref}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}


function RelationshipGraphView({ payload }) {
  const rows  = payload?.results || [];
  if (!rows.length) return <div style={S.empty}>No events.</div>;
  const hosts = payload.matched_hosts     || [];
  const users = payload.matched_users     || [];
  const procs = payload.matched_processes || [];
  // Only build edges the evidence explicitly recorded.
  const edges = [];
  rows.forEach(r => {
    if (r.host && r.user)                        edges.push(["host:"+r.host,       "user:"+r.user,       "on"]);
    if (r.user && r.process)                     edges.push(["user:"+r.user,       "process:"+r.process, "ran"]);
    if (r.parent_process && r.process)           edges.push(["process:"+r.parent_process, "process:"+r.process, "spawned"]);
  });
  // Dedupe edges (rare — same event contributes once).
  const uniq = Array.from(new Set(edges.map(e => e.join("|")))).map(s => s.split("|"));

  return (
    <div style={{ display: "grid", gap: 10 }} data-testid="qh-graph">
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 }}>
        {[
          { label: "Hosts",     items: hosts, testid: "qh-graph-hosts" },
          { label: "Users",     items: users, testid: "qh-graph-users" },
          { label: "Processes", items: procs, testid: "qh-graph-processes" },
        ].map(col => (
          <div key={col.label} data-testid={col.testid}
               style={{ padding: 10, borderRadius: 6,
                        background: "rgba(255,255,255,0.02)",
                        border: "1px solid var(--border-subtle, #1f2937)" }}>
            <div style={{ fontSize: 11, fontWeight: 600, opacity: 0.65,
                          marginBottom: 6, letterSpacing: 0.5 }}>
              {col.label.toUpperCase()} · {col.items.length}
            </div>
            {col.items.length === 0
              ? <div style={{ fontSize: 11, opacity: 0.5 }}>none</div>
              : col.items.map(it => (
                  <div key={it} style={{ fontSize: 11.5,
                                         fontFamily: "ui-monospace, SFMono-Regular, monospace",
                                         padding: "2px 0" }}>
                    {it}
                  </div>))}
          </div>
        ))}
      </div>
      <div data-testid="qh-graph-edges"
           style={{ padding: 10, borderRadius: 6,
                    background: "rgba(255,255,255,0.02)",
                    border: "1px solid var(--border-subtle, #1f2937)" }}>
        <div style={{ fontSize: 11, fontWeight: 600, opacity: 0.65,
                      marginBottom: 6, letterSpacing: 0.5 }}>
          EVIDENCE-BACKED EDGES · {uniq.length}
        </div>
        {uniq.length === 0
          ? <div style={{ fontSize: 11, opacity: 0.5 }}>
              No relationships supported by the current result set.
            </div>
          : (
            <div style={{ display: "flex", flexDirection: "column", gap: 4,
                          fontSize: 11.5,
                          fontFamily: "ui-monospace, SFMono-Regular, monospace" }}>
              {uniq.map((e, i) => (
                <div key={i} data-testid={`qh-graph-edge-${i}`}>
                  {e[0]}  ─{e[2]}→  {e[1]}
                </div>
              ))}
            </div>)}
      </div>
    </div>
  );
}

function TableView({ rows }) {
  if (!rows?.length) return <div style={S.empty} data-testid="qh-table-empty">No events in result set.</div>;
  return (
    <div style={{ overflowX: "auto" }} data-testid="qh-table-scroll">
      <table style={S.table} data-testid="qh-table">
        <thead>
          <tr>
            {["Timestamp","Host","User","Process","Parent","Action","MITRE","Ev","Conf"].map(h =>
              <th key={h} style={S.th}>{h}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={`${r.timestamp}-${r.evidence_ref || i}`} data-testid={`qh-table-row-${i}`}>
              <td style={S.td} title={r.timestamp}>{r.timestamp}</td>
              <td style={S.td}>{r.host || ""}</td>
              <td style={S.td}>{r.user || ""}</td>
              <td style={S.td} title={r.process || ""}>{r.process || ""}</td>
              <td style={S.td} title={r.parent_process || ""}>{r.parent_process || ""}</td>
              <td style={S.td}>{(r.event_type || "").split(".").pop()}</td>
              <td style={S.td}>{(r.mitre || []).map(m => m.id).join(",")}</td>
              <td style={S.td} title={r.evidence_ref || ""}>{r.evidence_ref || ""}</td>
              <td style={S.td}><ConfidenceBadge level={r.confidence} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}


export default function QueryHuntPanel({ rawInput }) {
  const [filters, setFilters] = useState({});
  const [status, setStatus]   = useState("idle");   // idle · loading · ready · error
  const [error, setError]     = useState(null);
  const [payload, setPayload] = useState(null);
  const [view, setView]       = useState(null);     // null → follows payload.default_view

  const activeView = view || payload?.default_view || "timeline";

  const summary = useMemo(() => {
    if (!payload) return null;
    const parts = [];
    parts.push(`${payload.event_count} of ${payload.total_available} events`);
    if (payload.matched_hosts?.length) parts.push(`${payload.matched_hosts.length} hosts`);
    if (payload.matched_users?.length) parts.push(`${payload.matched_users.length} users`);
    if (payload.parent_child_edges)    parts.push(`${payload.parent_child_edges} parent→child edges`);
    return parts.join(" · ");
  }, [payload]);

  const runQuery = () => {
    if (!rawInput || !rawInput.trim()) {
      setError("Query is scoped to the current investigation. Paste or upload input first.");
      setStatus("error");
      return;
    }
    setStatus("loading"); setError(null); setView(null); // reset view → auto
    api.post("/die/query", { input: rawInput, filters })
      .then(r => { setPayload(r.data); setStatus("ready"); })
      .catch(err => {
        setError(String(err?.response?.data?.detail || err?.message || err));
        setStatus("error");
      });
  };

  const clearQuery = () => {
    setFilters({}); setPayload(null); setStatus("idle"); setError(null); setView(null);
  };

  const update = (k) => (e) => setFilters(prev => ({ ...prev, [k]: e.target.value }));

  return (
    <div style={S.wrap} data-testid="query-hunt-panel">
      <div style={S.head}>
        <div>
          <div style={S.title}>Query / Hunt</div>
          <div style={S.sub}>
            Optional scoped sub-view over the current investigation.
            Results project into Table · Timeline; process-tree &amp;
            relationship-graph coming next.
          </div>
        </div>
      </div>

      <div style={S.formGrid} data-testid="query-hunt-form">
        {FIELDS.map(f => (
          <label key={f.key} style={S.field}>
            <span style={S.label}>{f.label}</span>
            <input
              style={S.input}
              type="text"
              value={filters[f.key] || ""}
              onChange={update(f.key)}
              placeholder={f.hint || ""}
              title={f.hint || ""}
              data-testid={`qh-filter-${f.key}`}
            />
          </label>
        ))}
      </div>

      <div style={S.actions}>
        <button style={S.btn} onClick={runQuery}
                disabled={status === "loading"}
                data-testid="qh-run">
          {status === "loading" ? "Running…" : "Run query"}
        </button>
        <button style={S.btnAlt} onClick={clearQuery} data-testid="qh-clear">Clear</button>
        {payload && payload.event_count > 0 && (
          <div style={S.view}>
            {[
              { key: "table",        label: "Table" },
              { key: "timeline",     label: "Timeline" },
              { key: "process_tree", label: "Process Tree" },
              { key: "graph",        label: "Graph" },
            ].map(v => {
              const supported = !!(payload.capabilities || {})[v.key];
              const active = activeView === v.key && supported;
              return (
                <button key={v.key}
                        style={{
                          ...S.viewBtn(active),
                          opacity: supported ? 1 : 0.35,
                          cursor: supported ? "pointer" : "not-allowed",
                        }}
                        disabled={!supported}
                        title={supported ? "" : "No evidence in this result set supports this view"}
                        onClick={() => supported && setView(v.key)}
                        data-testid={`qh-view-${v.key}`}>
                  {v.label}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {status === "error" && <div style={S.err} data-testid="qh-error">{error}</div>}
      {status === "loading" && <div style={S.status} data-testid="qh-loading">Applying filters…</div>}

      {status === "ready" && (
        <>
          <div style={S.summary} data-testid="qh-summary">{summary}</div>
          {payload.event_count === 0 && (
            <div style={{ ...S.empty, marginBottom: 8, opacity: 0.85,
                          padding: 12, borderRadius: 6,
                          border: "1px dashed var(--border-subtle, #1f2937)",
                          background: "rgba(0,0,0,0.15)" }}
                 data-testid="qh-zero-viz">
              No events match the filters you set — no evidence-backed
              visualization can be constructed for this query.
              {Object.keys(payload.filters_applied || {}).length > 1
                ? " Try removing one filter at a time to see which is over-narrow."
                : " Try a shorter substring, a different action verb (block / detect / quarantine / allow), or check the timestamp range."}
              <div style={{ marginTop: 6, opacity: 0.6, fontSize: 11 }}>
                The underlying investigation ({payload.total_available} events)
                is unchanged — this Query result is scoped, not destructive.
              </div>
            </div>
          )}
          {payload.event_count > 0 && (
            <>
              {activeView === "table"        && <TableView          rows={payload.results} />}
              {activeView === "timeline"     && <ScopedTimelineView rows={payload.results} />}
              {activeView === "process_tree" && <ProcessTreeView    rows={payload.results} />}
              {activeView === "graph"        && <RelationshipGraphView payload={payload} />}
            </>
          )}
        </>
      )}
    </div>
  );
}
