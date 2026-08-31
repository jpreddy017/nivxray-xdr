/**
 * XdrIncidentsPage · `/xdr/incidents`
 *
 * Phase 2 · Investigation-Aware Incident Queue.
 *
 * URL params (all optional, all URL-persisted, all shareable):
 *   ?lens=<id>          Phase-1 lens (critical, high_priority, ...)
 *   ?state=…            filter by lifecycle state
 *   ?priority=P1|P2|…   filter by priority
 *   ?severity=…         critical|high|medium|low|info
 *   ?verdict=…          malicious|suspicious|benign|unknown
 *   ?confidence=…       high|medium|low
 *   ?customer=…         tenant/customer id
 *   ?detection_source=… engine that produced the evidence
 *   ?technique=T####    filter by MITRE technique
 *   ?sort=…&order=…     column + direction
 *   ?view=<uuid>        pre-loaded saved view
 *
 * Owner-locked rules:
 *   - Queue is a READ MODEL.  NEVER invokes an engine.
 *   - Every unavailable field renders honest empty state (— or NOT_RUN).
 *   - Bulk operations require confirmation, write audit rows,
 *     never mutate canonical evidence.
 *   - Saved views are per-user; shareable via ?view=<id>.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { X, Filter as FilterIcon, ChevronDown, ChevronUp, Save, Trash2 } from "lucide-react";

import { useAuth } from "@/lib/auth";
import {
  listIncidents, bulkAssign, bulkState,
  listSavedViews, createSavedView, deleteSavedView,
} from "@/lib/incidentsApi";
import XdrShell from "@/xdr/XdrShell";


const LENS_LABELS = {
  critical: "Critical", high_priority: "High Priority",
  high_fidelity: "High Fidelity", unassigned: "Unassigned",
  in_progress_mine: "In Progress — Mine",
  customer_response: "Customer Response", on_hold: "On Hold",
  aging: "SLA / Aging Risk",
  recently_created: "Recently Created", recently_updated: "Recently Updated",
};

const PRIO_COLOR = { P1: "#f87171", P2: "#fb923c", P3: "#fbbf24",
                        P4: "#4ade80", P5: "#a3a3a3" };
const VERDICT_COLOR = { malicious: "#f87171", suspicious: "#fb923c",
                             benign: "#4ade80", unknown: "#a3a3a3" };
const STATE_COLOR = { new: "#22d3ee", in_progress: "#fbbf24",
                           on_hold: "#f472b6", resolved: "#4ade80",
                           closed: "#a3a3a3" };
const AI_COLOR = { NOT_RUN: "#525252", RUNNING: "#fbbf24",
                       COMPLETE: "#4ade80", PARTIAL: "#fb923c",
                       FAILED: "#f87171" };

const COLUMNS = [
  { id: "priority", label: "Priority", sort: "priority", w: 70 },
  { id: "severity", label: "Severity", sort: "severity", w: 90 },
  { id: "verdict", label: "Verdict", w: 100 },
  { id: "confidence", label: "Confidence", w: 90 },
  { id: "customer", label: "Customer", sort: "customer", w: 130 },
  { id: "detection_source", label: "Detection Source", w: 130 },
  { id: "evidence_count", label: "Evidence", w: 70 },
  { id: "techniques_top", label: "MITRE", w: 150 },
  { id: "sla_due_at", label: "SLA", sort: "sla_due_at", w: 130 },
  { id: "aging_seconds", label: "Aging", w: 70 },
  { id: "assignee", label: "Owner", sort: "assignee", w: 130 },
  { id: "state", label: "State", sort: "state", w: 90 },
  { id: "last_activity", label: "Last Activity", sort: "updated_at", w: 130 },
  { id: "auto_investigation", label: "Auto-Investigation", w: 120 },
  { id: "engine_results", label: "Engine Results", w: 110 },
];


function fmtAging(sec) {
  if (sec == null) return "—";
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec/60)}m`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h`;
  return `${Math.floor(sec/86400)}d`;
}


export default function XdrIncidentsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  // ── URL-persisted filters ───────────────────────────────────────
  const filters = {
    lens:             params.get("lens"),
    state:            params.get("state"),
    priority:         params.get("priority"),
    severity:         params.get("severity"),
    verdict:          params.get("verdict"),
    confidence:       params.get("confidence"),
    customer:         params.get("customer"),
    detection_source: params.get("detection_source"),
    technique:        params.get("technique"),
  };
  const sort  = params.get("sort")  || "updated_at";
  const order = params.get("order") || "desc";

  const [body, setBody]     = useState(null);
  const [loading, setL]     = useState(true);
  const [error, setError]   = useState(null);
  const [selected, setSel]  = useState(new Set());
  const [views, setViews]   = useState([]);
  const [viewName, setVName] = useState("");
  const [hidden, setHidden]  = useState(new Set());   // hidden columns

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const res = await listIncidents({ ...filters, sort, order, limit: 500 });
      setBody(res);
      setSel(new Set());
    } catch (e) {
      setError(e?.response?.data?.detail?.error
                  || e?.response?.data?.detail
                  || e?.message || "Failed to load.");
    } finally { setL(false); }
  }, [JSON.stringify(filters), sort, order]);

  const loadViews = useCallback(async () => {
    try { setViews((await listSavedViews()).views || []); } catch (_) {}
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadViews(); }, [loadViews]);

  // ── URL helpers ─────────────────────────────────────────────────
  const setParam = (k, v) => {
    const next = new URLSearchParams(params);
    if (v == null || v === "") next.delete(k); else next.set(k, v);
    setParams(next, { replace: true });
  };
  const clearAll = () => setParams(new URLSearchParams(), { replace: true });

  const rows = body?.incidents || [];
  const visibleCols = useMemo(() => COLUMNS.filter(c => !hidden.has(c.id)),
                                     [hidden]);

  const activeChips = Object.entries(filters).filter(([, v]) => v);

  // ── Bulk actions ────────────────────────────────────────────────
  const doBulkAssign = async () => {
    const assignee = prompt("Bulk assign — new owner email (blank to unassign):");
    if (assignee === null) return;
    if (!confirm(`Assign ${selected.size} incident(s) to "${assignee || "unassigned"}"?`)) return;
    await bulkAssign([...selected], assignee.trim() || null,
                       "bulk_assign from queue");
    await load();
  };
  const doBulkState = async () => {
    const st = prompt("Bulk state — target state (new|in_progress|on_hold|resolved|closed):");
    if (!st) return;
    if (!confirm(`Transition ${selected.size} incident(s) to "${st}"?`)) return;
    try {
      await bulkState([...selected], st.trim(), "bulk_state from queue");
      await load();
    } catch (e) {
      alert(e?.response?.data?.detail?.error || "Failed");
    }
  };

  // ── Save current view ───────────────────────────────────────────
  const saveView = async () => {
    if (!viewName.trim()) return;
    await createSavedView({
      name: viewName.trim(),
      filters: Object.fromEntries(Object.entries(filters).filter(([, v]) => v)),
      sort, order,
      lens: filters.lens || null,
      visible_columns: visibleCols.map(c => c.id),
    });
    setVName("");
    await loadViews();
  };
  const applyView = (v) => {
    const next = new URLSearchParams();
    Object.entries(v.filters || {}).forEach(([k, val]) => val && next.set(k, val));
    if (v.lens)  next.set("lens",  v.lens);
    if (v.sort)  next.set("sort",  v.sort);
    if (v.order) next.set("order", v.order);
    next.set("view", v.id);
    setParams(next, { replace: true });
    if (v.visible_columns?.length) {
      const shown = new Set(v.visible_columns);
      setHidden(new Set(COLUMNS.map(c => c.id).filter(id => !shown.has(id))));
    }
  };
  const removeView = async (v) => {
    if (!confirm(`Delete saved view "${v.name}"?`)) return;
    await deleteSavedView(v.id);
    await loadViews();
  };

  // ── Sort click ──────────────────────────────────────────────────
  const clickSort = (colSort) => {
    if (!colSort) return;
    if (sort === colSort) setParam("order", order === "desc" ? "asc" : "desc");
    else { setParam("sort", colSort); setParam("order", "desc"); }
  };

  return (
    <XdrShell activeTop="dashboards">
      <div style={headerRow}>
        <div>
          <h1 className="page-h1" data-testid="xdr-incidents-heading">
            {filters.lens ? `Incidents · ${LENS_LABELS[filters.lens] || filters.lens}` : "Incidents"}
          </h1>
          <div className="page-sub">
            Investigation-aware queue · projection of canonical evidence ·
            never runs an engine.
          </div>
        </div>
        <button className="btn ghost"
                   data-testid="xdr-incidents-back-to-mss"
                   onClick={() => navigate("/xdr/mss-dashboard")}
                   style={{ padding: "6px 10px", fontSize: 11,
                            fontFamily: "var(--mono)" }}>
          ← MSS Dashboard
        </button>
      </div>

      {/* ── Filter chip row ─────────────────────────────────────── */}
      <div style={chipRow} data-testid="xdr-incidents-filters">
        <FilterIcon size={11} style={{ color: "var(--purple)" }} />
        {activeChips.length === 0 && (
          <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                           color: "var(--text-dim)" }}>
            No filters — showing everything.
          </span>
        )}
        {activeChips.map(([k, v]) => (
          <span key={k} style={chip}
                  data-testid={`xdr-incidents-chip-${k}`}>
            <span style={chipK}>{k}:</span>
            <span style={chipV}>{v}</span>
            <button onClick={() => setParam(k, null)}
                       data-testid={`xdr-incidents-chip-clear-${k}`}
                       style={chipClose}>
              <X size={10} />
            </button>
          </span>
        ))}
        {activeChips.length > 0 && (
          <button className="btn ghost"
                     data-testid="xdr-incidents-clear-all"
                     onClick={clearAll}
                     style={{ padding: "2px 8px", fontSize: 10 }}>
            Clear all
          </button>
        )}
      </div>

      {/* ── Saved views bar ─────────────────────────────────────── */}
      <div style={savedRow} data-testid="xdr-incidents-saved-views">
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                         color: "var(--text-dim)" }}>
          SAVED VIEWS
        </span>
        {views.map(v => (
          <span key={v.id} style={savedChip}>
            <button onClick={() => applyView(v)}
                       data-testid={`xdr-incidents-view-${v.id}`}
                       style={savedName}>
              {v.name}
            </button>
            <button onClick={() => removeView(v)}
                       data-testid={`xdr-incidents-view-del-${v.id}`}
                       style={savedDel}>
              <Trash2 size={9} />
            </button>
          </span>
        ))}
        <input value={viewName} onChange={e => setVName(e.target.value)}
                placeholder="Name…"
                data-testid="xdr-incidents-view-name"
                style={viewInput} />
        <button onClick={saveView} disabled={!viewName.trim()}
                   data-testid="xdr-incidents-view-save"
                   style={saveBtn}>
          <Save size={10} /> Save current
        </button>
      </div>

      {/* ── Bulk-op bar ─────────────────────────────────────────── */}
      {selected.size > 0 && (
        <div style={bulkBar} data-testid="xdr-incidents-bulk-bar">
          <span>{selected.size} selected</span>
          <button onClick={doBulkAssign}
                     data-testid="xdr-incidents-bulk-assign"
                     style={bulkBtn}>Assign…</button>
          <button onClick={doBulkState}
                     data-testid="xdr-incidents-bulk-state"
                     style={bulkBtn}>Change state…</button>
          <button onClick={() => setSel(new Set())}
                     data-testid="xdr-incidents-bulk-clear"
                     style={bulkBtnGhost}>Clear</button>
        </div>
      )}

      {/* ── Loading / error ─────────────────────────────────────── */}
      {loading && <div className="x-empty">LOADING…</div>}
      {error && (
        <div className="x-empty"
              data-testid="xdr-incidents-error"
              style={{ color: "#ff9494" }}>{String(error)}</div>
      )}

      {/* ── Queue table ─────────────────────────────────────────── */}
      {!loading && !error && (
        <div style={{ overflowX: "auto", marginTop: 10 }}>
          <table style={tbl} data-testid="xdr-incidents-queue">
            <thead>
              <tr>
                <th style={{ ...th, width: 24 }}>
                  <input type="checkbox"
                            data-testid="xdr-incidents-select-all"
                            checked={rows.length > 0 && selected.size === rows.length}
                            onChange={e => setSel(e.target.checked
                              ? new Set(rows.map(r => r.id)) : new Set())} />
                </th>
                <th style={{ ...th, width: 100 }}>ID</th>
                <th style={{ ...th, width: 200 }}>Name</th>
                {visibleCols.map(c => (
                  <th key={c.id} style={{ ...th, width: c.w,
                                                cursor: c.sort ? "pointer" : "default" }}
                         onClick={() => clickSort(c.sort)}
                         data-testid={`xdr-incidents-col-${c.id}`}>
                    {c.label}
                    {c.sort && sort === c.sort && (
                      order === "desc" ? <ChevronDown size={10} /> : <ChevronUp size={10} />
                    )}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr><td colSpan={visibleCols.length + 3} className="x-empty"
                           data-testid="xdr-incidents-empty"
                           style={{ padding: 20 }}>
                  NO INCIDENTS MATCH THIS FILTER — honest empty state.
                </td></tr>
              )}
              {rows.map(r => (
                <tr key={r.id}
                       data-testid={`xdr-incidents-row-${r.id}`}
                       style={{ ...tr,
                                background: selected.has(r.id)
                                  ? "rgba(155,123,240,0.08)" : "transparent" }}>
                  <td style={td} onClick={e => e.stopPropagation()}>
                    <input type="checkbox"
                              data-testid={`xdr-incidents-select-${r.id}`}
                              checked={selected.has(r.id)}
                              onChange={e => {
                                const n = new Set(selected);
                                if (e.target.checked) n.add(r.id); else n.delete(r.id);
                                setSel(n);
                              }} />
                  </td>
                  <td style={{ ...td, fontFamily: "var(--mono)", cursor: "pointer" }}
                        onClick={() => navigate(`/xdr/incidents/${r.id}`)}>
                    {r.id?.slice(0, 10)}…
                  </td>
                  <td style={{ ...td, cursor: "pointer" }}
                        onClick={() => navigate(`/xdr/incidents/${r.id}`)}>
                    {r.name}
                  </td>
                  {visibleCols.map(c => (
                    <td key={c.id} style={td}
                           data-testid={`xdr-incidents-cell-${c.id}-${r.id}`}>
                      {renderCell(c.id, r)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {body?.invariant && (
        <div style={invariantNote}
              data-testid="xdr-incidents-invariant">{body.invariant}</div>
      )}
    </XdrShell>
  );
}


function renderCell(colId, r) {
  const dash = <span style={{ color: "var(--faint)" }}>—</span>;
  switch (colId) {
    case "priority":
      return r.priority?.code
        ? <span style={{ color: PRIO_COLOR[r.priority.code] || "var(--text)" }}>{r.priority.code}</span>
        : dash;
    case "severity":
      return r.severity || dash;
    case "verdict":
      return r.verdict?.stage2_label
        ? <span style={{ color: VERDICT_COLOR[r.verdict.stage2_label] || "var(--text)" }}>
            {r.verdict.stage2_label}
          </span>
        : <span style={{ color: "var(--faint)" }}>UNKNOWN</span>;
    case "confidence":
      return r.confidence || dash;
    case "customer":
      return <span style={{ fontFamily: "var(--mono)" }}>{r.customer}</span>;
    case "detection_source":
      return r.detection_source
        ? <span style={{ fontFamily: "var(--mono)" }}>{r.detection_source}</span>
        : dash;
    case "evidence_count":
      return (r.evidence_count ?? 0) > 0 ? r.evidence_count : dash;
    case "techniques_top":
      return r.techniques_top?.length
        ? <span style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
            {r.techniques_top.join(" · ")}
            {r.techniques_total > r.techniques_top.length
              && ` +${r.techniques_total - r.techniques_top.length}`}
          </span>
        : dash;
    case "sla_due_at":
      return r.sla_due_at
        ? r.sla_due_at.slice(0, 16).replace("T", " ")
        : dash;
    case "aging_seconds":
      return fmtAging(r.aging_seconds);
    case "assignee":
      return r.assignee
        ? <span style={{ fontFamily: "var(--mono)" }}>{r.assignee}</span>
        : <span style={{ color: "#fbbf24" }}>UNASSIGNED</span>;
    case "state":
      return <span style={{ color: STATE_COLOR[r.state] || "var(--text)" }}>{r.state}</span>;
    case "last_activity":
      return r.last_activity?.slice(0, 16).replace("T", " ") || dash;
    case "auto_investigation":
      return <span style={{ color: AI_COLOR[r.auto_investigation?.status] || "var(--faint)",
                              fontFamily: "var(--mono)", fontSize: 10 }}>
        {r.auto_investigation?.status || "NOT_RUN"}
      </span>;
    case "engine_results":
      return r.auto_investigation?.engines_total > 0
        ? `${r.auto_investigation.engines_ok}/${r.auto_investigation.engines_total}`
        : dash;
    default:
      return dash;
  }
}


// ── Styles ─────────────────────────────────────────────────────────
const headerRow = { display: "flex", justifyContent: "space-between",
                       alignItems: "flex-start", gap: 12, marginBottom: 4 };
const chipRow = { display: "flex", alignItems: "center",
                     gap: 6, flexWrap: "wrap", marginTop: 10, marginBottom: 6 };
const chip = { display: "inline-flex", alignItems: "center", gap: 6,
                  padding: "2px 8px", borderRadius: 3,
                  border: "1px solid var(--purple)",
                  background: "rgba(155,123,240,0.10)",
                  fontFamily: "var(--mono)", fontSize: 10 };
const chipK = { color: "var(--text-dim)" };
const chipV = { color: "var(--text)", fontWeight: 700 };
const chipClose = { background: "none", border: "none",
                        color: "var(--text-dim)", cursor: "pointer",
                        padding: 0, display: "flex" };
const savedRow = { display: "flex", alignItems: "center", gap: 6,
                      flexWrap: "wrap", marginTop: 6, marginBottom: 6,
                      padding: "6px 8px",
                      border: "1px dashed rgba(120,130,150,0.20)",
                      borderRadius: 4 };
const savedChip = { display: "inline-flex", alignItems: "center", gap: 4,
                        padding: "2px 4px", borderRadius: 3,
                        border: "1px solid rgba(120,130,150,0.25)",
                        background: "rgba(255,255,255,0.02)" };
const savedName = { background: "none", border: "none",
                        color: "var(--text)", fontFamily: "var(--mono)",
                        fontSize: 10, cursor: "pointer", padding: "0 4px" };
const savedDel = { background: "none", border: "none",
                       color: "#f87171", cursor: "pointer",
                       padding: "0 2px", display: "flex" };
const viewInput = { padding: "3px 6px", border: "1px solid rgba(120,130,150,0.30)",
                        background: "transparent", color: "var(--text)",
                        borderRadius: 3, fontFamily: "var(--mono)", fontSize: 10,
                        width: 100 };
const saveBtn = { display: "inline-flex", alignItems: "center", gap: 4,
                     padding: "3px 8px", fontSize: 10,
                     background: "rgba(155,123,240,0.14)",
                     border: "1px solid var(--purple)",
                     borderRadius: 3, color: "var(--text)",
                     cursor: "pointer", fontFamily: "var(--mono)" };
const bulkBar = { display: "flex", alignItems: "center", gap: 8,
                     padding: "6px 10px", marginTop: 8,
                     background: "rgba(155,123,240,0.12)",
                     border: "1px solid var(--purple)",
                     borderRadius: 4, fontFamily: "var(--mono)", fontSize: 11 };
const bulkBtn = { padding: "3px 10px", fontSize: 11,
                     background: "var(--purple)", border: "none",
                     color: "#000", cursor: "pointer", borderRadius: 3,
                     fontWeight: 700 };
const bulkBtnGhost = { padding: "3px 10px", fontSize: 11,
                          background: "transparent",
                          border: "1px solid rgba(255,255,255,0.15)",
                          color: "var(--text)", cursor: "pointer",
                          borderRadius: 3 };
const tbl = { width: "100%", borderCollapse: "collapse", fontSize: 11,
                 fontFamily: "var(--mono)" };
const th = { textAlign: "left", padding: "6px 8px",
                borderBottom: "1px solid rgba(120,130,150,0.20)",
                color: "var(--text-dim)", fontWeight: 600,
                letterSpacing: 0.5, fontSize: 10, whiteSpace: "nowrap" };
const tr = { transition: "background 100ms ease" };
const td = { padding: "6px 8px",
                borderBottom: "1px solid rgba(120,130,150,0.08)",
                color: "var(--text)", whiteSpace: "nowrap" };
const invariantNote = { marginTop: 22, padding: "8px 10px",
                            border: "1px dashed rgba(120,130,150,0.35)",
                            borderRadius: 4, fontFamily: "var(--mono)",
                            fontSize: 10, color: "var(--text-dim)",
                            letterSpacing: 0.25, lineHeight: 1.55 };
