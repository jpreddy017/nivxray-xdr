/**
 * XdrIncidentsPage · `/xdr/incidents`
 *
 * Layer 2 · full product-quality rebuild of the primary analyst
 * landing page.  Defender-inspired light workspace + dark
 * investigation preview drawer + NivXRay purple accent.
 *
 * Composition:
 *   PriorityStrip · attention/lens tiles
 *   QueueToolbar  · search · filters · saved views · customize columns · time · CSV · refresh
 *   Active filter chips row
 *   StateTabs     · All · New · In Progress · On Hold · Resolved · Closed
 *   Bulk action bar (appears when ≥1 row selected)
 *   QueueTable    · sticky dense projection of canonical incidents
 *   IncidentPreviewDrawer · right-side dark peek panel
 *
 * Owner-locked rules:
 *   · The queue is a READ MODEL — never invokes an engine.
 *   · Every unavailable field renders honestly (— · NOT_RUN · NO EVIDENCE).
 *   · Bulk operations require confirmation, write audit rows,
 *     and never mutate canonical evidence.
 *   · Saved views are per-user and shareable via ?view=<id>.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { X } from "lucide-react";

import { useAuth } from "@/lib/auth";
import {
  listIncidents, bulkAssign, bulkState,
  listSavedViews, createSavedView, deleteSavedView,
} from "@/lib/incidentsApi";
import XdrShell from "@/xdr/XdrShell";

import { NxHeroHeader } from "@/xdr/nx";

import PriorityStrip           from "./incidents/PriorityStrip";
import QueueToolbar            from "./incidents/QueueToolbar";
import StateTabs               from "./incidents/StateTabs";
import QueueTable, {
  ALL_COLUMNS, DEFAULT_VISIBLE, DEFAULT_ORDER,
}                              from "./incidents/QueueTable";
import IncidentPreviewDrawer   from "./incidents/IncidentPreviewDrawer";
import FiltersPanel            from "./incidents/FiltersPanel";
import "./incidents/queue-theme.css";


const LENS_LABELS = {
  critical: "Critical", high_priority: "High Priority",
  high_fidelity: "High Fidelity", unassigned: "Unassigned",
  in_progress_mine: "In Progress — Mine",
  customer_response: "Customer Response", on_hold: "On Hold",
  aging: "SLA / Aging Risk",
  recently_created: "Recently Created", recently_updated: "Recently Updated",
};

const FILTER_KEYS = [
  "priority", "severity", "verdict", "confidence",
  "customer", "detection_source", "technique",
];

const TIME_WINDOW_MS = {
  "1d":  86400_000,
  "3d":  3 * 86400_000,
  "7d":  7 * 86400_000,
  "30d": 30 * 86400_000,
  "6m":  180 * 86400_000,
  all:   null,
};

// ── CSV export (client-side · uses the currently-loaded rows) ──────
function toCSV(rows, cols) {
  const header = ["ID", "Number", "Name", ...cols.map(c => c.label)];
  const esc = (s) => {
    const v = s == null ? "" : String(s);
    return /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
  };
  const lines = [header.join(",")];
  for (const r of rows.slice(0, 10000)) {
    const row = [r.id, r.number, r.name];
    for (const c of cols) {
      switch (c.id) {
        case "priority":       row.push(r.priority?.code); break;
        case "severity":       row.push(r.severity); break;
        case "verdict":        row.push(r.verdict?.stage2_label); break;
        case "confidence":     row.push(r.confidence); break;
        case "customer":       row.push(r.customer); break;
        case "detection_source":row.push(r.detection_source); break;
        case "evidence_count": row.push(r.evidence_count); break;
        case "techniques_top": row.push((r.techniques_top || []).join("|")); break;
        case "sla_due_at":     row.push(r.sla_due_at); break;
        case "aging_seconds":  row.push(r.aging_seconds); break;
        case "assignee":       row.push(r.assignee); break;
        case "state":          row.push(r.state); break;
        case "last_activity":  row.push(r.last_activity); break;
        case "auto_investigation": row.push(r.auto_investigation?.status); break;
        case "engine_results": row.push(
          r.auto_investigation?.engines_total
            ? `${r.auto_investigation.engines_ok}/${r.auto_investigation.engines_total}`
            : "");
          break;
        default: row.push("");
      }
    }
    lines.push(row.map(esc).join(","));
  }
  return lines.join("\n");
}

function downloadCSV(csv, filename) {
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}


export default function XdrIncidentsPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();

  // ── URL-persisted state ─────────────────────────────────────────
  const urlLens     = params.get("lens");
  const urlState    = params.get("state");
  const urlSearch   = params.get("q") || "";
  const urlTime     = params.get("time") || "7d";
  const urlSort     = params.get("sort")  || "updated_at";
  const urlOrder    = params.get("order") || "desc";
  const urlViewId   = params.get("view");

  const filters = useMemo(() => {
    const out = {};
    FILTER_KEYS.forEach(k => { out[k] = params.get(k) || null; });
    return out;
  }, [params]);

  // ── Local state ─────────────────────────────────────────────────
  const [rows, setRows]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [refreshing, setRefresh] = useState(false);
  const [error, setError]       = useState(null);
  const [selected, setSelected] = useState(new Set());
  const [previewId, setPrevId]  = useState(null);
  const [views, setViews]       = useState([]);
  const [filterOpen, setFilterOpen] = useState(false);
  const [invariant, setInvariant]   = useState(null);

  // Column visibility + order (persisted in localStorage).
  const [hidden, setHidden] = useState(() => {
    try {
      const raw = localStorage.getItem("xdr.queue.hiddenCols");
      if (raw) return new Set(JSON.parse(raw));
    } catch (_) { /* noop */ }
    return new Set(ALL_COLUMNS.filter(c => c.defaultHidden).map(c => c.id));
  });
  const [columnOrder, setColumnOrder] = useState(() => {
    try {
      const raw = localStorage.getItem("xdr.queue.columnOrder");
      if (raw) {
        const parsed = JSON.parse(raw);
        // Only trust it if it still covers every known column.
        const known = new Set(DEFAULT_ORDER);
        const ok = parsed.length === DEFAULT_ORDER.length
          && parsed.every(id => known.has(id));
        if (ok) return parsed;
      }
    } catch (_) { /* noop */ }
    return DEFAULT_ORDER.slice();
  });

  useEffect(() => {
    try {
      localStorage.setItem("xdr.queue.hiddenCols", JSON.stringify([...hidden]));
      localStorage.setItem("xdr.queue.columnOrder", JSON.stringify(columnOrder));
    } catch (_) { /* noop */ }
  }, [hidden, columnOrder]);

  // ── Helpers to mutate URL params ────────────────────────────────
  const setParam = useCallback((k, v) => {
    const next = new URLSearchParams(params);
    if (v == null || v === "") next.delete(k); else next.set(k, v);
    setParams(next, { replace: true });
  }, [params, setParams]);

  const setManyParams = useCallback((updates) => {
    const next = new URLSearchParams(params);
    Object.entries(updates).forEach(([k, v]) => {
      if (v == null || v === "") next.delete(k); else next.set(k, v);
    });
    setParams(next, { replace: true });
  }, [params, setParams]);

  const clearAllFilters = useCallback(() => {
    const next = new URLSearchParams();
    if (urlSort  !== "updated_at") next.set("sort",  urlSort);
    if (urlOrder !== "desc")       next.set("order", urlOrder);
    if (urlTime  !== "7d")         next.set("time",  urlTime);
    setParams(next, { replace: true });
  }, [urlSort, urlOrder, urlTime, setParams]);

  // ── Data load ───────────────────────────────────────────────────
  const load = useCallback(async ({ silent = false } = {}) => {
    if (silent) setRefresh(true); else setLoading(true);
    setError(null);
    try {
      const res = await listIncidents({
        ...filters,
        lens:  urlLens  || null,
        state: urlState || null,
        sort:  urlSort,
        order: urlOrder,
        limit: 500,
      });
      setRows(res.incidents || []);
      setInvariant(res.invariant || null);
      setSelected(new Set());
    } catch (e) {
      setError(e?.response?.data?.detail?.error
        || e?.response?.data?.detail
        || e?.message || "Failed to load incidents.");
    } finally {
      setLoading(false); setRefresh(false);
    }
  }, [filters, urlLens, urlState, urlSort, urlOrder]);

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [load]);

  const loadViews = useCallback(async () => {
    try { setViews((await listSavedViews()).views || []); } catch (_) { /* noop */ }
  }, []);
  useEffect(() => { loadViews(); }, [loadViews]);

  // ── Client-side search + time filtering ─────────────────────────
  const visibleRows = useMemo(() => {
    let out = rows;
    const q = urlSearch.trim().toLowerCase();
    if (q) {
      out = out.filter(r => {
        const bag = [
          r.name, r.id, r.number, r.customer, r.assignee,
          r.detection_source, r.priority?.code, r.severity,
          r.verdict?.stage2_label, r.state,
          ...(r.techniques_top || []),
        ].filter(Boolean).join(" ").toLowerCase();
        return bag.includes(q);
      });
    }
    const win = TIME_WINDOW_MS[urlTime];
    if (win) {
      const cutoff = Date.now() - win;
      out = out.filter(r => {
        const ts = r.last_activity || r.updated_at || r.created_at;
        if (!ts) return true;
        const t = Date.parse(ts);
        return Number.isFinite(t) ? t >= cutoff : true;
      });
    }
    return out;
  }, [rows, urlSearch, urlTime]);

  // ── Client-side counts per lifecycle state ──────────────────────
  const stateCounts = useMemo(() => {
    const c = { new: 0, in_progress: 0, on_hold: 0, resolved: 0, closed: 0 };
    (visibleRows || []).forEach(r => {
      const s = r.state || "new";
      if (c[s] != null) c[s] += 1;
    });
    return c;
  }, [visibleRows]);

  // Columns in display order.
  const orderedCols = useMemo(
    () => columnOrder.map(id => ALL_COLUMNS.find(c => c.id === id)).filter(Boolean),
    [columnOrder]);
  const visibleColumns = useMemo(
    () => orderedCols.filter(c => !hidden.has(c.id)),
    [orderedCols, hidden]);

  // ── Column customization callbacks ──────────────────────────────
  const toggleColumn = (id) => {
    setHidden(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const moveColumn = (from, to) => {
    setColumnOrder(prev => {
      const next = prev.slice();
      const fi = next.indexOf(from);
      const ti = next.indexOf(to);
      if (fi < 0 || ti < 0) return prev;
      next.splice(fi, 1);
      next.splice(ti, 0, from);
      return next;
    });
  };
  const resetColumns = () => {
    setHidden(new Set(ALL_COLUMNS.filter(c => c.defaultHidden).map(c => c.id)));
    setColumnOrder(DEFAULT_ORDER.slice());
  };

  // ── Sort ────────────────────────────────────────────────────────
  const onSort = (colSort) => {
    if (urlSort === colSort) {
      setParam("order", urlOrder === "desc" ? "asc" : "desc");
    } else {
      setManyParams({ sort: colSort, order: "desc" });
    }
  };

  // ── Selection + preview ─────────────────────────────────────────
  const toggleSelect = (id, on) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (on) next.add(id); else next.delete(id);
      return next;
    });
  };
  const selectAll = (on) => {
    setSelected(on ? new Set(visibleRows.map(r => r.id)) : new Set());
  };

  const previewIndex = useMemo(
    () => visibleRows.findIndex(r => r.id === previewId),
    [visibleRows, previewId]);

  const previewRow = previewIndex >= 0 ? visibleRows[previewIndex] : null;

  const onRowClick = (r) => setPrevId(r.id);
  const onNameClick = (r) => navigate(`/xdr/incidents/${r.id}`);
  const onDrawerOpen = () => {
    if (previewRow) navigate(`/xdr/incidents/${previewRow.id}`);
  };
  const onDrawerPrev = () => {
    if (previewIndex > 0) setPrevId(visibleRows[previewIndex - 1].id);
  };
  const onDrawerNext = () => {
    if (previewIndex >= 0 && previewIndex < visibleRows.length - 1) {
      setPrevId(visibleRows[previewIndex + 1].id);
    }
  };

  // ── Bulk operations ─────────────────────────────────────────────
  const doBulkAssign = async () => {
    if (selected.size === 0) return;
    const assignee = window.prompt(
      "Bulk assign — new owner email (blank to unassign):",
      "");
    if (assignee === null) return;
    if (!window.confirm(
      `Assign ${selected.size} incident(s) to "${assignee || "unassigned"}"?`)) return;
    try {
      await bulkAssign([...selected], assignee.trim() || null,
                          "bulk_assign from queue");
      await load({ silent: true });
    } catch (e) {
      window.alert(e?.response?.data?.detail?.error || "Bulk assign failed.");
    }
  };

  const doBulkState = async () => {
    if (selected.size === 0) return;
    const target = window.prompt(
      "Bulk state — target state (new|in_progress|on_hold|resolved|closed):",
      "in_progress");
    if (!target) return;
    if (!window.confirm(
      `Transition ${selected.size} incident(s) to "${target}"?`)) return;
    try {
      await bulkState([...selected], target.trim(),
                          "bulk_state from queue");
      await load({ silent: true });
    } catch (e) {
      window.alert(e?.response?.data?.detail?.error || "Bulk state failed.");
    }
  };

  // ── Saved views ─────────────────────────────────────────────────
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
      setHidden(new Set(ALL_COLUMNS.map(c => c.id).filter(id => !shown.has(id))));
    }
  };
  const removeView = async (v) => {
    if (!window.confirm(`Delete saved view "${v.name}"?`)) return;
    await deleteSavedView(v.id);
    await loadViews();
  };
  const onSaveView = async (name) => {
    await createSavedView({
      name,
      filters: Object.fromEntries(
        Object.entries(filters).filter(([, v]) => v)),
      sort: urlSort, order: urlOrder,
      lens: urlLens || null,
      visible_columns: visibleColumns.map(c => c.id),
    });
    await loadViews();
  };

  // ── CSV export ──────────────────────────────────────────────────
  const doExportCsv = () => {
    const csv = toCSV(visibleRows, visibleColumns);
    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    downloadCSV(csv, `nivxray-incidents-${stamp}.csv`);
  };

  // ── Priority strip lens click ───────────────────────────────────
  const onLensClick = (lensId) => {
    if (urlLens === lensId) setParam("lens", null);
    else setParam("lens", lensId);
  };

  // ── Filters ─────────────────────────────────────────────────────
  const applyFilters = (next) => {
    setManyParams(next);
  };

  const activeChips = [
    urlLens  && ["lens",  urlLens],
    urlState && ["state", urlState],
    ...FILTER_KEYS.map(k => filters[k] && [k, filters[k]]).filter(Boolean),
  ].filter(Boolean);

  return (
    <XdrShell>
      <div className="xdr-queue-l2" data-testid="xdr-incidents-l2">
        {/* Hero header — first-5-seconds identity */}
        <NxHeroHeader
          eyebrow="ANALYST OPERATIONS"
          title="Incidents"
          description="Investigation-aware queue · projection of canonical evidence · never runs an engine · missing data stays honest."
          metrics={[
            { label: "All", value: (rows || []).length, tone: "neutral" },
            { label: "Selected", value: selected.size || null, tone: "purple" },
            urlLens ? { label: "Lens", value: (LENS_LABELS[urlLens] || urlLens), tone: "purple" } : null,
          ].filter(Boolean)}
          action={(
            <button
              type="button"
              className="ql-btn"
              onClick={() => navigate("/xdr/mss-dashboard")}
              data-testid="xdr-incidents-mss"
            >
              MSS Dashboard
            </button>
          )}
          provenance={<span>workspace_cases.live</span>}
        />

        {/* Priority strip */}
        <PriorityStrip activeLens={urlLens} onLensClick={onLensClick} />

        {/* Toolbar */}
        <QueueToolbar
          search={urlSearch}
          onSearchChange={(v) => setParam("q", v)}
          time={urlTime}
          onTimeChange={(v) => setParam("time", v)}
          columns={ALL_COLUMNS}
          hidden={hidden}
          columnOrder={columnOrder}
          onColumnToggle={toggleColumn}
          onColumnMove={moveColumn}
          onColumnReset={resetColumns}
          savedViews={views}
          currentViewId={urlViewId}
          onApplyView={applyView}
          onDeleteView={removeView}
          onSaveView={onSaveView}
          onCsvExport={doExportCsv}
          onRefresh={() => load({ silent: true })}
          refreshing={refreshing}
          onOpenFilters={() => setFilterOpen(true)}
          activeFilterCount={FILTER_KEYS.filter(k => filters[k]).length}
        />

        {/* Active-filter chip row */}
        <div className="ql-chips" data-testid="xdr-incidents-filters">
          {activeChips.length === 0 && (
            <span className="ql-empty-chip">
              No filters — showing all incidents in the selected time window.
            </span>
          )}
          {activeChips.map(([k, v]) => (
            <span key={k} className="ql-chip"
                    data-testid={`xdr-incidents-chip-${k}`}>
              <b>{k}:</b> {v}
              <button
                type="button"
                className="ql-chip-x"
                onClick={() => setParam(k, null)}
                data-testid={`xdr-incidents-chip-clear-${k}`}
                title={`Remove ${k}`}
              >
                <X size={11} />
              </button>
            </span>
          ))}
          {activeChips.length > 0 && (
            <button
              type="button"
              className="ql-btn ghost"
              onClick={clearAllFilters}
              data-testid="xdr-incidents-clear-all"
              style={{ padding: "3px 8px", fontSize: 11 }}
            >
              Clear all
            </button>
          )}
        </div>

        {/* State tabs */}
        <StateTabs
          current={urlState}
          counts={stateCounts}
          onChange={(k) => setParam("state", k)}
        />

        {(urlSort !== "updated_at" || urlOrder !== "desc") && (
          <div style={{ padding: "6px 12px",
                          background: "var(--ql-surface)",
                          borderLeft: "1px solid var(--ql-border)",
                          borderRight: "1px solid var(--ql-border)",
                          borderBottom: "1px solid var(--ql-border)" }}>
            <span className="ql-sort-marker" data-testid="xdr-incidents-sort-marker">
              Sorted by <b>{urlSort}</b> · {urlOrder === "desc" ? "↓" : "↑"}
              <button
                type="button"
                onClick={() => setManyParams({ sort: "updated_at", order: "desc" })}
                data-testid="xdr-incidents-sort-clear"
                style={{ marginLeft: 6, background: "transparent", border: "none",
                          color: "var(--nx-purple)", fontWeight: 700,
                          fontFamily: "var(--qs-mono)", fontSize: 10, cursor: "pointer" }}
              >
                Reset
              </button>
            </span>
          </div>
        )}

        {/* Bulk actions bar */}
        {selected.size > 0 && (
          <div className="ql-bulk" data-testid="xdr-incidents-bulk-bar">
            <span className="ql-bulk-count">
              {selected.size} selected
            </span>
            <button type="button" className="ql-btn primary"
                     onClick={doBulkAssign}
                     data-testid="xdr-incidents-bulk-assign">
              Assign owner
            </button>
            <button type="button" className="ql-btn"
                     onClick={doBulkState}
                     data-testid="xdr-incidents-bulk-state">
              Change state
            </button>
            <button type="button" className="ql-btn ghost"
                     onClick={() => setSelected(new Set())}
                     data-testid="xdr-incidents-bulk-clear"
                     style={{ marginLeft: "auto" }}>
              Clear selection
            </button>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="ql-error" data-testid="xdr-incidents-error">
            {String(error)}
          </div>
        )}

        {/* Table */}
        <QueueTable
          rows={visibleRows}
          visibleColumns={visibleColumns}
          selected={selected}
          allSelected={visibleRows.length > 0 && selected.size === visibleRows.length}
          onToggleSelect={toggleSelect}
          onSelectAll={selectAll}
          previewId={previewId}
          onRowClick={onRowClick}
          onNameClick={onNameClick}
          onCellDrill={(field, value) => setParam(field, value)}
          sort={urlSort}
          order={urlOrder}
          onSort={onSort}
          loading={loading}
        />

        {invariant && (
          <div className="ql-invariant" data-testid="xdr-incidents-invariant">
            {invariant}
          </div>
        )}

        {/* Preview drawer */}
        <IncidentPreviewDrawer
          incident={previewRow}
          onClose={() => setPrevId(null)}
          onOpen={onDrawerOpen}
          onPrev={onDrawerPrev}
          onNext={onDrawerNext}
          hasPrev={previewIndex > 0}
          hasNext={previewIndex >= 0 && previewIndex < visibleRows.length - 1}
          position={previewIndex >= 0 ? previewIndex + 1 : null}
          total={visibleRows.length}
        />

        {/* Filters panel */}
        <FiltersPanel
          open={filterOpen}
          onClose={() => setFilterOpen(false)}
          filters={filters}
          onApply={applyFilters}
        />
      </div>
    </XdrShell>
  );
}
