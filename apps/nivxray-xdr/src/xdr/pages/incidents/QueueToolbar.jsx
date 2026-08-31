/**
 * QueueToolbar · Search · Filters · Saved Views · Customize Columns ·
 *                Time selector · CSV Export · Refresh.
 *
 * Emits callbacks up to the page — the toolbar itself is stateless
 * apart from its own open/closed menus.
 */
import React, { useEffect, useRef, useState } from "react";
import {
  Search, Filter, Bookmark, Columns3, Download, RefreshCw, Clock, Save,
  Trash2, Check, GripVertical,
} from "lucide-react";

const TIME_OPTIONS = [
  { key: "1d",  label: "Last 24 hours" },
  { key: "3d",  label: "Last 3 days"   },
  { key: "7d",  label: "Last 7 days"   },
  { key: "30d", label: "Last 30 days"  },
  { key: "6m",  label: "Last 6 months" },
  { key: "all", label: "All time"      },
];

function useOutsideClose(ref, onClose) {
  useEffect(() => {
    const h = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose(); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [ref, onClose]);
}

function Menu({ open, onClose, children, minWidth = 260 }) {
  const ref = useRef(null);
  useOutsideClose(ref, onClose);
  if (!open) return null;
  return (
    <div ref={ref} className="ql-menu" style={{ minWidth }}>
      {children}
    </div>
  );
}

export default function QueueToolbar({
  search, onSearchChange,
  time, onTimeChange,
  columns, hidden, columnOrder,
  onColumnToggle, onColumnMove, onColumnReset,
  savedViews, currentViewId,
  onApplyView, onDeleteView, onSaveView,
  onCsvExport, onRefresh,
  refreshing,
  onOpenFilters,
  activeFilterCount,
}) {
  const [colOpen, setColOpen] = useState(false);
  const [viewOpen, setViewOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const [dragKey, setDragKey] = useState(null);

  const handleDragStart = (id) => setDragKey(id);
  const handleDragOver = (e) => e.preventDefault();
  const handleDrop = (targetId) => {
    if (dragKey && dragKey !== targetId) onColumnMove(dragKey, targetId);
    setDragKey(null);
  };

  const orderedCols = columnOrder
    .map(id => columns.find(c => c.id === id))
    .filter(Boolean);

  return (
    <div className="ql-toolbar" data-testid="ql-toolbar">
      <div className="ql-search">
        <Search size={13} />
        <input
          type="text"
          placeholder="Search incidents · name · ID · owner · IOC…"
          value={search || ""}
          onChange={e => onSearchChange(e.target.value)}
          data-testid="ql-toolbar-search"
        />
      </div>

      <div className="ql-tb-right">
        <button
          type="button"
          className="ql-btn"
          onClick={onOpenFilters}
          data-testid="ql-toolbar-filters"
        >
          <Filter size={13} /> Filters
          {activeFilterCount > 0 && (
            <span style={{ marginLeft: 4, padding: "0 5px", background: "var(--ql-purple)",
                            color: "#fff", borderRadius: 999,
                            fontFamily: "var(--qs-mono)", fontSize: 10, fontWeight: 700 }}>
              {activeFilterCount}
            </span>
          )}
        </button>

        {/* Saved Views */}
        <div className="ql-menu-wrap">
          <button
            type="button"
            className="ql-btn"
            onClick={() => setViewOpen(o => !o)}
            data-testid="ql-toolbar-saved-views"
          >
            <Bookmark size={13} /> Saved Views
          </button>
          <Menu open={viewOpen} onClose={() => setViewOpen(false)}>
            <div className="ql-menu-title">Apply saved view</div>
            {savedViews.length === 0 && (
              <div style={{ padding: "6px 12px", color: "var(--ql-muted)",
                            fontSize: 11.5 }}>
                No saved views yet.
              </div>
            )}
            {savedViews.map(v => (
              <div key={v.id}
                    style={{ display: "flex", alignItems: "center" }}>
                <button
                  type="button"
                  className="ql-menu-item"
                  style={{ flex: 1 }}
                  onClick={() => { onApplyView(v); setViewOpen(false); }}
                  data-testid={`ql-toolbar-view-${v.id}`}
                >
                  {currentViewId === v.id && <Check size={12} color="var(--ql-purple)" />}
                  <span style={{ marginLeft: currentViewId === v.id ? 0 : 18 }}>
                    {v.name}
                  </span>
                </button>
                <button
                  type="button"
                  className="ql-menu-item danger"
                  style={{ width: 32, justifyContent: "center", flex: "none" }}
                  onClick={() => onDeleteView(v)}
                  data-testid={`ql-toolbar-view-del-${v.id}`}
                  title="Delete saved view"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
            <div className="ql-menu-sep" />
            <div className="ql-menu-title">Save current view</div>
            <div style={{ display: "flex", gap: 6, padding: "4px 10px 10px" }}>
              <input
                type="text"
                placeholder="Name this view…"
                value={viewName}
                onChange={e => setViewName(e.target.value)}
                data-testid="ql-toolbar-view-name"
                style={{
                  flex: 1, padding: "5px 8px",
                  border: "1px solid var(--ql-border)", borderRadius: 4,
                  fontFamily: "var(--qs-sans)", fontSize: 12, outline: "none",
                  background: "var(--ql-surface-2)",
                }}
              />
              <button
                type="button"
                className="ql-btn primary"
                onClick={async () => {
                  if (!viewName.trim()) return;
                  await onSaveView(viewName.trim());
                  setViewName(""); setViewOpen(false);
                }}
                disabled={!viewName.trim()}
                data-testid="ql-toolbar-view-save"
              >
                <Save size={12} /> Save
              </button>
            </div>
          </Menu>
        </div>

        {/* Customize Columns */}
        <div className="ql-menu-wrap">
          <button
            type="button"
            className="ql-btn"
            onClick={() => setColOpen(o => !o)}
            data-testid="ql-toolbar-customize-columns"
          >
            <Columns3 size={13} /> Customize
          </button>
          <Menu open={colOpen} onClose={() => setColOpen(false)} minWidth={280}>
            <div className="ql-menu-title">Columns · drag to reorder</div>
            {orderedCols.map(c => {
              const on = !hidden.has(c.id);
              return (
                <div
                  key={c.id}
                  draggable
                  onDragStart={() => handleDragStart(c.id)}
                  onDragOver={handleDragOver}
                  onDrop={() => handleDrop(c.id)}
                  style={{
                    opacity: dragKey === c.id ? 0.5 : 1,
                    background: dragKey && dragKey !== c.id
                      ? "var(--ql-surface-3)" : "transparent",
                    display: "flex", alignItems: "center",
                  }}
                  data-testid={`ql-toolbar-col-row-${c.id}`}
                >
                  <span className="ql-menu-drag" style={{ padding: "6px 6px 6px 12px" }}>
                    <GripVertical size={12} />
                  </span>
                  <button
                    type="button"
                    className="ql-menu-item"
                    style={{ flex: 1, paddingLeft: 4 }}
                    onClick={() => onColumnToggle(c.id)}
                    data-testid={`ql-toolbar-col-toggle-${c.id}`}
                  >
                    <span style={{
                      width: 14, height: 14, borderRadius: 3,
                      border: `1px solid ${on ? "var(--ql-purple)" : "var(--ql-border-hi)"}`,
                      background: on ? "var(--ql-purple)" : "transparent",
                      display: "inline-flex", alignItems: "center", justifyContent: "center",
                      color: "#fff",
                    }}>
                      {on && <Check size={10} />}
                    </span>
                    {c.label}
                  </button>
                </div>
              );
            })}
            <div className="ql-menu-sep" />
            <button
              type="button"
              className="ql-menu-item"
              onClick={() => { onColumnReset(); setColOpen(false); }}
              data-testid="ql-toolbar-col-reset"
              style={{ color: "var(--ql-purple)", fontWeight: 600 }}
            >
              Reset to default
            </button>
          </Menu>
        </div>

        {/* Time selector */}
        <div style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <Clock size={13} style={{ color: "var(--ql-muted)" }} />
          <select
            className="ql-select"
            value={time || "7d"}
            onChange={e => onTimeChange(e.target.value)}
            data-testid="ql-toolbar-time"
          >
            {TIME_OPTIONS.map(t =>
              <option key={t.key} value={t.key}>{t.label}</option>)}
          </select>
        </div>

        <button
          type="button"
          className="ql-btn"
          onClick={onCsvExport}
          data-testid="ql-toolbar-export"
          title="Export the current filtered view as CSV (max 10 000 rows)"
        >
          <Download size={13} /> Export
        </button>

        <button
          type="button"
          className="ql-btn"
          onClick={onRefresh}
          disabled={refreshing}
          data-testid="ql-toolbar-refresh"
          title="Refresh the queue"
        >
          {refreshing
            ? <span className="ql-inline-spinner" />
            : <RefreshCw size={13} />}
          Refresh
        </button>
      </div>
    </div>
  );
}
