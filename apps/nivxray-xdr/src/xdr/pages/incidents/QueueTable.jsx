/**
 * QueueTable · dense, sticky-header, sortable incident table.
 *
 * The table is a PURE presentation layer — it consumes projected
 * rows returned by /api/incidents and never fabricates a value.
 * Missing values render honestly (— · NOT_RUN · NOT AVAILABLE).
 */
import React from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import {
  PriorityChip, SeverityChip, VerdictChip, StateChip,
} from "@/xdr/components/chips";

// Default column set + sortable metadata.  All 15 columns known
// to the backend projection; visible/hidden and ordering is
// controlled by the toolbar's Customize Columns dropdown.
export const ALL_COLUMNS = [
  { id: "priority",          label: "Priority",          sort: "priority",     w:  84 },
  { id: "severity",          label: "Severity",          sort: "severity",     w: 100 },
  { id: "name",              label: "Incident",          sort: null,           w: 260 },
  { id: "verdict",           label: "Verdict",           sort: null,           w: 108 },
  { id: "customer",          label: "Customer",          sort: "customer",     w: 130 },
  { id: "detection_source",  label: "Detection Source",  sort: null,           w: 140 },
  { id: "evidence_count",    label: "Evidence",          sort: null,           w:  86 },
  { id: "techniques_top",    label: "MITRE",             sort: null,           w: 160 },
  { id: "sla_due_at",        label: "SLA",               sort: "sla_due_at",   w: 150 },
  { id: "assignee",          label: "Owner",             sort: "assignee",     w: 140 },

  // Hidden by default (Customize Columns to enable)
  { id: "confidence",        label: "Confidence",        sort: null,           w: 100, defaultHidden: true },
  { id: "aging_seconds",     label: "Aging",             sort: null,           w:  80, defaultHidden: true },
  { id: "state",             label: "State",             sort: "state",        w: 110, defaultHidden: true },
  { id: "last_activity",     label: "Last Activity",     sort: "updated_at",   w: 150, defaultHidden: true },
  { id: "auto_investigation",label: "Auto-Investigation",sort: null,           w: 140, defaultHidden: true },
  { id: "engine_results",    label: "Engine Results",    sort: null,           w: 120, defaultHidden: true },
];

export const DEFAULT_VISIBLE = ALL_COLUMNS
  .filter(c => !c.defaultHidden).map(c => c.id);

export const DEFAULT_ORDER = ALL_COLUMNS.map(c => c.id);

function fmtAging(sec) {
  if (sec == null) return "—";
  if (sec < 60)    return `${sec}s`;
  if (sec < 3600)  return `${Math.floor(sec/60)}m`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h`;
  return `${Math.floor(sec/86400)}d`;
}

function fmtISO(iso) {
  if (!iso) return "—";
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 16).replace("T", " ") : s;
}

const dash = <span className="ql-td-dash">—</span>;

function renderCell(colId, r) {
  switch (colId) {
    case "priority":
      return r.priority?.code
        ? <PriorityChip code={r.priority.code} /> : dash;
    case "severity":
      return r.severity ? <SeverityChip value={r.severity} /> : <SeverityChip value="unknown" />;
    case "name":
      return null;  // handled specially by caller
    case "verdict":
      return r.verdict?.stage2_label
        ? <VerdictChip value={r.verdict.stage2_label} />
        : <VerdictChip value="unknown" />;
    case "confidence":
      return r.confidence
        ? <span className="ql-td-mono">{r.confidence.toUpperCase()}</span>
        : dash;
    case "customer":
      return r.customer
        ? <span className="ql-td-mono">{r.customer}</span> : dash;
    case "detection_source":
      return r.detection_source
        ? <span className="ql-td-mono">{r.detection_source}</span> : dash;
    case "evidence_count":
      return (r.evidence_count ?? 0) > 0
        ? <span className="ql-td-mono">{r.evidence_count}</span> : dash;
    case "techniques_top":
      return r.techniques_top?.length
        ? (
          <span className="ql-td-mono">
            {r.techniques_top.join(" · ")}
            {r.techniques_total > r.techniques_top.length
              && ` +${r.techniques_total - r.techniques_top.length}`}
          </span>
        )
        : dash;
    case "sla_due_at":
      return r.sla_due_at
        ? <span className="ql-td-mono">{fmtISO(r.sla_due_at)}</span>
        : dash;
    case "aging_seconds":
      return <span className="ql-td-mono">{fmtAging(r.aging_seconds)}</span>;
    case "assignee":
      return r.assignee
        ? <span className="ql-td-mono">{r.assignee}</span>
        : <span className="ql-td-mono"
                  style={{ color: "var(--ql-amber)" }}>UNASSIGNED</span>;
    case "state":
      return <StateChip value={r.state} />;
    case "last_activity":
      return <span className="ql-td-mono">{fmtISO(r.last_activity)}</span>;
    case "auto_investigation": {
      const s = r.auto_investigation?.status || "NOT_RUN";
      const color = s === "COMPLETE" ? "var(--ql-green)"
                       : s === "PARTIAL"  ? "var(--ql-orange)"
                       : s === "FAILED"   ? "var(--ql-red)"
                       : s === "RUNNING"  ? "var(--ql-blue)"
                       : "var(--ql-muted)";
      return <span className="ql-td-mono" style={{ color, fontWeight: 700 }}>{s}</span>;
    }
    case "engine_results":
      return r.auto_investigation?.engines_total > 0
        ? (
          <span className="ql-td-mono">
            {r.auto_investigation.engines_ok}/{r.auto_investigation.engines_total}
          </span>
        )
        : <span className="ql-td-mono" style={{ color: "var(--ql-faint)" }}>NOT_RUN</span>;
    default:
      return dash;
  }
}

export default function QueueTable({
  rows,
  visibleColumns,          // array of column meta in display order
  selected, onToggleSelect, onSelectAll, allSelected,
  previewId,
  onRowClick, onNameClick,
  sort, order, onSort,
  loading,
  emptyMessage = "NO INCIDENTS MATCH THIS FILTER — honest empty state.",
}) {
  if (loading) {
    return (
      <div className="ql-loading" data-testid="ql-table-loading">
        LOADING INCIDENTS…
      </div>
    );
  }

  if (!rows || rows.length === 0) {
    return (
      <div className="ql-empty" data-testid="ql-table-empty">
        {emptyMessage}
        <span className="kbd">
          queue == projection · never runs an engine · never fabricates a value
        </span>
      </div>
    );
  }

  return (
    <div className="ql-table-wrap" data-testid="ql-table-wrap">
      <table className="ql-table" data-testid="ql-table">
        <thead>
          <tr>
            <th className="ql-td-checkbox">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={e => onSelectAll(e.target.checked)}
                data-testid="ql-select-all"
              />
            </th>
            {visibleColumns.map(c => {
              const isSorted = c.sort && sort === c.sort;
              return (
                <th
                  key={c.id}
                  className={`${c.sort ? "sortable" : ""} ${isSorted ? "sorted" : ""}`}
                  style={{ width: c.w, minWidth: c.w }}
                  onClick={() => c.sort && onSort(c.sort)}
                  data-testid={`ql-th-${c.id}`}
                >
                  {c.label}
                  {isSorted && (order === "desc"
                    ? <ChevronDown size={11} style={{ display: "inline", marginLeft: 4 }} />
                    : <ChevronUp   size={11} style={{ display: "inline", marginLeft: 4 }} />)}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map(r => {
            const isSel = selected.has(r.id);
            const isPreview = previewId === r.id;
            return (
              <tr
                key={r.id}
                className={`${isSel ? "selected" : ""} ${isPreview ? "previewed" : ""}`}
                onClick={() => onRowClick(r)}
                data-testid={`ql-row-${r.id}`}
              >
                <td className="ql-td-checkbox" onClick={e => e.stopPropagation()}>
                  <input
                    type="checkbox"
                    checked={isSel}
                    onChange={e => onToggleSelect(r.id, e.target.checked)}
                    data-testid={`ql-select-${r.id}`}
                  />
                </td>
                {visibleColumns.map(c => {
                  if (c.id === "name") {
                    return (
                      <td
                        key={c.id}
                        className="ql-td-name"
                        style={{ maxWidth: c.w }}
                        onClick={e => { e.stopPropagation(); onNameClick(r); }}
                        title={r.name}
                        data-testid={`ql-cell-name-${r.id}`}
                      >
                        {r.name}
                      </td>
                    );
                  }
                  return (
                    <td
                      key={c.id}
                      data-testid={`ql-cell-${c.id}-${r.id}`}
                    >
                      {renderCell(c.id, r)}
                    </td>
                  );
                })}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
