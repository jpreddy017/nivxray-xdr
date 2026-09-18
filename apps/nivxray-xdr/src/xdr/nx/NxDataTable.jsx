/**
 * NxDataTable · Slice 1 · the ONE enterprise table for NivXRay XDR.
 *
 * Every operational page composes this instead of hand-rolling markup:
 * search · sort · configurable columns · pagination · selection + bulk
 * actions · row quick actions · loading · empty · error · keyboard focus.
 * Capabilities are opt-in — a table only shows what the page actually has.
 */
import React, { useMemo, useState } from "react";
import { ChevronDown, ChevronUp, Columns3, RefreshCw, Search } from "lucide-react";
import { NxEmpty, NxSkeleton } from "./NxEmpty";
import "./nx-datatable.css";

export default function NxDataTable({
  columns, rows, rowKey = (r, i) => r.id ?? i,
  loading = false, error = null, onRefresh = null,
  searchable = true, searchPlaceholder = "Search",
  pageSize = 25, selectable = false, bulkActions = null,
  rowActions = null, onRowClick = null,
  emptyTitle = "Nothing here yet", emptyHint = null, emptyCta = null,
  toolbarExtra = null, testid = "nx-table",
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState({ key: null, dir: "asc" });
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState({});
  const [hidden, setHidden] = useState({});
  const [colMenu, setColMenu] = useState(false);

  const shown = columns.filter((c) => !hidden[c.key]);

  const filtered = useMemo(() => {
    if (!q.trim()) return rows;
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => columns.some((c) => {
      const v = c.value ? c.value(r) : r[c.key];
      return v != null && String(v).toLowerCase().includes(needle);
    }));
  }, [rows, q, columns]);

  const sorted = useMemo(() => {
    if (!sort.key) return filtered;
    const col = columns.find((c) => c.key === sort.key);
    const get = (r) => (col?.value ? col.value(r) : r[sort.key]);
    return [...filtered].sort((a, b) => {
      const x = get(a), y = get(b);
      if (x == null) return 1;
      if (y == null) return -1;
      const n = typeof x === "number" && typeof y === "number"
        ? x - y : String(x).localeCompare(String(y));
      return sort.dir === "asc" ? n : -n;
    });
  }, [filtered, sort, columns]);

  const pages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const view = sorted.slice(page * pageSize, page * pageSize + pageSize);
  const selectedKeys = Object.keys(selected).filter((k) => selected[k]);

  const toggleSort = (key) => setSort((s) =>
    s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" }
                  : { key, dir: "asc" });

  return (
    <div className="nx-dt" data-testid={testid}>
      <div className="nx-dt-toolbar">
        {searchable && (
          <label className="nx-dt-search">
            <Search size={13} aria-hidden="true" />
            <input value={q} data-testid={`${testid}-search`}
                   placeholder={searchPlaceholder}
                   onChange={(e) => { setQ(e.target.value); setPage(0); }} />
          </label>
        )}
        {toolbarExtra}
        <span className="nx-dt-count" data-testid={`${testid}-count`}>
          {loading ? "loading…" : `${sorted.length} of ${rows.length}`}
        </span>
        <span className="nx-dt-spacer" />
        {selectable && selectedKeys.length > 0 && bulkActions && (
          <div className="nx-dt-bulk" data-testid={`${testid}-bulk`}>
            <span>{selectedKeys.length} selected</span>
            {bulkActions(selectedKeys, () => setSelected({}))}
          </div>
        )}
        <div className="nx-dt-colwrap">
          <button className="nx-dt-btn" data-testid={`${testid}-columns`}
                  onClick={() => setColMenu((v) => !v)}
                  aria-expanded={colMenu} title="Columns">
            <Columns3 size={13} /> Columns
          </button>
          {colMenu && (
            <div className="nx-dt-colmenu" role="menu">
              {columns.map((c) => (
                <label key={c.key} className="nx-dt-colopt">
                  <input type="checkbox" checked={!hidden[c.key]}
                         onChange={() => setHidden((h) =>
                           ({ ...h, [c.key]: !h[c.key] }))} />
                  {c.header}
                </label>
              ))}
            </div>
          )}
        </div>
        {onRefresh && (
          <button className="nx-dt-btn" onClick={onRefresh} title="Refresh"
                  data-testid={`${testid}-refresh`}>
            <RefreshCw size={13} /> Refresh
          </button>
        )}
      </div>

      {error ? (
        <div className="nx-dt-error" role="alert" data-testid={`${testid}-error`}>
          <strong>This view could not load.</strong>
          <span>{String(error)}</span>
          {onRefresh && (
            <button className="nx-dt-btn" onClick={onRefresh}>Try again</button>
          )}
        </div>
      ) : (
        <div className="nx-dt-scroll">
          <table className="nx-dt-table">
            <thead>
              <tr>
                {selectable && <th className="nx-dt-check" />}
                {shown.map((c) => (
                  <th key={c.key} style={{ width: c.width }}
                      className={c.align === "right" ? "nx-dt-r" : ""}>
                    {c.sortable === false ? c.header : (
                      <button className="nx-dt-sort" onClick={() => toggleSort(c.key)}
                              data-testid={`${testid}-sort-${c.key}`}>
                        {c.header}
                        {sort.key === c.key && (sort.dir === "asc"
                          ? <ChevronUp size={12} /> : <ChevronDown size={12} />)}
                      </button>
                    )}
                  </th>
                ))}
                {rowActions && <th className="nx-dt-r">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {loading && [0, 1, 2, 3, 4].map((i) => (
                <tr key={`sk${i}`}>
                  {selectable && <td />}
                  {shown.map((c) => (
                    <td key={c.key}><NxSkeleton width="70%" /></td>
                  ))}
                  {rowActions && <td />}
                </tr>
              ))}
              {!loading && view.map((r, i) => {
                const k = String(rowKey(r, i));
                return (
                  <tr key={k} data-testid={`${testid}-row-${k}`}
                      className={onRowClick ? "nx-dt-clickable" : ""}
                      tabIndex={onRowClick ? 0 : -1}
                      onClick={onRowClick ? () => onRowClick(r) : undefined}
                      onKeyDown={onRowClick ? (e) => {
                        if (e.key === "Enter") onRowClick(r);
                      } : undefined}>
                    {selectable && (
                      <td className="nx-dt-check" onClick={(e) => e.stopPropagation()}>
                        <input type="checkbox" checked={!!selected[k]}
                               aria-label={`select ${k}`}
                               onChange={() => setSelected((s) =>
                                 ({ ...s, [k]: !s[k] }))} />
                      </td>
                    )}
                    {shown.map((c) => (
                      <td key={c.key}
                          className={c.align === "right" ? "nx-dt-r" : ""}>
                        {c.render ? c.render(r)
                          : (c.value ? c.value(r) : r[c.key]) ?? "—"}
                      </td>
                    ))}
                    {rowActions && (
                      <td className="nx-dt-r" onClick={(e) => e.stopPropagation()}>
                        {rowActions(r)}
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!loading && sorted.length === 0 && (
            <NxEmpty title={emptyTitle} hint={emptyHint} cta={emptyCta}
                     data-testid={`${testid}-empty`} />
          )}
        </div>
      )}

      {!error && pages > 1 && (
        <div className="nx-dt-pager">
          <button className="nx-dt-btn" disabled={page === 0}
                  onClick={() => setPage((p) => p - 1)}
                  data-testid={`${testid}-prev`}>Previous</button>
          <span>Page {page + 1} of {pages}</span>
          <button className="nx-dt-btn" disabled={page + 1 >= pages}
                  onClick={() => setPage((p) => p + 1)}
                  data-testid={`${testid}-next`}>Next</button>
        </div>
      )}
    </div>
  );
}
