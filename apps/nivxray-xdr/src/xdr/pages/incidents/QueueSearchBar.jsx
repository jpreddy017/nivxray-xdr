/**
 * QueueSearchBar · column-scoped, SERVER-side search.
 *
 * Owner direction 2026-09-05: the per-column search controls belong on
 * the right, above the table line (next to the state-tab strip) — not
 * as a second row inside the header, where they fought the column
 * widths and drifted out of alignment.
 *
 * Every control writes a URL query parameter that the incidents API
 * honours, so the search runs against the AUTHORITATIVE query — never
 * over the rows already loaded — and the resulting view is shareable.
 */
import React, { useEffect, useState } from "react";
import { Search, X } from "lucide-react";

const TEXTS = [
  { param: "number",    label: "Number",   ph: "INC000000137 / inc_…" },
  { param: "name",      label: "Title",    ph: "short description" },
  { param: "assignee",  label: "Owner",    ph: "analyst@…" },
  { param: "technique", label: "MITRE",    ph: "T1059.001" },
];

const SELECTS = [
  { param: "priority", label: "Priority",
    fixed: ["P1", "P2", "P3", "P4", "P5"] },
  { param: "severity", label: "Severity",
    fixed: ["critical", "high", "medium", "low"] },
  { param: "verdict",  label: "Verdict",
    fixed: ["malicious", "suspicious", "benign"] },
  { param: "customer", label: "Customer", facet: "customers" },
  { param: "detection_source", label: "Source", facet: "sources" },
];

function TextField({ label, ph, value, onCommit }) {
  const [v, setV] = useState(value || "");
  useEffect(() => { setV(value || ""); }, [value]);
  useEffect(() => {
    const id = setTimeout(() => {
      if ((v || "") !== (value || "")) onCommit(v.trim() || null);
    }, 350);
    return () => clearTimeout(id);
  }, [v]);            // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <label className="ql-qs__field" title={`Search by ${label.toLowerCase()}`}>
      <span className="ql-qs__label">{label}</span>
      <input className="ql-qs__input"
              value={v}
              placeholder={ph}
              onChange={(e) => setV(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter")  onCommit(v.trim() || null);
                if (e.key === "Escape") { setV(""); onCommit(null); }
              }}
              data-testid={`ql-qs-${label.toLowerCase()}`} />
    </label>
  );
}

export default function QueueSearchBar({ values, facets, onChange, onClear }) {
  const [open, setOpen] = useState(false);
  const activeKeys = [...TEXTS, ...SELECTS]
    .map(f => f.param)
    .filter(p => values?.[p]);

  return (
    <div className="ql-qs" data-testid="ql-search-bar">
      <button className={`ql-qs__toggle${open ? " is-open" : ""}`}
               onClick={() => setOpen(v => !v)}
               data-testid="ql-qs-toggle"
               aria-expanded={open ? "true" : "false"}>
        <Search size={11} />
        <span>Column search</span>
        {activeKeys.length > 0 && (
          <b className="ql-qs__count" data-testid="ql-qs-active-count">
            {activeKeys.length}
          </b>
        )}
      </button>
      {activeKeys.length > 0 && (
        <button className="ql-qs__clear" onClick={onClear}
                 title="Clear every column search"
                 data-testid="ql-qs-clear">
          <X size={10} /> clear
        </button>
      )}
      {open && (
        <div className="ql-qs__panel" data-testid="ql-qs-panel">
          {TEXTS.map(f => (
            <TextField key={f.param} label={f.label} ph={f.ph}
                        value={values?.[f.param]}
                        onCommit={(v) => onChange(f.param, v)} />
          ))}
          {SELECTS.map(f => {
            const opts = f.fixed || facets?.[f.facet] || [];
            return (
              <label key={f.param} className="ql-qs__field"
                      title={`Filter by ${f.label.toLowerCase()}`}>
                <span className="ql-qs__label">{f.label}</span>
                <select className="ql-qs__select"
                         value={values?.[f.param] || ""}
                         onChange={(e) => onChange(f.param, e.target.value || null)}
                         data-testid={`ql-qs-${f.param}`}>
                  <option value="">any</option>
                  {opts.map(o => (
                    <option key={o} value={o}>{String(o).replace(/_/g, " ")}</option>
                  ))}
                </select>
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}
