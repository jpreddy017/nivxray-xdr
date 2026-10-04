/**
 * Shared operational primitives for the NivXForge EDR fleet surfaces.
 *
 * Small, dense and honest: a state token renders the SERVER's token and
 * its basis, never a prettier invention; an absent value renders as an
 * explicit unavailable marker rather than a zero.
 */
import React, { useMemo, useState } from "react";
import { AlertTriangle, ArrowDown, ArrowUp, Check, Copy } from "lucide-react";

import "@/nivxforge/nvf-ops.css";

const TONE = {
  // Green is reserved for VERIFIED HEALTHY / CONFIRMED-GOOD facts only.
  CONNECTED: "ok",
  AVAILABLE: "ok",
  VERIFIED: "ok",
  AUTHENTICATED: "ok",
  // Amber = warning / suspicious · red = critical · cyan = informational
  ALIVE_NO_RECENT_TELEMETRY: "warn",
  ENROLLED_NO_TELEMETRY: "warn",
  SILENT: "bad",
  REVOKED: "void",
  NOT_ENROLLED: "void",
  DETECTION_MATCHED: "bad",
  EVALUATED_NO_MATCH: "",
  NOT_EVALUATED: "warn",
  NOT_RECORDED: "void",
  DECODED: "info",
  DECODE_NOT_RECORDED: "void",
  NOT_BUILT: "void",
  INCOMPLETE: "warn",
  REFUSED_EMBEDDED_CREDENTIAL: "bad",
  DETECT_ONLY: "info",
  UNAVAILABLE: "void",
  OBSERVED: "",
  PREVIEW: "warn",
  UNSIGNED: "warn",
};

export function StateChip({ token, tone, title, testid }) {
  if (!token) return <NA />;
  const cls = tone || TONE[token] || "";
  return (
    <span className={`st ${cls}`} title={title || token}
          data-testid={testid} data-state={token}>
      <span className="dot" />{String(token).replace(/_/g, " ")}
    </span>
  );
}

/** An unavailable fact. Deliberately NOT a zero and NOT an em dash alone. */
export function NA({ reason, label = "NOT AVAILABLE" }) {
  return <span className="na" title={reason || label}>◇ {label}</span>;
}

export function Kpi({ label, value, unit, tone, testid, title }) {
  const missing = value === null || value === undefined || value === "";
  return (
    <div className={`kpi ${missing ? "void" : (tone || "")}`}
         data-testid={testid} title={title}>
      <div className="k">{label}</div>
      <div className="v">
        {missing ? "◇ N/A" : value}
        {!missing && unit ? <span className="unit">{unit}</span> : null}
      </div>
    </div>
  );
}

export function CopyBlock({ text, testid, label }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand("copy"); ta.remove();
    }
    setDone(true);
    window.setTimeout(() => setDone(false), 1600);
  };
  return (
    <div>
      {label ? <div className="section-title" style={{ marginBottom: 5 }}>{label}</div> : null}
      <div className="cmd" data-testid={testid}>
        {text}
        <button className="copy" onClick={copy} title="Copy"
                data-testid={testid ? `${testid}-copy` : undefined}>
          {done ? <Check size={11} /> : <Copy size={11} />}
        </button>
      </div>
    </div>
  );
}

/** Dense sortable table. Column definitions carry their own renderer. */
export function OpsTable({ columns, rows, rowKey, selectedKey, onSelect,
                           testid, initialSort }) {
  const [sort, setSort] = useState(initialSort || { key: null, dir: -1 });
  const sorted = useMemo(() => {
    if (!sort.key) return rows;
    const col = columns.find((c) => c.key === sort.key);
    const val = col?.sortValue || ((r) => r[sort.key]);
    return [...rows].sort((a, b) => {
      const x = val(a), y = val(b);
      if (x === y) return 0;
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (x > y ? 1 : -1) * sort.dir;
    });
  }, [rows, sort, columns]);

  return (
    <div className="tbl-wrap">
      <table className="tbl" data-testid={testid}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={c.width ? { width: c.width } : undefined}
                  title={c.title}
                  data-testid={`${testid}-th-${c.key}`}
                  onClick={() => setSort((s) => ({
                    key: c.key, dir: s.key === c.key ? -s.dir : -1 }))}>
                {c.label}
                {sort.key === c.key
                  ? <span className="ar">{sort.dir === 1
                      ? <ArrowUp size={9} /> : <ArrowDown size={9} />}</span>
                  : null}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r) => {
            const key = rowKey(r);
            return (
              <tr key={key} data-sel={key === selectedKey}
                  data-testid={`${testid}-row-${key}`}
                  onClick={() => onSelect && onSelect(r)}>
                {columns.map((c) => (
                  <td key={c.key} className={c.cls}
                      data-testid={`${testid}-cell-${c.key}-${key}`}>
                    {c.render ? c.render(r) : (r[c.key] ?? <NA />)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Refusal({ title, body, testid }) {
  return (
    <div className="refusal" data-testid={testid || "nvf-refusal"} role="alert">
      <div className="h">
        <AlertTriangle size={11} style={{ verticalAlign: -1, marginRight: 5 }} />
        {title}
      </div>
      <div className="b">{body}</div>
    </div>
  );
}

export function Skeleton({ rows = 6, testid }) {
  return (
    <div data-testid={testid || "nvf-loading"} style={{ padding: "10px 2px" }}>
      {Array.from({ length: rows }).map((_, i) => (
        <div className="sk" key={i}
             style={{ width: `${95 - i * 7}%` }} />
      ))}
    </div>
  );
}

/** Relative age for a recorded instant. Absent time is never "just now". */
export function Ago({ iso }) {
  if (!iso) return <NA label="NOT RECORDED" />;
  const ms = Date.now() - Date.parse(iso);
  if (Number.isNaN(ms)) return <NA label="UNPARSEABLE" />;
  const s = Math.max(0, Math.round(ms / 1000));
  const txt = s < 60 ? `${s}s ago`
    : s < 3600 ? `${Math.round(s / 60)}m ago`
    : s < 86400 ? `${Math.round(s / 3600)}h ago`
    : `${Math.round(s / 86400)}d ago`;
  return <span className="mono" title={iso}>{txt}</span>;
}
