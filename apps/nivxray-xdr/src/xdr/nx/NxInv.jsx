/**
 * Nx · investigation primitives.
 *
 * ONE table language, ONE empty-state language, ONE status vocabulary and
 * ONE place for engine/implementation detail across every investigation
 * tab. This is part of `xdr/nx` on purpose: the investigation experience
 * must NOT own a second design system.
 *
 * Product laws encoded here:
 *   · a missing value is never a zero — `NxInvValue` renders the named
 *     absence (NO DATA · NOT AVAILABLE · NOT OBSERVED · NOT AUTHORIZED ·
 *     NOT EVALUATED · UNSUPPORTED · EVIDENCE INCOMPLETE · ERROR);
 *   · engine strings (`NOT_RUN`, `attack_progression[]`, provider
 *     internals) live under Technical details, never in primary content.
 */
import React, { useEffect, useState } from "react";
import "./nx-inv.css";

export const ABSENCE = {
  NO_DATA: "NO DATA",
  NOT_AVAILABLE: "NOT AVAILABLE",
  NOT_OBSERVED: "NOT OBSERVED",
  NOT_AUTHORIZED: "NOT AUTHORIZED",
  NOT_EVALUATED: "NOT EVALUATED",
  UNSUPPORTED: "UNSUPPORTED",
  EVIDENCE_INCOMPLETE: "EVIDENCE INCOMPLETE",
  NOT_ATTRIBUTED: "NOT ATTRIBUTED",
  NOT_RECORDED: "NOT RECORDED",
  ERROR: "ERROR",
};

/** A value that cannot lie. `absent` names WHY it is missing. */
export function NxInvValue({ value, absent = ABSENCE.NOT_AVAILABLE, mono }) {
  const missing = value == null || value === "" || value === "unset";
  if (missing) return <span className="inv-tb__na">{absent}</span>;
  // A composed node (a chip, an entity, a token) is already presentation —
  // render it. Stringifying it used to throw on React's circular fiber
  // refs and took the whole surface down with it.
  if (React.isValidElement(value)) {
    return <span className={mono ? "mono" : undefined}>{value}</span>;
  }
  return <span className={mono ? "mono" : undefined}>
    {typeof value === "object" ? JSON.stringify(value) : String(value)}
  </span>;
}

export function NxInvSection({ title, subtitle, actions, children, testid,
                              pad = false }) {
  return (
    <section className="inv-sec" data-testid={testid}>
      {(title || subtitle || actions) && (
        <div className="inv-sec__h">
          {title && <span className="inv-sec__t">{title}</span>}
          {subtitle && <span className="inv-sec__s">{subtitle}</span>}
          {actions && <span className="inv-sec__a">{actions}</span>}
        </div>
      )}
      <div className={`inv-sec__b${pad ? " inv-sec__b--pad" : ""}`}>
        {children}
      </div>
    </section>
  );
}

/** The investigation empty state. Analyst language first, then exactly
 *  what IS known, so an absence is still information. */
export function NxInvEmpty({ title, body, points = [], testid }) {
  return (
    <div className="inv-empty" data-testid={testid}>
      <div className="inv-empty__t">{title}</div>
      {body}
      {points.length > 0 && (
        <ul className="inv-empty__l">
          {points.map((p, i) => <li key={i}>{p}</li>)}
        </ul>
      )}
    </div>
  );
}

/** Filter chips with live counts. Selection is a set of keys. */
export function NxInvFilters({ options, active, onChange, right, testid }) {
  const toggle = (k) => {
    if (k === "__all") return onChange([]);
    onChange(active.includes(k) ? active.filter((x) => x !== k) : [...active, k]);
  };
  return (
    <div className="inv-filters" data-testid={testid}>
      <button className="inv-chip" aria-pressed={active.length === 0}
              onClick={() => toggle("__all")}
              data-testid={`${testid}-all`}>
        All
      </button>
      {options.map((o) => (
        <button key={o.key} className="inv-chip"
                aria-pressed={active.includes(o.key)}
                onClick={() => toggle(o.key)}
                data-testid={`${testid}-${o.key}`}>
          {o.label}
          {o.count != null && <span className="inv-chip__n">{o.count}</span>}
        </button>
      ))}
      {right && <span className="inv-filters__sp">{right}</span>}
    </div>
  );
}

/** Dense table with optional row expansion — the ONE table in the
 *  investigation experience. `columns: [{key,label,width,num,render}]`.
 *  `openKey` opens (and marks `data-focus`) one row from outside the table,
 *  so one surface can hand an analyst to the same fact on another surface. */
export function NxInvTable({ columns, rows, rowKey, detail, testid,
                            onRowClick, empty, openKey }) {
  const [open, setOpen] = useState(openKey ?? null);
  useEffect(() => { if (openKey != null) setOpen(openKey); }, [openKey]);
  if (!rows || rows.length === 0) return empty || null;
  return (
    <table className="inv-tb" data-testid={testid}>
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.key} style={c.width ? { width: c.width } : undefined}
                className={c.num ? "num" : undefined}>
              {c.label}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => {
          const k = rowKey ? rowKey(r, i) : i;
          const isOpen = open === k;
          return (
            <React.Fragment key={k}>
              <tr className="inv-tb__r" data-open={isOpen || undefined}
                  data-focus={(openKey != null && openKey === k)
                    ? "true" : undefined}
                  data-testid={`${testid}-row-${k}`}
                  onClick={() => {
                    if (onRowClick) return onRowClick(r);
                    if (detail) setOpen(isOpen ? null : k);
                  }}>
                {columns.map((c) => (
                  <td key={c.key} className={c.num ? "num" : undefined}>
                    {c.render ? c.render(r) : <NxInvValue value={r[c.key]} />}
                  </td>
                ))}
              </tr>
              {detail && isOpen && (
                <tr className="inv-tb__d" data-testid={`${testid}-detail-${k}`}>
                  <td colSpan={columns.length}>{detail(r)}</td>
                </tr>
              )}
            </React.Fragment>
          );
        })}
      </tbody>
    </table>
  );
}

/** Where engine / implementation truth lives. Never deleted, never
 *  promoted into primary analyst content. */
export function NxInvTech({ label = "Technical details", children, testid }) {
  return (
    <details className="inv-tech" data-testid={testid}>
      <summary>{label}</summary>
      <div className="inv-tech__b">{children}</div>
    </details>
  );
}

/** A compact metric row. Absence is named, never rendered as 0. */
export function NxInvMetrics({ items, testid }) {
  return (
    <div className="inv-metrics" data-testid={testid}>
      {items.map((m) => {
        const missing = m.value == null || m.value === "";
        return (
          <div className="inv-metrics__i" key={m.key}
               title={missing ? (m.absent || ABSENCE.NOT_AVAILABLE) : undefined}
               data-testid={`${testid}-${m.key}`}>
            <span className="inv-metrics__k">{m.label}</span>
            <span className="inv-metrics__v" data-absent={missing ? "1" : undefined}>
              {missing ? (m.absent || ABSENCE.NOT_AVAILABLE) : m.value}
            </span>
            {m.sub && <span className="inv-sec__s">{m.sub}</span>}
          </div>
        );
      })}
    </div>
  );
}

export function fmtTime(iso) {
  if (!iso) return null;
  const s = String(iso);
  return s.length >= 16 ? s.slice(0, 19).replace("T", " ") : s;
}
