/**
 * NxOps · the shared operational composition primitives.
 *
 * These exist so an operational page never hand-rolls a section header, a
 * metric strip, a key/value block, a token list or a "technical details"
 * disclosure again. Everything here is theme-token only: no hard-coded
 * colour, no page-local CSS, readable in BOTH themes.
 *
 * Absence grammar (product law, not styling):
 *   a measurement that was never taken renders `—` or an explicit state
 *   chip with its reason. It never renders `0`, and never renders blank.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import NxState from "./NxOpsState";
import "./nx-ops.css";

/** `—` for a measurement that was never taken. Never `0`. */
export const measured = (v) =>
  v === null || v === undefined || v === "" ? "—"
    : typeof v === "number" ? v.toLocaleString() : String(v);

/** Section · one title, one optional explanation, one action slot. */
export function NxSection({ title, note, action, aside, children,
                            variant = "plain", className = "", testid }) {
  return (
    <section className={`nx-sec nx-sec--${variant} ${className}`}
             data-testid={testid}>
      {(title || action) && (
        <header className="nx-sec-head">
          <div className="nx-sec-headline">
            {title && <h3 className="nx-sec-title">{title}</h3>}
            {aside && <span className="nx-sec-aside">{aside}</span>}
          </div>
          {action && <div className="nx-sec-action">{action}</div>}
        </header>
      )}
      {note && <p className="nx-sec-note">{note}</p>}
      <div className="nx-sec-body">{children}</div>
    </section>
  );
}

/** Toolbar · filters, scope pickers and page actions on one dense row. */
export function NxToolbar({ children, right, testid = "nx-toolbar" }) {
  return (
    <div className="nx-tb" data-testid={testid}>
      <div className="nx-tb-main">{children}</div>
      {right && <div className="nx-tb-right">{right}</div>}
    </div>
  );
}

/** A labelled control inside a toolbar. */
export function NxField({ label, children, testid }) {
  return (
    <label className="nx-tb-field" data-testid={testid}>
      <span className="nx-tb-label">{label}</span>
      {children}
    </label>
  );
}

/**
 * Metric strip · compact operational counters.
 *
 * Deliberately NOT four giant hero cards: an operator reads these on one
 * line and spends the viewport on the work surface below.
 */
export function NxMetricStrip({ items = [], testid = "nx-metrics" }) {
  return (
    <div className="nx-ms" data-testid={testid}>
      {items.map((m) => (
        <div className="nx-ms-item" key={m.label}
             data-testid={m.testid || `nx-metric-${slug(m.label)}`}>
          <span className="nx-ms-label">{m.label}</span>
          <span className={`nx-ms-value${m.value == null ? " nx-ms-absent" : ""}`}
                title={m.reason || undefined}>
            {measured(m.value)}
          </span>
          {m.sub && <span className="nx-ms-sub">{m.sub}</span>}
        </div>
      ))}
    </div>
  );
}

/**
 * Dimension strip · the five INDEPENDENT dimensions side by side.
 *
 * It computes nothing and rolls nothing up. There is deliberately no
 * composite verdict: a tenant can be receiving every channel and be able
 * to detect almost none of it, and one green light would hide exactly that.
 */
export function NxDimensionStrip({ dimensions = [], testid = "nx-dimensions" }) {
  return (
    <div className="nx-dims" data-testid={testid}>
      {dimensions.map((d) => (
        <div className="nx-dim" key={d.label}
             data-testid={`nx-dim-${slug(d.label)}`}>
          <div className="nx-dim-head">
            <span className="nx-dim-label">{d.label}</span>
            {d.note && <span className="nx-dim-note">{d.note}</span>}
          </div>
          <div className="nx-dim-states">
            {(d.counts && Object.keys(d.counts).length
              ? Object.entries(d.counts).filter(([, n]) => n > 0)
              : []).map(([state, n]) => (
                <span className="nx-dim-pair" key={state}>
                  <NxState value={state} size="sm" />
                  <span className="nx-dim-count">{n}</span>
                </span>
              ))}
            {d.state && <NxState value={d.state} reason={d.reason} />}
            {!d.state && (!d.counts
              || !Object.values(d.counts).some((n) => n > 0)) && (
              <NxState value="NOT_MEASURED" reason={d.reason} />
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/**
 * Blocker group · the same blocker stated ONCE with everything it affects.
 *
 * Repeating an identical sentence on forty rows is noise; the operator
 * needs the root cause and its blast radius.
 */
export function NxBlockerGroup({ blockers = [], onSelect = null,
                                 emptyLabel = "No blocker reported",
                                 testid = "nx-blockers" }) {
  if (!blockers.length) {
    return <p className="nx-sec-note" data-testid={`${testid}-empty`}>
      {emptyLabel}</p>;
  }
  return (
    <ul className="nx-blk" data-testid={testid}>
      {blockers.map((b) => (
        <li className="nx-blk-item" key={b.blocker}
            data-testid={`nx-blocker-${slug(b.blocker)}`}>
          <span className="nx-blk-what">{b.blocker}</span>
          <span className="nx-blk-scope">
            {(b.targets || []).slice(0, 8).map((t) => (
              <button type="button" className="nx-token nx-token--action"
                      key={t} onClick={() => onSelect && onSelect(t)}
                      disabled={!onSelect}>{t}</button>
            ))}
            {(b.targets || []).length > 8 && (
              <span className="nx-token">
                +{b.targets.length - 8}
              </span>
            )}
          </span>
          {b.impact && <span className="nx-blk-impact">{b.impact}</span>}
        </li>
      ))}
    </ul>
  );
}

/** Key facts · a real definition list, not a two-column monospace dump. */
export function NxFacts({ children, columns = 2, testid }) {
  return (
    <dl className={`nx-facts nx-facts--${columns}`} data-testid={testid}>
      {children}
    </dl>
  );
}

export function NxKeyFact({ label, value, reason = null, mono = false, testid }) {
  const absent = value === null || value === undefined || value === "";
  return (
    <div className="nx-fact" data-testid={testid}>
      <dt className="nx-fact-label">{label}</dt>
      <dd className={`nx-fact-value${mono ? " nx-mono" : ""}${absent ? " nx-fact-absent" : ""}`}>
        {absent ? (reason ? "Not available" : "—") : value}
      </dd>
      {reason && <dd className="nx-fact-reason">{reason}</dd>}
    </div>
  );
}

/** Technical token · monospace is reserved for MACHINE facts only. */
export function NxToken({ children, title, onClick, testid }) {
  const Tag = onClick ? "button" : "span";
  return (
    <Tag className={`nx-token${onClick ? " nx-token--action" : ""}`}
         title={title} onClick={onClick} data-testid={testid}
         {...(onClick ? { type: "button" } : {})}>
      {children}
    </Tag>
  );
}

export function NxTokenList({ values = [], limit = 10, empty = "—",
                              onSelect = null, testid }) {
  if (!values.length) {
    return <span className="nx-absent" data-testid={testid}>{empty}</span>;
  }
  const shown = values.slice(0, limit);
  return (
    <span className="nx-tokens" data-testid={testid}>
      {shown.map((v) => (
        <NxToken key={String(v)}
                 onClick={onSelect ? () => onSelect(v) : undefined}>
          {String(v)}
        </NxToken>
      ))}
      {values.length > limit && (
        <span className="nx-absent">+{values.length - limit}</span>
      )}
    </span>
  );
}

/** Progressive disclosure for raw/internal truth. Collapsed by default. */
export function NxTechnical({ title = "Technical details", children,
                              testid = "nx-technical" }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="nx-tech" data-testid={testid}>
      <button type="button" className="nx-tech-toggle"
              aria-expanded={open} onClick={() => setOpen((v) => !v)}
              data-testid={`${testid}-toggle`}>
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        {title}
      </button>
      {open && <div className="nx-tech-body">{children}</div>}
    </div>
  );
}

/** Raw machine text (XML/JSON/command line) — the ONE code surface. */
export function NxRaw({ children, testid = "nx-raw" }) {
  return <pre className="nx-raw" data-testid={testid}>{children}</pre>;
}

/** Primary/secondary action button in the nx grammar. */
export function NxButton({ children, onClick, variant = "quiet",
                           disabled = false, testid, ...rest }) {
  return (
    <button type="button" className={`nx-btn nx-btn--${variant}`}
            onClick={onClick} disabled={disabled} data-testid={testid}
            {...rest}>
      {children}
    </button>
  );
}

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-")
  .replace(/(^-|-$)/g, "");

export { slug as nxSlug };
