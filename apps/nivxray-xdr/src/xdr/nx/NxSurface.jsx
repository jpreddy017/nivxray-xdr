/**
 * NxSurface · Phase A.2 · reusable primary/inset/flat surface with
 * optional header + footer.  Composes with `.nx-*` class vocabulary.
 */
import React from "react";

export function NxSurface({
  title, subtitle, action, footer, children,
  variant = "primary", className = "", testid,
}) {
  const cls = variant === "inset"
    ? "nx-inset"
    : variant === "flat"
      ? "nx-surface nx-surface-flat"
      : "nx-surface";
  return (
    <section className={`${cls} ${className}`} data-testid={testid}>
      {(title || subtitle || action) && (
        <header className="nx-surface-head" style={{
          display: "flex", justifyContent: "space-between",
          alignItems: "flex-start", gap: 12,
        }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            {title && <h3 className="nx-surface-title">{title}</h3>}
            {subtitle && <p className="nx-surface-sub">{subtitle}</p>}
          </div>
          {action && <div style={{ flex: "0 0 auto" }}>{action}</div>}
        </header>
      )}
      <div className="nx-surface-body">{children}</div>
      {footer && <footer className="nx-surface-foot">{footer}</footer>}
    </section>
  );
}


/** NxKpi · attention tile fed by real data.  When `value` is
 *  null/undefined, renders "—" (honest absence). */
export function NxKpi({
  icon: Icon, label, value, sub, delta, tone = "purple", testid,
}) {
  const shown = value == null
    ? "—"
    : typeof value === "number"
      ? value.toLocaleString()
      : value;
  return (
    <div className="nx-kpi" data-testid={testid}>
      {Icon && (
        <div className={`nx-kpi-icon nx-kpi-icon-${tone}`} aria-hidden="true">
          <Icon size={16} />
        </div>
      )}
      <div className="nx-kpi-body">
        <div className="nx-kpi-value">{shown}</div>
        <div className="nx-kpi-label">{label}</div>
        {sub && <div className="nx-kpi-sub">{sub}</div>}
        {delta && (
          <div className={`nx-kpi-delta nx-kpi-delta-${delta.direction}`}>
            {delta.direction === "up" ? "↑" : "↓"} {Math.abs(delta.pct)}% {delta.suffix || ""}
          </div>
        )}
      </div>
    </div>
  );
}


/** NxEmpty · designed truth-state empty block with optional CTA. */
export function NxEmpty({ icon: Icon, title, body, actions, testid }) {
  return (
    <div className="nx-empty" data-testid={testid}>
      {Icon && (
        <span className="nx-empty-icon" aria-hidden="true">
          <Icon size={18} />
        </span>
      )}
      <div style={{ minWidth: 0 }}>
        {title && <h4 className="nx-empty-title">{title}</h4>}
        {body && <p className="nx-empty-body">{body}</p>}
        {actions && <div className="nx-empty-actions">{actions}</div>}
      </div>
    </div>
  );
}


/** NxPill · semantic status pill. */
export function NxPill({ tone = "faint", children, testid }) {
  return (
    <span className={`nx-pill nx-pill-${tone}`} data-testid={testid}>
      {children}
    </span>
  );
}
