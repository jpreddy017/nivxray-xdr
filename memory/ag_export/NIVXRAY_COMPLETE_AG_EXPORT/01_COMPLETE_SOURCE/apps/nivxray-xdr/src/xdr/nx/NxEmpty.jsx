/**
 * NxEmpty / NxSkeleton · §11 empty & loading grammar.
 *
 * Empty is a state, not an absence.  Use compact where the empty
 * state sits inside a section; use default where the empty state
 * *is* the page.
 */
import React from "react";

export function NxEmpty({
  title,
  hint,
  cta = null,
  compact = false,
  className = "",
  children,
  ...rest
}) {
  return (
    <div
      className={`nx-empty ${compact ? "nx-empty--compact" : ""} ${className}`}
      role="status"
      {...rest}
    >
      {title && <div className="nx-empty__title">{title}</div>}
      {children && <div className="nx-t-body">{children}</div>}
      {hint  && <div className="nx-empty__hint">{hint}</div>}
      {cta   && <div className="nx-empty__cta">{cta}</div>}
    </div>
  );
}

export function NxSkeleton({ width = "100%", height = 12, style, ...rest }) {
  return (
    <span
      className="nx-skel"
      style={{
        display: "inline-block",
        width,
        height,
        ...style,
      }}
      aria-hidden
      {...rest}
    />
  );
}
