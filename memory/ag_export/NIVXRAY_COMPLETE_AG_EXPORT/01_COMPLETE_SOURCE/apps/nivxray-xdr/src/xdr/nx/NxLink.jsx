/**
 * NxLink · §9 evidence-first navigation edge.
 *
 * Wrap any decision-critical value that must lead the analyst back
 * to evidence.  Renders as an accessible button so keyboard users
 * get the same navigation.  When onClick is absent the value is
 * rendered as static text — this keeps grammar rule §9 discoverable
 * (a missing onClick on a decision-critical value IS the design
 * bug).
 */
import React from "react";

export default function NxLink({
  onClick,
  as,
  children,
  className = "",
  disabled = false,
  ...rest
}) {
  if (!onClick || disabled) {
    const Tag = as || "span";
    return <Tag className={className} {...rest}>{children}</Tag>;
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className={`nx-link ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}
