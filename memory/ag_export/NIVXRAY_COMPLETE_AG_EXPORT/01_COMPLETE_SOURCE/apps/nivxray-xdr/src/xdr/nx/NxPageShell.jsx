/**
 * NxPageShell · shared page composition wrapper for Phase A.2.
 *
 * Provides the canvas, hero band, and slot for body content.
 * Every non-Platform-Overview page family composes from this
 * so we get consistent visual maturity without per-page CSS.
 */
import React from "react";
import "./nx-page.css";

export default function NxPageShell({
  eyebrow, title, description, action, meta,
  children, className = "",
  testid,
}) {
  return (
    <div className={`nx-page ${className}`} data-testid={testid}>
      {(eyebrow || title || description || action) && (
        <header className="nx-page-hero">
          <div className="nx-page-hero-body">
            {eyebrow && <div className="nx-page-hero-eyebrow">{eyebrow}</div>}
            {title && <h1 className="nx-page-hero-title">{title}</h1>}
            {description && (
              <p className="nx-page-hero-desc">{description}</p>
            )}
            {meta && <div style={{ marginTop: 8 }}>{meta}</div>}
          </div>
          {action && <div className="nx-page-hero-action">{action}</div>}
        </header>
      )}
      {children}
    </div>
  );
}
