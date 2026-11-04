/**
 * NxFlyout · Slice 1 · layered contextual detail.
 *
 * Investigation context is preserved: a flyout opens over the workspace,
 * and a second flyout layers over the first (incident → endpoint → process)
 * with a breadcrumb back and an explicit "open full page" escape.
 */
import React from "react";
import { ArrowUpRight, X } from "lucide-react";
import "./nx-datatable.css";

export default function NxFlyout({
  open, title, eyebrow, onClose, onBack, backLabel,
  fullPageHref, fullPageLabel = "Open full page",
  width = 560, children, footer, testid = "nx-flyout",
}) {
  if (!open) return null;
  return (
    <>
      <div className="nx-fly-scrim" onClick={onClose}
           data-testid={`${testid}-scrim`} />
      <aside className="nx-fly" style={{ width }} role="dialog"
             aria-modal="true" aria-label={title} data-testid={testid}>
        <header className="nx-fly-head">
          <div style={{ minWidth: 0 }}>
            {onBack && (
              <button className="nx-fly-back" onClick={onBack}
                      data-testid={`${testid}-back`}>
                ← {backLabel || "Back"}
              </button>
            )}
            {eyebrow && <div className="nx-fly-eyebrow">{eyebrow}</div>}
            <h2 className="nx-fly-title">{title}</h2>
          </div>
          <div className="nx-fly-actions">
            {fullPageHref && (
              <a className="nx-dt-btn" href={fullPageHref}
                 data-testid={`${testid}-fullpage`}>
                {fullPageLabel} <ArrowUpRight size={13} />
              </a>
            )}
            <button className="nx-fly-x" onClick={onClose} aria-label="Close"
                    data-testid={`${testid}-close`}>
              <X size={16} />
            </button>
          </div>
        </header>
        <div className="nx-fly-body">{children}</div>
        {footer && <footer className="nx-fly-foot">{footer}</footer>}
      </aside>
    </>
  );
}
