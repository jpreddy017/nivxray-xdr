/**
 * NxFlyout · Slice 1 · layered contextual detail.
 *
 * Investigation context is preserved: a flyout opens over the workspace,
 * and a second flyout layers over the first (incident → endpoint → process)
 * with a breadcrumb back and an explicit "open full page" escape.
 */
import React, { useEffect, useRef } from "react";
import { ArrowUpRight, X } from "lucide-react";
import "./nx-datatable.css";

export function manageFlyoutFocus(dialog, onClose) {
  const previous = document.activeElement;
  const focusable = () => [...dialog.querySelectorAll('a[href],button:not([disabled]),[tabindex="0"]')];
  (focusable()[0] || dialog).focus();
  const keydown = (event) => {
    if (event.key === "Escape") { event.preventDefault(); onClose(); }
    if (event.key !== "Tab") return;
    const items = focusable();
    const target = event.shiftKey ? items[items.length - 1] : items[0];
    if (!items.length || (event.shiftKey ? document.activeElement === items[0] : document.activeElement === items[items.length - 1])) {
      event.preventDefault(); (target || dialog).focus();
    }
  };
  document.addEventListener("keydown", keydown);
  return () => {
    document.removeEventListener("keydown", keydown);
    if (previous?.isConnected) previous.focus();
  };
}

export default function NxFlyout({
  open, title, eyebrow, onClose, onBack, backLabel,
  fullPageHref, fullPageLabel = "Open full page",
  width = 560, children, footer, testid = "nx-flyout", manageFocus = false,
}) {
  const dialog = useRef(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    if (!open || !manageFocus) return undefined;
    return manageFlyoutFocus(dialog.current, () => close.current());
  }, [open, manageFocus]);
  if (!open) return null;
  return (
    <>
      <div className="nx-fly-scrim" onClick={onClose}
           data-testid={`${testid}-scrim`} />
      <aside ref={dialog} tabIndex={-1} className="nx-fly" style={{ width }} role="dialog"
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
