/**
 * NxTabs · Slice 1 · page-level tabs.
 *
 * Depth is primary rail → page tabs → flyout → full page.  A page never
 * grows a second permanent navigation column.
 */
import React from "react";
import "./nx-datatable.css";

export default function NxTabs({ tabs, active, onChange, testid = "nx-tabs" }) {
  return (
    <div className="nx-tabs" role="tablist" data-testid={testid}>
      {tabs.map((t) => (
        <button key={t.key} role="tab" aria-selected={t.key === active}
                data-state={t.key === active ? "active" : "inactive"}
                className={`nx-tab${t.key === active ? " is-active" : ""}`}
                data-testid={`${testid}-${t.key}`}
                onClick={() => onChange(t.key)}>
          {t.label}
          {t.count != null && <span className="nx-tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}
