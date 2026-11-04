/**
 * StateTabs · lifecycle-state selector.
 *
 * All · New · In Progress · On Hold · Resolved · Closed
 * URL-persisted (?state=…).  Empty selection = "All".
 */
import React from "react";

const TABS = [
  { key: null,          label: "All"          },
  { key: "new",         label: "New"          },
  { key: "in_progress", label: "In Progress"  },
  { key: "on_hold",     label: "On Hold"      },
  { key: "resolved",    label: "Resolved"     },
  { key: "closed",      label: "Closed"       },
];

export default function StateTabs({ current, counts, onChange }) {
  return (
    <div className="ql-tabs" data-testid="ql-state-tabs" role="tablist">
      {TABS.map(t => {
        const isActive = (t.key || null) === (current || null);
        const count = t.key == null
          ? Object.values(counts || {}).reduce((a, b) => a + (b || 0), 0)
          : counts?.[t.key];
        return (
          <button
            key={t.label}
            role="tab"
            aria-selected={isActive}
            className={`ql-tab ${isActive ? "active" : ""}`}
            onClick={() => onChange(t.key)}
            data-testid={`ql-state-tab-${t.key || "all"}`}
          >
            {t.label}
            {count != null && (
              <span className="ql-tab-count">{count.toLocaleString()}</span>
            )}
          </button>
        );
      })}
    </div>
  );
}
