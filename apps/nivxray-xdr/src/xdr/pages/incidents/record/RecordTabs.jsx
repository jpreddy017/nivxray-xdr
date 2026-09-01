/**
 * RecordTabs · Layer 3 · 11-tab investigation workspace navigation.
 *
 *   Executive · Technical · Evidence · Investigation Activity · MITRE ·
 *   Attack Story · Recommendations · Notes · Timeline · Related · Closure
 *
 * Every tab is URL-persisted via ?tab= so an analyst can share a
 * direct link into a specific tab.
 */
import React from "react";

export const RECORD_TABS = [
  { key: "executive",         label: "Executive"          },
  { key: "technical",         label: "Technical"          },
  { key: "evidence",          label: "Evidence"           },
  { key: "auto_investigation",label: "Investigation Activity" },
  { key: "mitre",             label: "MITRE"              },
  { key: "attack_story",      label: "Attack Story"       },
  { key: "recommendations",   label: "Recommendations"    },
  { key: "notes",             label: "Notes"              },
  { key: "timeline",          label: "Timeline"           },
  { key: "related",           label: "Related"            },
  { key: "closure",           label: "Closure"            },
];

// Which tabs render inside the dark investigation canvas.
export const CANVAS_TABS = new Set([
  "mitre", "attack_story", "recommendations", "auto_investigation",
]);

export default function RecordTabs({ current, onChange, counts = {} }) {
  return (
    <nav className="rl-tabs" role="tablist" data-testid="xdr-record-tabs">
      {RECORD_TABS.map(t => {
        const isActive = current === t.key;
        return (
          <button
            key={t.key}
            role="tab"
            type="button"
            className={`rl-tab ${isActive ? "active" : ""}`}
            aria-selected={isActive}
            onClick={() => onChange(t.key)}
            data-testid={`xdr-record-tab-${t.key}`}
          >
            {t.label}
            {counts[t.key] != null && (
              <span className="count">{counts[t.key]}</span>
            )}
          </button>
        );
      })}
    </nav>
  );
}
