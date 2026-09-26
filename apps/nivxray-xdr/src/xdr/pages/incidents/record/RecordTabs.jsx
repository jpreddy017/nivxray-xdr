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

// ── INVESTIGATION INFORMATION ARCHITECTURE (owner-approved 2026-09-05)
// Grouped by the ANALYST'S QUESTION, never by backend engine.  Reading
// left to right is the investigation itself:
//
//   WHAT HAPPENED → WHY WE BELIEVE IT → WHAT PROVES IT → WHAT NEXT
//
// Attack Story leads (primary narrative), the Evidence Graph is the
// secondary relationship surface, and Device Trajectory stays the
// endpoint forensic view inside the evidence group.
export const RECORD_TAB_GROUPS = [
  {
    id: "happened", label: "What happened",
    question: "The narrative and the sequence",
    tabs: [
      { key: "attack_story", label: "Attack Story", primary: true },
      { key: "executive",    label: "Summary"    },
      { key: "timeline",     label: "Timeline"   },
    ],
  },
  {
    id: "believe", label: "Why we believe it",
    question: "The verdict and its contributors",
    tabs: [
      { key: "technical", label: "Verdict & Technical" },
      { key: "mitre",     label: "ATT&CK" },
    ],
  },
  {
    id: "proves", label: "What proves it",
    question: "Evidence, relationships and the gaps",
    tabs: [
      { key: "evidence",     label: "Evidence" },
      { key: "attack_graph", label: "Evidence Graph" },
      { key: "related",      label: "Related" },
    ],
  },
  {
    id: "next", label: "What next",
    question: "Act, record and verify",
    tabs: [
      { key: "auto_investigation", label: "Investigation" },
      { key: "closure",            label: "Response & Closure" },
      { key: "notes",              label: "Notes" },
      { key: "report",             label: "Report" },
    ],
  },
];

export const RECORD_TABS = RECORD_TAB_GROUPS.flatMap(g => g.tabs);

// Which tabs render inside the dark investigation canvas.
export const CANVAS_TABS = new Set([
  "mitre", "attack_story", "attack_graph", "auto_investigation",
]);

export default function RecordTabs({ current, onChange, counts = {} }) {
  return (
    <nav className="rl-tabs rl-tabs--grouped" role="tablist"
          data-testid="xdr-record-tabs">
      {RECORD_TAB_GROUPS.map(g => (
        <div key={g.id} className="rl-tabgroup"
              data-testid={`xdr-record-tabgroup-${g.id}`}>
          <span className="rl-tabgroup__label" title={g.question}>
            {g.label}
          </span>
          <div className="rl-tabgroup__tabs">
            {g.tabs.map(t => {
              const isActive = current === t.key;
              return (
                <button
                  key={t.key}
                  role="tab"
                  type="button"
                  className={`rl-tab${isActive ? " active" : ""}`
                    + (t.primary ? " rl-tab--primary" : "")}
                  aria-selected={isActive}
                  onClick={() => onChange(t.key)}
                  title={t.primary
                    ? `${t.label} — primary analyst narrative`
                    : t.label}
                  data-testid={`xdr-record-tab-${t.key}`}
                >
                  {t.label}
                  {counts[t.key] != null && (
                    <span className="count">{counts[t.key]}</span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}
