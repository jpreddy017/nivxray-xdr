/**
 * Lens tab bar (Blueprint §9).
 *
 * PR-3 renders empty placeholder panels for each lens. Real content
 * for each lens lands in PR-4 / PR-5 / PR-6:
 *   summary  · story    → PR-4
 *   timeline · evidence → PR-5
 *   analysis · exports  → PR-6
 */
import React from "react";
import {
  LENSES,
  TID_LENS_PANEL,
  TID_LENS_PLACEHOLDER,
  TID_LENS_TAB,
  TID_LENS_TABS,
} from "./testIds";

const LABELS = {
  summary:  "Summary",
  story:    "Story",
  timeline: "Timeline",
  evidence: "Evidence",
  analysis: "Analysis",
  exports:  "Exports",
};

const NEXT_PR = {
  summary:  "PR-4",
  story:    "PR-4",
  timeline: "PR-5",
  evidence: "PR-5",
  analysis: "PR-6",
  exports:  "PR-6",
};

export function LensTabs({ activeLens, onLensChange }) {
  return (
    <div
      role="tablist"
      aria-label="Workspace lenses"
      data-testid={TID_LENS_TABS}
      className="flex flex-wrap gap-1 border-b border-slate-800 bg-slate-950/60 px-4 py-2"
    >
      {LENSES.map((lens) => {
        const active = lens === activeLens;
        return (
          <button
            key={lens}
            role="tab"
            aria-selected={active}
            data-testid={TID_LENS_TAB(lens)}
            onClick={() => onLensChange?.(lens)}
            className={`rounded-md px-3 py-1.5 text-sm transition-colors focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
              active
                ? "bg-indigo-500/15 text-indigo-200"
                : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-100"
            }`}
          >
            {LABELS[lens]}
          </button>
        );
      })}
    </div>
  );
}

export function LensPanel({ lens }) {
  return (
    <section
      role="tabpanel"
      aria-labelledby={`lens-tab-${lens}`}
      data-testid={TID_LENS_PANEL(lens)}
      className="flex min-h-[320px] flex-1 items-center justify-center px-4 py-16"
    >
      <div
        data-testid={TID_LENS_PLACEHOLDER(lens)}
        className="max-w-md text-center"
      >
        <p className="text-xs uppercase tracking-widest text-slate-500">
          {LABELS[lens]} lens
        </p>
        <p className="mt-3 text-sm text-slate-400">
          Placeholder. Real content lands in {NEXT_PR[lens]} per the
          approved roadmap.
        </p>
      </div>
    </section>
  );
}

export default LensTabs;
