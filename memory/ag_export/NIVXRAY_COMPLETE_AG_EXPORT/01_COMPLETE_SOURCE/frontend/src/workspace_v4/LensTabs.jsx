/**
 * Lens tab bar (Blueprint §9).
 *
 * PR-4 wires the Summary + Story lenses to real content. Remaining
 * lenses (Timeline / Evidence / Analysis / Exports) stay as
 * placeholder panels per the ARB PR sequence:
 *   summary  · story    → PR-4 (this PR)
 *   timeline · evidence → PR-5
 *   analysis · exports  → PR-6
 */
import React from "react";
import SummaryLens from "./SummaryLens";
import StoryLens from "./StoryLens";
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

export function LensPanel({ lens, caseId, onAnchorClick }) {
  // PR-4 lenses render real content.
  if (lens === "summary") {
    return (
      <div
        role="tabpanel"
        aria-labelledby={`lens-tab-${lens}`}
        data-testid={TID_LENS_PANEL(lens)}
        className="flex min-h-[320px] flex-1 flex-col"
      >
        <SummaryLens caseId={caseId} onAnchorClick={onAnchorClick} />
      </div>
    );
  }
  if (lens === "story") {
    return (
      <div
        role="tabpanel"
        aria-labelledby={`lens-tab-${lens}`}
        data-testid={TID_LENS_PANEL(lens)}
        className="flex min-h-[320px] flex-1 flex-col"
      >
        <StoryLens caseId={caseId} onAnchorClick={onAnchorClick} />
      </div>
    );
  }
  // Placeholder for PR-5 / PR-6 lenses.
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
