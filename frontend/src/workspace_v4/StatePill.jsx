/**
 * Investigation State pill (Blueprint §8.1).
 *
 * PR-3 scope: read-only visual pill. Transition buttons are wired to
 * the L1 POST /state/transition endpoint, but the actual UI for
 * choosing "next state" is minimal — a single "Advance" button that
 * moves to the sole allowed next state (per §8.1 the graph is
 * mostly linear). No graphs, no timelines, no history drawer — those
 * belong to later PRs.
 */
import React, { useMemo } from "react";
import { Button } from "@/components/ui/button";
import {
  TID_STATE_PILL,
  TID_STATE_PILL_VALUE,
  TID_STATE_TRANSITION_BTN,
} from "./testIds";

// Blueprint §8.1 transition table — mirrors the backend
// InvestigationStateMachine.
const NEXT_STATE = {
  new:         "collecting",
  collecting:  "correlating",
  correlating: "reviewing",
  reviewing:   "completed",
  completed:   "reported",
  reported:    "reopened",
  reopened:    "correlating",
};

// Tailwind color per state — deliberately restrained (no gradients).
const STATE_STYLE = {
  new:         "bg-slate-800 text-slate-200 border-slate-600",
  collecting:  "bg-indigo-950 text-indigo-200 border-indigo-700",
  correlating: "bg-amber-950 text-amber-200 border-amber-700",
  reviewing:   "bg-purple-950 text-purple-200 border-purple-700",
  completed:   "bg-emerald-950 text-emerald-200 border-emerald-700",
  reported:    "bg-cyan-950 text-cyan-200 border-cyan-700",
  reopened:    "bg-rose-950 text-rose-200 border-rose-700",
};

export function StatePill({ state = "new", disabled = false, onAdvance }) {
  const next = useMemo(() => NEXT_STATE[state] || null, [state]);
  const style = STATE_STYLE[state] || STATE_STYLE.new;
  const label = state.replace(/_/g, " ");

  return (
    <div
      data-testid={TID_STATE_PILL}
      className="flex items-center gap-3"
    >
      <span
        data-testid={TID_STATE_PILL_VALUE}
        className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-wide ${style}`}
        aria-label={`investigation state ${label}`}
      >
        {label}
      </span>
      {next ? (
        <Button
          data-testid={TID_STATE_TRANSITION_BTN(next)}
          size="sm"
          variant="outline"
          disabled={disabled}
          onClick={() => onAdvance?.(next)}
          className="h-7 px-3 text-xs"
        >
          Advance → {next.replace(/_/g, " ")}
        </Button>
      ) : null}
    </div>
  );
}

export default StatePill;
