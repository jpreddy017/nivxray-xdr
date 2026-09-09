/**
 * Workspace Mode selector (Blueprint §8.2).
 *
 * Native <select> for maximum keyboard accessibility. No portal, no
 * animation — the shell must be usable with tab + arrow keys only.
 */
import React from "react";
import { MODES, TID_MODE_OPTION, TID_MODE_SELECT } from "./testIds";

const LABELS = {
  quick_triage:  "Quick Triage",
  investigation: "Investigation",
  deep_analysis: "Deep Analysis",
};

export function ModeSelector({ value, onChange, disabled = false }) {
  return (
    <label className="flex items-center gap-2 text-xs text-slate-300">
      <span className="uppercase tracking-wider text-slate-400">Mode</span>
      <select
        data-testid={TID_MODE_SELECT}
        value={value}
        disabled={disabled}
        onChange={(e) => onChange?.(e.target.value)}
        className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {MODES.map((m) => (
          <option
            key={m}
            value={m}
            data-testid={TID_MODE_OPTION(m)}
            className="bg-slate-900 text-slate-100"
          >
            {LABELS[m] || m}
          </option>
        ))}
      </select>
    </label>
  );
}

export default ModeSelector;
