/**
 * LifecycleBar — NivXRay ONE XDR skin.
 *
 * Reference: §progression.  Dot + label per stage; arrow separator.
 * Stages that are legal next-transitions render as clickable
 * ".actionable" and hover in cyan.  Passed stages get the mint "done"
 * treatment; the current stage gets the purple "active" halo.
 */
import React, { useState, useMemo } from "react";
import { Check, Loader2, AlertOctagon } from "lucide-react";

import { LIFECYCLE_STATES, LIFECYCLE_TRANSITIONS } from "@/lib/incidentsApi";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

export default function LifecycleBar({ state, onTransition }) {
  const [busy, setBusy]   = useState(null);
  const [error, setError] = useState(null);

  const activeIdx = useMemo(
    () => LIFECYCLE_STATES.findIndex((s) => s.key === state),
    [state],
  );
  const allowed = useMemo(
    () => new Set(LIFECYCLE_TRANSITIONS[state] || []),
    [state],
  );

  const handleClick = async (target) => {
    if (!allowed.has(target) || busy) return;
    setBusy(target); setError(null);
    try { await onTransition(target); }
    catch (e) { setError(e?.response?.data?.detail || e?.message || "Transition failed."); }
    finally  { setBusy(null); }
  };

  return (
    <>
      <div className="progression" data-testid={T.lifecycleBar}>
        {LIFECYCLE_STATES.map((s, idx) => {
          const isActive  = idx === activeIdx;
          const isDone    = idx <  activeIdx;
          const isTarget  = allowed.has(s.key);
          const isBusy    = busy === s.key;
          const clickable = isTarget && !busy;

          const cls = [
            "stage",
            isActive && "active",
            isDone   && "done",
            clickable && "actionable",
          ].filter(Boolean).join(" ");

          const testId = isTarget
            ? T.lifecycleTransition(s.key)
            : T.lifecycleStep(s.key);

          return (
            <React.Fragment key={s.key}>
              <button
                type="button"
                className={cls}
                data-testid={testId}
                data-active={isActive || undefined}
                disabled={!clickable}
                onClick={() => clickable && handleClick(s.key)}
                title={
                  isActive  ? "Current state"
                  : isDone    ? "Passed"
                  : isTarget  ? `Transition to ${s.label}`
                                : "Not reachable from current state"
                }
              >
                <span className="dot">
                  {isBusy   && <Loader2 size={11} className="spin" />}
                  {!isBusy && isDone && <Check size={12} />}
                  {!isBusy && !isDone && String(idx + 1)}
                </span>
                <span className="lbl">{s.label}</span>
              </button>
              {idx < LIFECYCLE_STATES.length - 1 && <span className="stage-arrow" />}
            </React.Fragment>
          );
        })}
      </div>
      {error && (
        <div
          style={{
            marginTop: 6, color: "#ff9494",
            fontSize: 11, fontFamily: "var(--xmono)",
            display: "inline-flex", alignItems: "center", gap: 6,
          }}
        >
          <AlertOctagon size={12} /> {String(error)}
        </div>
      )}
    </>
  );
}
