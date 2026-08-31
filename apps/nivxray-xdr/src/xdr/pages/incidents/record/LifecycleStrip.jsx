/**
 * LifecycleStrip · Layer 3 · Defender/SIR-inspired state stepper.
 *
 * The strip is presentation-only: it invokes the existing
 * `PATCH /api/incidents/:id/state` endpoint (already policy-guarded
 * on the backend) via the `onTransition` callback and honours the
 * `LIFECYCLE_TRANSITIONS` map that mirrors backend truth.  Every
 * illegal step renders as non-clickable.
 */
import React, { useMemo, useState } from "react";
import { Check, Loader2, AlertOctagon } from "lucide-react";

import { LIFECYCLE_STATES, LIFECYCLE_TRANSITIONS } from "@/lib/incidentsApi";

export default function LifecycleStrip({ state, onTransition }) {
  const [busy, setBusy]   = useState(null);
  const [error, setError] = useState(null);

  const activeIdx = useMemo(
    () => LIFECYCLE_STATES.findIndex((s) => s.key === state),
    [state]);
  const allowed = useMemo(
    () => new Set(LIFECYCLE_TRANSITIONS[state] || []),
    [state]);

  const go = async (target) => {
    if (!allowed.has(target) || busy) return;
    setBusy(target); setError(null);
    try   { await onTransition(target); }
    catch (e) { setError(e?.response?.data?.detail?.error || e?.message || "Transition failed."); }
    finally { setBusy(null); }
  };

  return (
    <>
      <div className="rl-lifecycle" data-testid="xdr-record-lifecycle">
        {LIFECYCLE_STATES.map((s, i) => {
          const isActive  = i === activeIdx;
          const isDone    = i <  activeIdx;
          const isTarget  = allowed.has(s.key);
          const isBusy    = busy === s.key;
          const clickable = isTarget && !busy;

          const cls = [
            "rl-step",
            isDone && "done",
            isActive && "active",
            clickable && "actionable",
          ].filter(Boolean).join(" ");

          return (
            <React.Fragment key={s.key}>
              <button
                type="button"
                className={cls}
                disabled={!clickable}
                onClick={() => clickable && go(s.key)}
                title={isActive ? "Current state"
                    : isDone   ? "Passed"
                    : isTarget ? `Transition to ${s.label}`
                                : "Not reachable from current state"}
                data-testid={isTarget
                    ? `xdr-record-lifecycle-transition-${s.key}`
                    : `xdr-record-lifecycle-step-${s.key}`}
                data-active={isActive || undefined}
              >
                <span className="dot">
                  {isBusy       && <Loader2 size={12} className="rl-spin" />}
                  {!isBusy && isDone && <Check size={13} />}
                  {!isBusy && !isDone && String(i + 1)}
                </span>
                <span className="lbl">{s.label}</span>
              </button>
              {i < LIFECYCLE_STATES.length - 1 && (
                <span className={`rl-step-arrow ${isDone ? "done" : ""}`} />
              )}
            </React.Fragment>
          );
        })}
      </div>
      {error && (
        <div className="rl-lifecycle-error" data-testid="xdr-record-lifecycle-error">
          <AlertOctagon size={12} style={{ display: "inline", verticalAlign: "-2px", marginRight: 4 }} />
          {String(error)}
        </div>
      )}
    </>
  );
}
