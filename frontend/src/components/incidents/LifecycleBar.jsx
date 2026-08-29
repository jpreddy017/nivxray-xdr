/**
 * LifecycleBar — 5-state incident lifecycle stepper.
 *
 * Reads the current incident state and the allowed transitions from
 * `LIFECYCLE_TRANSITIONS` (mirrors the backend allow-list).
 * Rendering a transition button in the UI does NOT bypass the server
 * check — the PATCH endpoint enforces the same rules.
 */
import React, { useState } from "react";
import { Check, Loader2, AlertOctagon } from "lucide-react";

import { LIFECYCLE_STATES, LIFECYCLE_TRANSITIONS } from "@/lib/incidentsApi";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

export default function LifecycleBar({ state, onTransition }) {
  const [busy, setBusy]   = useState(null);
  const [error, setError] = useState(null);

  const active = (LIFECYCLE_STATES.findIndex((s) => s.key === state));
  const allowed = new Set(LIFECYCLE_TRANSITIONS[state] || []);

  const handleClick = async (target) => {
    if (!allowed.has(target) || busy) return;
    setBusy(target); setError(null);
    try {
      await onTransition(target);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Transition failed.");
    } finally {
      setBusy(null);
    }
  };

  return (
    <section
      data-testid={T.lifecycleBar}
      style={{
        marginTop: 14,
        padding: "14px 18px",
        border: "1px solid rgba(148,163,184,0.14)",
        borderRadius: 10,
        background: "rgba(2,6,23,0.5)",
      }}
    >
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 12, gap: 12, flexWrap: "wrap",
      }}>
        <div style={{
          fontFamily: "JetBrains Mono, monospace",
          fontSize: 10, letterSpacing: "0.18em",
          color: "rgba(148,163,184,0.85)",
          textTransform: "uppercase",
        }}>
          Lifecycle
        </div>
        {error && (
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            color: "#fca5a5", fontSize: 11,
            fontFamily: "JetBrains Mono, monospace",
          }}>
            <AlertOctagon size={12} /> {String(error)}
          </div>
        )}
      </div>

      <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap",
                      gap: 8 }}>
        {LIFECYCLE_STATES.map((s, idx) => {
          const isActive   = idx === active;
          const isDone     = idx < active;
          const isTarget   = allowed.has(s.key);
          const isBusy     = busy === s.key;
          const clickable  = isTarget && !busy;
          const tone = isActive ? "active"
                        : isDone   ? "done"
                        : isTarget ? "target"
                                     : "idle";
          const style = STYLE_BY_TONE[tone];
          return (
            <React.Fragment key={s.key}>
              <button
                type="button"
                data-testid={
                  isTarget
                    ? T.lifecycleTransition(s.key)
                    : T.lifecycleStep(s.key)
                }
                data-active={isActive || undefined}
                onClick={() => clickable && handleClick(s.key)}
                disabled={!clickable}
                style={{
                  ...style,
                  cursor: clickable ? "pointer" : "default",
                  opacity: !isActive && !isTarget && !isDone ? 0.5 : 1,
                }}
              >
                {isDone && <Check size={12} />}
                {isBusy && <Loader2 size={12} className="spin" />}
                {s.label}
              </button>
              {idx < LIFECYCLE_STATES.length - 1 && (
                <span aria-hidden style={{
                  width: 18, height: 1,
                  background: "rgba(148,163,184,0.3)",
                }} />
              )}
            </React.Fragment>
          );
        })}
      </div>
      <style>{`@keyframes lc-spin { from { transform: rotate(0); } to { transform: rotate(360deg); } }
                .spin { animation: lc-spin 1s linear infinite; }`}</style>
    </section>
  );
}

const BASE = {
  display: "inline-flex", alignItems: "center", gap: 6,
  padding: "6px 12px",
  borderRadius: 6,
  fontFamily: "JetBrains Mono, ui-monospace, monospace",
  fontSize: 11, letterSpacing: "0.12em",
  textTransform: "uppercase",
  border: "1px solid transparent",
  background: "transparent",
  transition: "background 160ms ease, color 160ms ease, border-color 160ms ease",
};

const STYLE_BY_TONE = {
  active: { ...BASE,
    color: "#86efac",
    background: "rgba(34,197,94,0.14)",
    borderColor: "rgba(34,197,94,0.55)",
    boxShadow: "0 0 12px rgba(34,197,94,0.28)",
  },
  done: { ...BASE,
    color: "rgba(203,213,225,0.7)",
    borderColor: "rgba(148,163,184,0.20)",
  },
  target: { ...BASE,
    color: "#67e8f9",
    background: "rgba(6,182,212,0.10)",
    borderColor: "rgba(6,182,212,0.45)",
  },
  idle: { ...BASE,
    color: "rgba(148,163,184,0.7)",
    borderColor: "rgba(148,163,184,0.15)",
  },
};
