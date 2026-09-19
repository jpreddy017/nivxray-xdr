/**
 * Windows console · shared presentation primitives.
 *
 * `StageBar` renders the compact `Acquired → Understood → Detectable`
 * summary. It computes NOTHING: every stage, its reached flag and its
 * detail come from the server, and clicking a stage drills into the
 * authoritative dimension it stands on.
 */
import React from "react";
import { ChevronRight } from "lucide-react";
import { STATE_TONE, measured } from "./windowsApi";

export const StateChip = ({ value, title }) => {
  const label = value === null || value === undefined ? "NOT AVAILABLE"
    : String(value);
  const tone = STATE_TONE[label] || "info";
  return (
    <span className={`wx-chip wx-${tone}`} title={title || label}
          data-testid={`wx-state-${label.replace(/\s+/g, "-").toLowerCase()}`}>
      {label}
    </span>
  );
};

export const Measured = ({ value, suffix = "" }) => (
  <span className={value === null || value === undefined ? "wx-dim" : ""}>
    {measured(value)}{value === null || value === undefined ? "" : suffix}
  </span>
);

export const StageBar = ({ stages = [], onDrill = null, testid = "wx-stages" }) => (
  <div className="wx-stagebar" data-testid={testid}>
    {stages.map((s, i) => (
      <React.Fragment key={s.stage}>
        <button type="button"
                className={`wx-stage ${s.reached ? "wx-stage-on" : "wx-stage-off"}`}
                title={s.detail}
                data-testid={`wx-stage-${s.stage.toLowerCase()}`}
                onClick={() => onDrill && onDrill(s.drill)}>
          <span className="wx-stage-name">{s.stage}</span>
          <span className="wx-stage-state">{s.state}</span>
        </button>
        {i < stages.length - 1 && (
          <ChevronRight size={12} className="wx-stage-arrow" aria-hidden="true" />
        )}
      </React.Fragment>
    ))}
  </div>
);

export const Fact = ({ label, value, reason = null, testid = null }) => (
  <div className="wx-fact" data-testid={testid}>
    <span className="wx-fact-label">{label}</span>
    <span className="wx-fact-value">
      {value === null || value === undefined || value === ""
        ? <em className="wx-dim">{reason ? "NOT AVAILABLE" : "—"}</em>
        : value}
    </span>
    {reason && <span className="wx-fact-reason">{reason}</span>}
  </div>
);

export const Section = ({ title, note = null, children, testid = null }) => (
  <section className="wx-section" data-testid={testid}>
    <h3 className="wx-section-title">{title}</h3>
    {note && <p className="wx-section-note">{note}</p>}
    {children}
  </section>
);
