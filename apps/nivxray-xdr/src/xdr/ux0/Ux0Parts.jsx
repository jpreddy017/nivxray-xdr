/**
 * E2E-UX0 · shared prototype parts.
 *
 * These are the candidate contracts for `NxIncidentHeader`,
 * `NxMetricDrawerCard`, `NxStageRail`, `NxClaimCard` and
 * `NxTechnicalDetails` (blueprint §4). They live under `ux0/` until the owner
 * approves the design — nothing in `nx/` is modified before approval.
 */
import React, { useState } from "react";
import { ChevronDown, ChevronRight, ArrowRight, Copy, Check } from "lucide-react";

export const Panel = ({ title, right, flush = false, children, testid }) => (
  <section className="ux0-panel ux0-rise" data-testid={testid}>
    <header className="ux0-panel__h">
      <span className="ux0-panel__t">{title}</span>
      {right}
    </header>
    <div className={`ux0-panel__b${flush ? " ux0-panel__b--flush" : ""}`}>
      {children}
    </div>
  </section>
);

export const Fact = ({ k, v, warn }) => (
  <div className="ux0-fact">
    <div className="ux0-fact__k">{k}</div>
    <div className={`ux0-fact__v${warn ? " is-warn" : ""}`}>{v}</div>
  </div>
);

export const MetricDrawerCard = ({ label, value, sub, onViewAll, testid }) => (
  <button type="button" className="ux0-metric" onClick={onViewAll}
          data-testid={testid}>
    <div className="ux0-metric__k">{label}</div>
    <div className="ux0-metric__v">{value}</div>
    <div className="ux0-metric__sub">{sub}</div>
    <span className="ux0-metric__cta">View all <ArrowRight size={12} /></span>
  </button>
);

export const StageRail = ({ stages, active, onSelect }) => (
  <div className="ux0-rail" data-testid="ux0-stage-rail">
    {stages.map((s) => (
      <button key={s.key} type="button"
              className={`ux0-rail__node${
                s.key === active ? " is-active" : s.state === "done" ? " is-done" : ""}`}
              onClick={() => onSelect(s.key)}
              data-testid={`ux0-stage-${s.key}`}>
        <div className="ux0-rail__line"><span className="ux0-rail__dot" /></div>
        <div className="ux0-rail__lbl">{s.label}</div>
      </button>
    ))}
  </div>
);

export const TechnicalDetails = ({ title = "Technical details", json, testid }) => {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const body = typeof json === "string" ? json : JSON.stringify(json, null, 2);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(body);
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch { /* clipboard unavailable — non-fatal */ }
  };
  return (
    <div className="ux0-tech" data-testid={testid}>
      <button type="button" className="ux0-tech__h" onClick={() => setOpen((o) => !o)}
              data-testid={`${testid}-toggle`}>
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        {title} — engine output, not the analyst answer
      </button>
      {open && (
        <>
          <button type="button" className="ux0-btn" onClick={copy}
                  style={{ marginBottom: 8 }} data-testid={`${testid}-copy`}>
            {copied ? <Check size={13} /> : <Copy size={13} />}
            {copied ? "Copied" : "Copy JSON"}
          </button>
          <pre className="ux0-pre" data-testid={`${testid}-json`}>{body}</pre>
        </>
      )}
    </div>
  );
};
