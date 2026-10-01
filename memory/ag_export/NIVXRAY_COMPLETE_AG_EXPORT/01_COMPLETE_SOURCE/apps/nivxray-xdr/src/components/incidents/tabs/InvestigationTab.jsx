/**
 * InvestigationTab · 7 sub-tab nav shell (XDR skin).
 *
 * Reference: §subnav / §subtabbtn (mint underline for active tab).
 *
 * Each sub-tab is either a NAV SHELL to an existing implementation
 * (opens in a new tab per the telemetry rule) or an honest
 * "Reserved · later slice" state.  We never build a duplicate.
 */
import React, { useState } from "react";
import { ExternalLink, Lock } from "lucide-react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const SUBTABS = [
  { key: "evidence",       label: "Evidence" },
  { key: "timeline",       label: "Timeline" },
  { key: "attack_story",   label: "Attack Story" },
  { key: "evidence_graph", label: "Evidence Graph" },
  { key: "attck",          label: "ATT&CK" },
  { key: "verdict",        label: "Verdict" },
  { key: "report",         label: "Report" },
];

function buildCapabilityMap(incident) {
  const caseId = incident?.id || "";
  const hasCase = !!caseId;

  return {
    evidence: hasCase ? {
      status: "available",
      title:  "Structured Evidence (existing Analyst Workspace)",
      body:   "Structured Evidence Tab is available inside the Analyst Workspace where the case was decoded. Opens the workspace with this case rehydrated.",
      deep_link: `/history?case=${encodeURIComponent(caseId)}`,
    } : null,

    timeline: hasCase ? {
      status: "available",
      title:  "Attack Story Timeline (existing IUE projection)",
      body:   "Reuses the IUE timeline projection surfaced today inside the Analyst Workspace Story lens. This slice does not duplicate the canvas.",
      deep_link: `/analyst?case=${encodeURIComponent(caseId)}&tab=story`,
    } : null,

    attack_story: hasCase ? {
      status: "available",
      title:  "Attack Story lens (existing)",
      body:   "The Attack Story lens already lives inside the Analyst Workspace. It stays there — we deep-link, not duplicate.",
      deep_link: `/analyst?case=${encodeURIComponent(caseId)}&tab=story`,
    } : null,

    evidence_graph: hasCase ? {
      status: "available",
      title:  "Investigation Relationship Graph (v2 IRG)",
      body:   "Reuses the existing IRG workspace — the same graph implementation used across NivXRay v2.",
      deep_link: `/v2/irg/${encodeURIComponent(caseId)}`,
    } : null,

    attck: {
      status: "available",
      title:  "MITRE ATT&CK Heatmap (existing)",
      body:   "Uses the existing global heatmap page. Filtering to per-incident techniques will land in a later slice.",
      deep_link: "/heatmap",
    },

    verdict: hasCase ? {
      status: "available",
      title:  "Stage-2 Deterministic Verdict",
      body:   incident?.verdict_stage2
                ? `Current Stage-2 label: ${incident.verdict_stage2.label} · confidence ${incident.verdict_stage2.confidence_bucket} · risk ${incident.verdict_stage2.risk_score}. Full explainability lives in the EDR Device Trajectory Verdict Card.`
                : "Stage-2 has not been computed yet for this incident. Trigger a decode from the Analyst Workspace or hit /api/verdict/stage2/compute.",
      deep_link: "/edr/trajectory",
    } : null,

    report: {
      status: "coming_in_slice",
      title:  "Incident Report",
      body:   "Deterministic report generation for the canonical Incident is scheduled for Slice 2 (Negative Explainability + Evidence Gaps).",
      deep_link: null,
      slice: "Slice 2",
    },
  };
}

export default function InvestigationTab({ incident }) {
  const [active, setActive] = useState(SUBTABS[0].key);
  const caps = buildCapabilityMap(incident);
  const cap = caps[active];

  return (
    <div data-testid={T.investigationPane}>
      <div className="subnav" data-testid={T.investigationSubtabs} role="tablist">
        {SUBTABS.map((s) => {
          const isActive = s.key === active;
          return (
            <button
              key={s.key}
              type="button"
              role="tab"
              className={`subtabbtn ${isActive ? "active" : ""}`}
              data-testid={T.investigationSubtab(s.key)}
              data-active={isActive || undefined}
              aria-selected={isActive}
              onClick={() => setActive(s.key)}
            >
              {s.label}
            </button>
          );
        })}
      </div>
      <SubtabBody activeKey={active} cap={cap} />
    </div>
  );
}

function SubtabBody({ activeKey, cap }) {
  if (!cap) {
    return (
      <div className="x-empty" data-testid={T.investigationSubtabBody(activeKey)}>
        No data attached to this incident yet. Save a case from the
        Workspace first — this sub-tab will then surface the corresponding
        existing capability.
      </div>
    );
  }
  const isComing = cap.status === "coming_in_slice";
  const launch = () => {
    if (isComing || !cap.deep_link) return;
    window.open(cap.deep_link, "_blank", "noopener,noreferrer");
  };
  return (
    <div className="x-reserved" data-testid={T.investigationSubtabBody(activeKey)}>
      <div className="lock">
        {isComing ? <Lock size={11} /> : <ExternalLink size={11} />}
        {isComing ? `Reserved · ${cap.slice}` : "Reuses existing capability"}
      </div>
      <div className="title">{cap.title}</div>
      <div className="body">{cap.body}</div>
      {!isComing && cap.deep_link && (
        <button
          type="button"
          className="btn primary"
          style={{ alignSelf: "flex-start", marginTop: 4 }}
          data-testid={T.investigationLaunch(activeKey)}
          onClick={launch}
        >
          Open in new tab <ExternalLink size={11} />
        </button>
      )}
    </div>
  );
}
