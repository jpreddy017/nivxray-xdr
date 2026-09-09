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
import { useNavigate } from "react-router-dom";
import { ArrowRight, Lock } from "lucide-react";
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
  const rec = (tab) => `/xdr/incidents/${encodeURIComponent(caseId)}?tab=${tab}`;

  // PR-XDR-0 · every destination below is a canonical in-product NivXRay XDR
  // route. The previous targets (`/history`, `/analyst`, `/v2/irg/:id`,
  // `/heatmap`) are base-app paths that do not exist in this bundle, so each
  // "open" fell through the SPA catch-all to the incident queue.
  return {
    evidence: hasCase ? {
      status: "available",
      title:  "Structured Evidence (NivXRay XDR incident record)",
      body:   "Domain evidence for this incident is projected on the record's Evidence lens, backed by the authoritative evidence pointers.",
      deep_link: rec("evidence"),
    } : null,

    timeline: hasCase ? {
      status: "available",
      title:  "Timeline (NivXRay XDR incident record)",
      body:   "The canonical chronology for this incident, including the attributed state history.",
      deep_link: rec("timeline"),
    } : null,

    attack_story: hasCase ? {
      status: "available",
      title:  "Attack Story (NivXRay XDR incident record)",
      body:   "The Attack Story lens is native to the NivXRay XDR incident record. We navigate to it — we do not duplicate it.",
      deep_link: rec("attack_story"),
    } : null,

    evidence_graph: hasCase ? {
      status: "available",
      title:  "Evidence Graph (NivXRay XDR incident record)",
      body:   "Relationship graph over this incident's evidence, rendered natively in NivXRay XDR.",
      deep_link: rec("attack_graph"),
    } : null,

    attck: {
      status: "available",
      title:  "MITRE ATT&CK Heatmap (NivXRay XDR)",
      body:   "The native NivXRay XDR ATT&CK heatmap, reading /api/mitre/heatmap. Per-incident technique filtering is a later slice.",
      deep_link: "/xdr/intelligence/mitre",
    },

    verdict: hasCase ? {
      status: "available",
      title:  "Stage-2 Deterministic Verdict",
      body:   incident?.verdict_stage2
                ? `Current Stage-2 label: ${incident.verdict_stage2.label} · confidence ${incident.verdict_stage2.confidence_bucket} · risk ${incident.verdict_stage2.risk_score}. Full explainability is on the record's Verdict & Technical lens.`
                : "Stage-2 has not been computed yet for this incident.",
      deep_link: rec("technical"),
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
  const navigate = useNavigate();
  if (!cap) {
    return (
      <div className="x-empty" data-testid={T.investigationSubtabBody(activeKey)}>
        No data attached to this incident yet.
      </div>
    );
  }
  const isComing = cap.status === "coming_in_slice";
  // PR-XDR-0 · in-product navigation only. No new browser tab, no other
  // frontend; the NivXRay XDR shell stays mounted.
  const launch = () => {
    if (isComing || !cap.deep_link) return;
    navigate(cap.deep_link);
  };
  return (
    <div className="x-reserved" data-testid={T.investigationSubtabBody(activeKey)}>
      <div className="lock">
        {isComing ? <Lock size={11} /> : <ArrowRight size={11} />}
        {isComing ? `Reserved · ${cap.slice}` : "Native NivXRay XDR surface"}
      </div>
      <div className="title">{cap.title}</div>
      <div className="body">{cap.body}</div>
      {!isComing && cap.deep_link && (
        <button
          type="button"
          className="btn primary"
          style={{ alignSelf: "flex-start", marginTop: 4 }}
          data-testid={T.investigationLaunch(activeKey)}
          data-open-to={cap.deep_link}
          onClick={launch}
        >
          Open <ArrowRight size={11} />
        </button>
      )}
    </div>
  );
}
