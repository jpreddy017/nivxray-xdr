/**
 * InvestigationTab · 7 sub-tab nav shell.
 *
 * Each sub-tab is a NAV SHELL — not a fake duplicate implementation.
 *   - When an existing capability already ships in another surface,
 *     the sub-tab surfaces a deep link + short description and opens
 *     that surface in a new tab (owner telemetry rule).
 *   - When the capability is not yet available in this slice, the
 *     sub-tab says so plainly.  No placeholder that looks functional.
 *
 * The 7 sub-tabs (owner spec):
 *   Evidence · Timeline · Attack Story · Evidence Graph · ATT&CK ·
 *   Verdict · Report
 */
import React, { useState } from "react";
import { ExternalLink, Lock, ChevronRight, Info } from "lucide-react";

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

/**
 * Real capability map — points each sub-tab at the existing
 * implementation when one exists.  Keep this table SMALL and honest:
 * every entry either resolves to a live route or is `null`.
 */
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
                ? `Current Stage-2 label: ${incident.verdict_stage2.label} · confidence ${incident.verdict_stage2.confidence_bucket} · risk ${incident.verdict_stage2.risk_score}. Full explainability is rendered inside the EDR Device Trajectory Verdict Card.`
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
  const capabilities = buildCapabilityMap(incident);
  const cap = capabilities[active];

  return (
    <section
      data-testid={T.investigationPane}
      style={{ display: "flex", flexDirection: "column", gap: 14 }}
    >
      <div
        data-testid={T.investigationSubtabs}
        role="tablist"
        aria-label="Investigation sub-tabs"
        style={{
          display: "flex", flexWrap: "wrap", gap: 6,
          padding: 6,
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 10,
          background: "rgba(2,6,23,0.5)",
        }}
      >
        {SUBTABS.map((s) => {
          const isActive = s.key === active;
          return (
            <button
              key={s.key}
              role="tab"
              type="button"
              onClick={() => setActive(s.key)}
              data-testid={T.investigationSubtab(s.key)}
              data-active={isActive || undefined}
              aria-selected={isActive}
              style={{
                padding: "6px 12px",
                borderRadius: 6,
                fontFamily: "JetBrains Mono, ui-monospace, monospace",
                fontSize: 11, letterSpacing: "0.12em",
                textTransform: "uppercase",
                border: `1px solid ${isActive ? "rgba(34,197,94,0.55)" : "transparent"}`,
                background: isActive
                  ? "linear-gradient(160deg, rgba(34,197,94,0.16), rgba(34,197,94,0.03))"
                  : "transparent",
                color: isActive ? "#86efac" : "rgba(203,213,225,0.75)",
                cursor: "pointer",
                transition: "background 160ms ease, color 160ms ease, border-color 160ms ease",
              }}
            >
              {s.label}
            </button>
          );
        })}
      </div>

      <SubtabBody activeKey={active} cap={cap} />
    </section>
  );
}

function SubtabBody({ activeKey, cap }) {
  if (!cap) {
    return (
      <div
        data-testid={T.investigationSubtabBody(activeKey)}
        style={emptyStyle}
      >
        <Info size={14} style={{ color: "rgba(148,163,184,0.7)" }} />
        <div>
          <div style={{ color: "#e2e8f0", fontWeight: 600 }}>
            No data attached to this incident.
          </div>
          <div style={{ marginTop: 4, fontSize: 12,
                          color: "rgba(148,163,184,0.7)" }}>
            Save a case from the Workspace first — then this sub-tab
            will surface the corresponding existing capability.
          </div>
        </div>
      </div>
    );
  }

  const isComing = cap.status === "coming_in_slice";

  const launch = () => {
    if (isComing || !cap.deep_link) return;
    window.open(cap.deep_link, "_blank", "noopener,noreferrer");
  };

  return (
    <div
      data-testid={T.investigationSubtabBody(activeKey)}
      style={{
        padding: 18,
        border: "1px solid rgba(148,163,184,0.14)",
        borderRadius: 10,
        background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.62))",
        display: "flex", flexDirection: "column", gap: 10,
      }}
    >
      <div style={{
        display: "inline-flex", alignItems: "center", gap: 8,
        color: isComing ? "rgba(148,163,184,0.85)" : "#86efac",
        fontFamily: "JetBrains Mono, monospace",
        fontSize: 10, letterSpacing: "0.18em",
        textTransform: "uppercase",
      }}>
        {isComing ? <Lock size={12} /> : <ChevronRight size={12} />}
        {isComing ? `Reserved · ${cap.slice}` : "Reuses existing capability"}
      </div>
      <div style={{ fontSize: 15, fontWeight: 700, color: "#e2e8f0" }}>
        {cap.title}
      </div>
      <div style={{ fontSize: 12, color: "rgba(203,213,225,0.75)",
                      lineHeight: 1.5 }}>
        {cap.body}
      </div>
      {!isComing && cap.deep_link && (
        <button
          type="button"
          onClick={launch}
          data-testid={T.investigationLaunch(activeKey)}
          className="nvx-btn sm"
          style={{
            alignSelf: "flex-start",
            display: "inline-flex", alignItems: "center", gap: 6,
          }}
        >
          Open in new tab
          <ExternalLink size={12} />
        </button>
      )}
    </div>
  );
}

const emptyStyle = {
  padding: 18,
  border: "1px dashed rgba(148,163,184,0.20)",
  borderRadius: 10,
  background: "rgba(2,6,23,0.42)",
  display: "flex", alignItems: "flex-start", gap: 10,
};
