/**
 * OverviewTab · Incident Evidence Across Domains (XDR skin).
 *
 * Reference: §edom-grid / §edom-card. Left-border color denotes state:
 *   • cyan  = related (has evidence, deep link available)
 *   • faint = searched (no telemetry hits recorded)
 *   • dashed faint = notconnected (integration not present for tenant)
 *
 * Owner rule: launch buttons open the domain surface in a NEW BROWSER
 * TAB — never a modal, drawer, inline miniature, or iframe.
 */
import React from "react";
import { INCIDENT_TESTIDS as T } from "@/constants/incidentTestIds";

const DOMAIN_LABELS = {
  edr:       "EDR",
  ndr:       "NDR",
  identity:  "IDENTITY",
  cloud:     "CLOUD",
  email:     "EMAIL",
  web:       "WEB",
  workspace: "WORKSPACE",
};

/** Classify a pointer into the reference `edom-card` state class. */
function classifyPointer(p) {
  if (p.status === "available")  return "related";
  // Slice 1: no "searched" state signal yet; treat unconnected domains
  // as `notconnected` when we know the tenant lacks the integration,
  // and `searched` (dim) when we simply have no evidence for it.
  return "notconnected";
}

export default function OverviewTab({ incident }) {
  const pointers = incident?.evidence_pointers || [];

  return (
    <div data-testid={T.overviewPane}>
      <div className="section-title" style={{ marginBottom: 8 }}>
        Incident Evidence Across Domains
      </div>
      <div style={{
        marginBottom: 12,
        color: "var(--xmuted)", fontSize: 11.5, lineHeight: 1.5,
      }}>
        Each card opens the full domain surface in a new browser tab.
        Unconnected integrations are shown honestly — no fake placeholders.
      </div>

      <div className="edom-grid" data-testid={T.domainCards}>
        {pointers.map((p) => {
          const cls = classifyPointer(p);
          const available = p.status === "available" && !!p.deep_link;
          const domainKey = p.domain || "workspace";
          const displayCount = domainKey === "edr" && available ? "OPEN" : (available ? "→" : "—");
          return (
            <div
              key={domainKey}
              className={`edom-card ${cls}`}
              data-testid={T.domainCard(domainKey)}
            >
              <div className="edom-top">
                <span className="edom-name">
                  {DOMAIN_LABELS[domainKey] || domainKey.toUpperCase()}
                </span>
                <span className="edom-count">{displayCount}</span>
              </div>
              <div className="edom-why">
                <b>{p.label}</b>
                {p.hint && <><br /><span>{p.hint}</span></>}
                {!available && p.reason && (
                  <><br /><span style={{ fontStyle: "italic" }}>{p.reason}</span></>
                )}
              </div>
              <button
                type="button"
                className="edom-open"
                data-testid={T.domainLaunch(domainKey)}
                disabled={!available}
                onClick={() => {
                  if (!available) return;
                  window.open(p.deep_link, "_blank", "noopener,noreferrer");
                }}
              >
                {available ? "Open in new tab →" : "Not available"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
