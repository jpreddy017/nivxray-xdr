/**
 * NxEntityHeader · the platform's ONE entity/record header pattern.
 *
 * Used identically by the incident investigation workspace and by every
 * Entity 360 (device · user · process · file · IP · domain · hash), so an
 * analyst never has to relearn where the verdict, the owner or the actions
 * live.
 *
 *   eyebrow            INCIDENT · INC000001376
 *   title              Execution from a world-writable directory
 *   facts              severity · verdict · confidence · risk · state · owner
 *   provenance         evidence/provenance line — NivXRay's differentiator
 *   actions            right-aligned, permission-aware at the call site
 *   tabs               the single NxTabs bar, owned by the header
 */
import React from "react";
import NxTabs from "./NxTabs";
import "./nx-entity.css";

export function NxFact({ label, children, testid }) {
  return (
    <div className="nx-eh-fact" data-testid={testid}>
      <span className="nx-eh-fact-k">{label}</span>
      <span className="nx-eh-fact-v">{children ?? "—"}</span>
    </div>
  );
}

export default function NxEntityHeader({
  eyebrow, title, subtitle, facts = null, chips = null,
  provenance = null, actions = null,
  tabs = null, activeTab = null, onTabChange = null,
  testid = "nx-entity-header",
}) {
  return (
    <header className="nx-eh" data-testid={testid}>
      <div className="nx-eh-top">
        <div className="nx-eh-id">
          {eyebrow && (
            <div className="nx-eh-eyebrow" data-testid={`${testid}-eyebrow`}>
              {eyebrow}
            </div>
          )}
          <h1 className="nx-eh-title" data-testid={`${testid}-title`}>
            {title}
          </h1>
          {subtitle && <div className="nx-eh-sub">{subtitle}</div>}
          {chips && (
            <div className="nx-eh-chips" data-testid={`${testid}-chips`}>
              {chips}
            </div>
          )}
        </div>
        {actions && (
          <div className="nx-eh-actions" data-testid={`${testid}-actions`}>
            {actions}
          </div>
        )}
      </div>

      {facts && (
        <div className="nx-eh-facts" data-testid={`${testid}-facts`}>
          {facts}
        </div>
      )}

      {provenance && (
        <div className="nx-eh-prov" data-testid={`${testid}-provenance`}>
          {provenance}
        </div>
      )}

      {tabs && (
        <NxTabs tabs={tabs} active={activeTab} onChange={onTabChange}
                testid={`${testid}-tabs`} />
      )}
    </header>
  );
}
