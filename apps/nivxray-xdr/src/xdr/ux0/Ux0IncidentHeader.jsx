/**
 * E2E-UX0 · persistent incident header (blueprint §3.1).
 *
 * Candidate contract for `NxIncidentHeader`. Band A (verdict) + band B
 * (impact) never scroll away: past 120px the header collapses to a 52px
 * condensed bar and the tab strip stays pinned.
 *
 * Every action is permission-adapted through `useAccess().canAny` —
 * three-valued, so a transient authorization read never locks an operator out.
 * There is no role-name literal in this file.
 */
import React from "react";
import { ChevronDown } from "lucide-react";
import { Link } from "react-router-dom";

import { useAccess } from "@/xdr/access/AccessProvider";
import { NxVerdict, NxConfidence, NxTabs } from "@/xdr/nx";
import { Fact } from "./Ux0Parts";

const ACTIONS = [
  { key: "assign",  label: "Assign",          perms: ["incident.assign", "incident.write"] },
  { key: "manage",  label: "Manage incident", perms: ["incident.write"] },
  { key: "respond", label: "Take action",     perms: ["incident.respond", "response.execute"] },
];

export default function Ux0IncidentHeader({
  incident, condensed, tabs, active, onTab,
}) {
  const { canAny } = useAccess();

  return (
    <>
      <div className="ux0-hdr" data-testid="ux0-incident-header"
           data-condensed={condensed ? "true" : "false"}>
        {condensed ? (
          <div className="ux0-hdr--condensed">
            <span className="ux0-sevdot" data-sev={incident.severity} />
            <span className="ux0-mono" style={{ fontSize: 11.5 }}>{incident.id}</span>
            <h1 className="ux0-hdr__title">{incident.title}</h1>
            <div className="ux0-hdr__actions" style={{ marginLeft: "auto" }}>
              <ActionCluster canAny={canAny} compact />
            </div>
          </div>
        ) : (
          <>
            <div className="ux0-hdr__crumb">
              <Link to="/xdr/incidents">Incidents</Link>
              <span>›</span>
              <span className="ux0-mono" style={{ fontSize: 11 }}>{incident.id}</span>
            </div>
            <div className="ux0-hdr__main">
              <div style={{ minWidth: 0 }}>
                <h1 className="ux0-hdr__title" data-testid="ux0-incident-title">
                  {incident.title}
                </h1>
                <div className="ux0-hdr__assess">
                  <NxVerdict value={incident.verdict} testid="ux0-hdr-verdict" />
                  <NxConfidence value={Math.round(incident.confidence * 100)} />
                  <span>correlated from {incident.correlation.detections} detections</span>
                </div>
              </div>
              <div className="ux0-hdr__actions">
                <ActionCluster canAny={canAny} />
              </div>
            </div>
            <div className="ux0-facts" data-testid="ux0-fact-strip">
              {incident.facts.map((f) => (
                <Fact key={f.k} k={f.k} v={f.v} warn={f.warn} />
              ))}
            </div>
          </>
        )}
      </div>
      <div className="ux0-tabwrap">
        <NxTabs tabs={tabs} active={active} onChange={onTab} testid="ux0-tabs" />
      </div>
    </>
  );
}

function ActionCluster({ canAny, compact = false }) {
  return ACTIONS.map((a) => {
    const allowed = canAny(a.perms) !== false;
    return (
      <button key={a.key} type="button" disabled={!allowed}
              title={allowed ? undefined
                : `Your effective permissions do not include ${a.perms.join(" or ")}`}
              className={`ux0-btn${a.key === "respond" && allowed ? " ux0-btn--primary" : ""}`}
              data-testid={`ux0-action-${a.key}`}
              data-allowed={allowed ? "true" : "false"}>
        {compact && a.key !== "respond" ? a.label.split(" ")[0] : a.label}
        <ChevronDown size={13} />
      </button>
    );
  });
}
