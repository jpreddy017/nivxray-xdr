/**
 * NxAttackChain · the ONE attack-progression visual.
 *
 * Owner directive §6: give attack progression a first-class treatment where
 * authoritative data exists, and **never draw a decorative graph that the
 * evidence does not support**. So:
 *
 *   · nodes come only from the backend `attack_progression[]` array;
 *   · an empty array renders an explicit, reasoned empty state — not a
 *     placeholder chain and not an invented kill-chain;
 *   · a node offers a pivot only when the record actually carries the
 *     identifier that pivot needs.
 */
import React from "react";
import { ChevronRight } from "lucide-react";
import NxChip from "./NxChip";
import { NxEmpty } from "./NxEmpty";
import "./nx-entity.css";

const STAGE_TONE = {
  initial_access: "high", execution: "critical", persistence: "high",
  privilege_escalation: "critical", defense_evasion: "high",
  credential_access: "critical", discovery: "medium",
  lateral_movement: "critical", collection: "medium",
  command_and_control: "critical", exfiltration: "critical",
  impact: "critical",
};

function toneFor(node) {
  const k = String(node.tactic_id || node.stage || node.tactic || "")
    .toLowerCase().replace(/[\s-]/g, "_");
  return STAGE_TONE[k] || "purple";
}

export default function NxAttackChain({
  nodes, onPivot = null, emptyReason = null, testid = "nx-attack-chain",
}) {
  const list = Array.isArray(nodes) ? nodes : [];
  if (list.length === 0) {
    return (
      <NxEmpty
        title="No attack progression is recorded for this incident"
        hint={emptyReason
          || "The backend returned an empty attack_progression[]. NivXRay "
           + "does not draw a progression that the evidence does not "
           + "support, so nothing is shown rather than a generic chain."}
        data-testid={`${testid}-empty`}
      />
    );
  }
  return (
    <ol className="nx-ac" data-testid={testid}>
      {list.map((n, i) => {
        const label = n.label || n.name || n.technique || n.stage || `Step ${i + 1}`;
        const key = n.id || `${label}-${i}`;
        const pivotable = !!onPivot
          && !!(n.evidence_ref || n.event_id || n.process || n.entity
                || n.technique_id);
        return (
          <li className="nx-ac-node" key={key}
              data-testid={`${testid}-node-${i}`}>
            <div className="nx-ac-rail">
              <span className="nx-ac-dot" />
              {i < list.length - 1 && <span className="nx-ac-line" />}
            </div>
            <div className="nx-ac-body">
              <div className="nx-ac-head">
                <NxChip tone={toneFor(n)} variant="tinted">
                  {(n.tactic || n.stage || "STAGE").toString().toUpperCase()}
                </NxChip>
                <span className="nx-ac-label">{label}</span>
                {n.technique_id && (
                  <NxChip tone="neutral" variant="dashed">
                    {n.technique_id}
                  </NxChip>
                )}
              </div>
              {(n.detail || n.description) && (
                <p className="nx-ac-detail">{n.detail || n.description}</p>
              )}
              <div className="nx-ac-meta">
                {n.at || n.timestamp
                  ? <span>{n.at || n.timestamp}</span>
                  : <span className="nx-ac-absent">
                      Timestamp not recorded
                    </span>}
                {pivotable ? (
                  <button className="nx-ac-pivot"
                          data-testid={`${testid}-pivot-${i}`}
                          onClick={() => onPivot(n)}>
                    Pivot to evidence <ChevronRight size={12} />
                  </button>
                ) : (
                  <span className="nx-ac-absent"
                        title="This node carries no evidence reference, so no pivot is offered">
                    No evidence reference
                  </span>
                )}
              </div>
            </div>
          </li>
        );
      })}
    </ol>
  );
}
