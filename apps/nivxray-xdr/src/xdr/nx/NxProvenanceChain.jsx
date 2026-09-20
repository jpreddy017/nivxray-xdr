/**
 * NxProvenanceChain · how the platform came to believe something.
 *
 * (Distinct from `NxProvenance`, which is the inline single-fact wrapper.)
 *
 * This is NivXRay's differentiator, so it gets a first-class primitive
 * instead of a JSON dump: each stage is an INDEPENDENT fact with its own
 * state, its own citation (`evidence_ref`) and, when it did not happen, its
 * own reason. A stage that never ran says so; it is never skipped over to
 * make the chain look complete, and the chain is never collapsed into a
 * single "verified" badge.
 */
import React from "react";
import { ChevronRight } from "lucide-react";
import NxState from "./NxOpsState";
import { NxToken } from "./NxOps";
import "./nx-ops.css";

/**
 * @param stages [{ stage, state, reason?, evidence_ref?, at?, by? }]
 */
export default function NxProvenanceChain({ stages = [], onCite = null,
                                            compact = false,
                                            testid = "nx-provenance-chain" }) {
  if (!stages.length) {
    return (
      <p className="nx-sec-note" data-testid={`${testid}-empty`}>
        No provenance stage was recorded for this object. That is a gap in
        this platform's record, not evidence that nothing happened.
      </p>
    );
  }
  if (compact) {
    return (
      <span className="nx-prov-rail" data-testid={`${testid}-rail`}>
        {stages.map((s, i) => (
          <React.Fragment key={s.stage}>
            <span className="nx-prov-rail-i" title={s.reason || s.stage}>
              <span className="nx-prov-stage">{s.stage}</span>
              <NxState value={s.state} reason={s.reason} size="sm" />
            </span>
            {i < stages.length - 1 && (
              <ChevronRight size={11} className="nx-prov-arrow" />
            )}
          </React.Fragment>
        ))}
      </span>
    );
  }
  return (
    <ol className="nx-prov" data-testid={testid}>
      {stages.map((s) => (
        <li className="nx-prov-step" key={s.stage}
            data-testid={`${testid}-${String(s.stage).toLowerCase()}`}>
          <div className="nx-prov-head">
            <span className="nx-prov-stage">{s.stage}</span>
            <NxState value={s.state} reason={s.reason} />
          </div>
          {s.reason && <p className="nx-prov-reason">{s.reason}</p>}
          <div className="nx-prov-meta">
            {s.evidence_ref
              ? <NxToken onClick={onCite ? () => onCite(s.evidence_ref) : undefined}
                         title="Open the cited evidence">
                  {s.evidence_ref}
                </NxToken>
              : <span className="nx-absent">no citation recorded</span>}
            {s.at && <span className="nx-absent nx-mono">{s.at}</span>}
            {s.by && <span className="nx-absent">{s.by}</span>}
          </div>
        </li>
      ))}
    </ol>
  );
}
