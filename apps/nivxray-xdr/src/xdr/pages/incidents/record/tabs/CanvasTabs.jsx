/**
 * Canvas-hosted tabs · MITRE · AttackStory · Recommendations.
 *
 * These three tabs reuse the existing dark-themed engine panels
 * without modification.  They live inside the dark analyst-canvas
 * variant of `.rl-tabpanel` so the panels retain the visual language
 * the engine fabric was authored against.  Zero engine changes.
 */
import React from "react";
import AttackChainPanel        from "@/xdr/investigation/AttackChainPanel";
import ProcessTreePanel        from "@/xdr/investigation/ProcessTreePanel";
import XdrRecommendationsPanel from "@/xdr/intel/XdrRecommendationsPanel";
import ScenarioIntelligencePanel from "@/xdr/investigation/ScenarioIntelligencePanel";
import XdrCompletenessPanel    from "@/xdr/investigation/XdrCompletenessPanel";
import { WorkspaceSelectionProvider }
  from "@/xdr/investigation/WorkspaceSelectionContext";


export function MitreTab({ incident }) {
  return (
    <WorkspaceSelectionProvider incident={incident}>
      <div data-testid="xdr-record-mitre" className="xdr-console"
            style={{ background: "transparent", padding: 0, minHeight: 0 }}>
        <AttackChainPanel incident={incident} />
      </div>
    </WorkspaceSelectionProvider>
  );
}

export function AttackStoryTab({ incident }) {
  return (
    <WorkspaceSelectionProvider incident={incident}>
      <div data-testid="xdr-record-attack-story" className="xdr-console"
            style={{ background: "transparent", padding: 0, minHeight: 0 }}>
        <ProcessTreePanel incident={incident} />
        <ScenarioIntelligencePanel incident={incident} />
      </div>
    </WorkspaceSelectionProvider>
  );
}

export function RecommendationsTab({ incident }) {
  return (
    <WorkspaceSelectionProvider incident={incident}>
      <div data-testid="xdr-record-recommendations" className="xdr-console"
            style={{ background: "transparent", padding: 0, minHeight: 0 }}>
        <XdrCompletenessPanel incident={incident} />
        <XdrRecommendationsPanel incident={incident} />
      </div>
    </WorkspaceSelectionProvider>
  );
}
