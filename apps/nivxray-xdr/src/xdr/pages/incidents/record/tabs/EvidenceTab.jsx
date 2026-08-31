/**
 * EvidenceTab · Layer 3 · evidence-first view of what each domain
 * knows about this incident.  Reuses the existing DomainCardsGrid
 * consumer (which already renders per-domain evidence pointers with
 * honest four-state semantics).  Renders it inside a scoped dark
 * canvas so it retains its existing visual language.
 */
import React from "react";
import DomainCardsGrid from "@/xdr/components/DomainCardsGrid";

export default function EvidenceTab({ incident }) {
  // Derive per-domain evidence counts from SSOT pointers so the
  // grid can render actual numbers.  Never fabricated: a missing
  // pointer just leaves the domain at zero, and the grid shows the
  // honest "SEARCHED" state.
  const evidenceCounts = React.useMemo(() => {
    const out = {};
    for (const p of (incident.evidence_pointers || [])) {
      const map = { edr: "endpoints", endpoint: "endpoints",
                     identity: "identity", itdr: "identity",
                     file: "files", files: "files",
                     network: "network", ndr: "network",
                     email: "email", cloud: "cloud" };
      const k = map[p.domain] || p.domain;
      const n = Array.isArray(p.bullets) ? p.bullets.length : 0;
      out[k] = (out[k] || 0) + n;
    }
    return out;
  }, [incident]);

  const pointers = incident.evidence_pointers || [];

  return (
    <div data-testid="xdr-record-evidence">
      <div className="rl-section">
        <div className="rl-section-title">Evidence pointers</div>
        {pointers.length === 0
          ? <div className="rl-empty">
              NO EVIDENCE POINTERS — no domain capability has projected
              evidence onto this case yet.
            </div>
          : <div className="canvas-inner"
                style={{ padding: "0 0 4px", background: "transparent" }}>
              <DomainCardsGrid
                incident={incident}
                evidenceCounts={evidenceCounts}
              />
            </div>}
      </div>
    </div>
  );
}
