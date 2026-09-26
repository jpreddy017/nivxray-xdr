/**
 * EvidenceExplorerPage · dedicated investigation drill-down
 * ─────────────────────────────────────────────────────────
 * Frozen 2026-03-01 · Slice 2.2.
 *
 * The workspace is the orchestration surface (URL → AUTO INVESTIGATE
 * → summary).  This page is the deep-dive surface — every extracted
 * artifact, every behavior cluster, the incident, and the evidence
 * matrix live here.  Reads the latest investigation from
 * sessionStorage (populated by the workspace after AUTO INVESTIGATE).
 */
import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ExtractedArtifactsPanel from "@/components/investigation/ExtractedArtifactsPanel";
import AcquisitionPlanPanel from "@/components/investigation/AcquisitionPlanPanel";

const STORAGE_KEY = "nivxray:last_investigation";

export default function EvidenceExplorerPage() {
  const [investigation, setInvestigation] = useState(null);
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (raw) setInvestigation(JSON.parse(raw));
    } catch (e) { /* noop */ }
  }, []);

  if (!investigation) {
    return (
      <div style={{ padding: 40, color: "#c5f5d6",
                     fontFamily: "ui-monospace, monospace",
                     background: "#001a0d", minHeight: "100vh" }}
           data-testid="evidence-explorer-empty">
        <h1 style={{ color: "#7ee6a8", fontSize: 18, letterSpacing: 2 }}>
          EVIDENCE EXPLORER
        </h1>
        <p style={{ marginTop: 16, color: "#96c9aa" }}>
          No investigation to explore yet.  Run an AUTO INVESTIGATE on a URL
          or paste from the Workspace, then click "Open Evidence Explorer →".
        </p>
        <p style={{ marginTop: 20 }}>
          <Link to="/workspace" style={{ color: "#7ee6a8",
                                           textDecoration: "underline" }}>
            ← Back to Workspace
          </Link>
        </p>
      </div>
    );
  }

  const prof = investigation.document_profile || {};
  const inc  = investigation.incident?.summary || {};

  return (
    <div style={{ background: "#001a0d", minHeight: "100vh",
                   fontFamily: "ui-monospace, monospace", color: "#c5f5d6",
                   padding: "20px 0 40px" }}
         data-testid="evidence-explorer-page">
      <header style={{ padding: "0 24px 16px",
                        borderBottom: "1px solid rgba(126, 230, 168, 0.2)",
                        marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "baseline",
                       justifyContent: "space-between", gap: 20 }}>
          <div>
            <div style={{ fontSize: 11, letterSpacing: 2,
                           color: "#7ee6a8", opacity: 0.85 }}>
              ▸ EVIDENCE EXPLORER
            </div>
            <div style={{ fontSize: 20, marginTop: 4, color: "#e6ffe9" }}>
              {inc.title || prof.title || "Investigation"}
            </div>
            <div style={{ fontSize: 12, color: "#96c9aa", marginTop: 4 }}>
              {inc.actor && <><b style={{ color: "#ffe0b3" }}>{inc.actor}</b> · </>}
              {prof.vendor && `${prof.vendor} · `}
              {inc.objective || ""}
            </div>
          </div>
          <Link to="/workspace" style={{ color: "#7ee6a8",
                                          textDecoration: "none",
                                          fontSize: 12, letterSpacing: 1 }}
                data-testid="evidence-explorer-back">
            ← BACK TO WORKSPACE
          </Link>
        </div>
      </header>

      <AcquisitionPlanPanel investigation={investigation} />
      <ExtractedArtifactsPanel investigation={investigation} />
    </div>
  );
}

// Re-export the storage key so the workspace can write to it without
// a duplicated string constant.
export const EVIDENCE_EXPLORER_STORAGE_KEY = STORAGE_KEY;
