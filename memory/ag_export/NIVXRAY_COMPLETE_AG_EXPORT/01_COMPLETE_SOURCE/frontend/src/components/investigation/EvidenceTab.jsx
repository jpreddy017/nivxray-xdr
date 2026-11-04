/**
 * Investigation · Evidence tab — Attack Chain + Evidence Graph +
 * Confidence Provenance rules. Every clickable target routes into
 * the shared <EvidenceModal> via `onOpenEvidence`.
 */
import { useEffect, useState } from "react";
import api from "@/lib/api";
import AttackChainView from "@/components/investigation/AttackChainView";
import EvidenceGraphView from "@/components/investigation/EvidenceGraphView";
import {
  fromChainStep, fromProvenanceRuleFire,
} from "@/components/evidenceDescriptors";

export default function EvidenceTab({ chain, graph, caseId, onUnlink, onOpenEvidence }) {
  const [prov, setProv] = useState(null);
  useEffect(() => {
    if (!caseId) return;
    (async () => {
      try {
        const r = await api.get(`/correlations/provenance/${caseId}`);
        setProv(r.data?.confidence_provenance);
      } catch {
        /* provenance is optional — silently absent when case not yet analysed */
      }
    })();
  }, [caseId]);

  return (
    <div data-testid="tab-panel-evidence" style={{ display: "grid", gap: 18 }}>
      <section>
        <SectionTitle>Attack chain</SectionTitle>
        <div style={{ marginTop: 10 }}>
          <AttackChainView chain={chain} onUnlink={onUnlink}
            onOpenEvidence={(step) => onOpenEvidence(fromChainStep(step))} />
        </div>
      </section>

      <section>
        <SectionTitle>Evidence graph</SectionTitle>
        <div style={{ marginTop: 10 }}>
          <EvidenceGraphView graph={graph} />
        </div>
      </section>

      {prov?.rules?.length > 0 && (
        <section data-testid="evidence-provenance-panel">
          <SectionTitle>Confidence provenance · why the verdict</SectionTitle>
          <div style={{ marginTop: 10, display: "grid", gap: 6 }}>
            {prov.rules.map((r) => (
              <button key={r.id}
                      data-testid={`evidence-provenance-rule-${r.id}`}
                      onClick={() => onOpenEvidence(fromProvenanceRuleFire(r, "Case"))}
                      style={{ textAlign: "left", padding: "8px 12px",
                               background: "#0a1526",
                               border: "1px solid #1f2b3f",
                               borderRadius: 8, color: "#e2e8f0",
                               cursor: "pointer",
                               display: "grid",
                               gridTemplateColumns: "1fr 60px 220px",
                               gap: 10, alignItems: "center" }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontFamily: "ui-monospace, monospace",
                                fontSize: 12, color: "#7dd3fc" }}>
                    {r.id}
                  </div>
                  <div style={{ fontSize: 11, color: "#94a3b8",
                                marginTop: 2,
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                                whiteSpace: "nowrap" }}>
                    {r.description}
                  </div>
                </div>
                <div style={{ fontFamily: "ui-monospace, monospace",
                              fontSize: 11, color: "#fbbf24" }}>
                  {(r.contribution ?? 0).toFixed?.(2) ?? r.contribution}
                </div>
                <div style={{ fontSize: 10, color: "#64748b" }}>
                  weight {r.weight ?? "—"} · hits {r.hit_count ?? 0}
                </div>
              </button>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function SectionTitle({ children }) {
  return (
    <div style={{ fontSize: 11, letterSpacing: "0.16em",
                  textTransform: "uppercase", color: "#94a3b8" }}>
      {children}
    </div>
  );
}
