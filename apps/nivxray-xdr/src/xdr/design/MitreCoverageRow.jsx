/**
 * MitreCoverageRow · Round 38 / Phase 1 Exemplar.
 * ---------------------------------------------------------------
 * Visual language for MITRE ATT&CK v16.1 heatmap & coverage rows.
 * Handles parent/sub-technique hierarchy:
 *   Parent: T1059 Command and Scripting Interpreter
 *   Sub:    T1059.001 PowerShell
 * States: OBSERVED / SUPPORTED / HYPOTHESIZED / SUPPRESSED / NO_EVIDENCE.
 */
import React from "react";
import { ExternalLink, ChevronRight, Layers, FileText } from "lucide-react";
import EvidenceState from "@/xdr/design/EvidenceState";
import Action from "@/xdr/design/Action";
import { TechniqueGlyph, TacticGlyph } from "@/xdr/design/glyphs";
import { attackHrefFor } from "@/xdr/mitre/attackLink";
import "@/xdr/design/tokens.css";

export default function MitreCoverageRow({ technique, subTechniques = [], onInspect }) {
  const attackHref = attackHrefFor(technique);
  const isParent = subTechniques.length > 0;
  const statusState = technique.confidence === "CONFIRMED" ? "observed"
                    : technique.confidence === "SUPPORTED" ? "supported"
                    : technique.confidence === "HYPOTHESIZED" ? "missing"
                    : "unavailable";

  return (
    <div
      className="evops-tech-row"
      data-testid={`mitre-coverage-row-${technique.id}`}
      style={{ borderLeft: isParent ? "2px solid var(--evops-prov-mapping)" : "none" }}
    >
      {/* Technique ID & Parent/Sub indicator */}
      <div className="evops-tech-row__id" style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <TechniqueGlyph size={13} />
        <span style={{ fontWeight: 700 }}>{technique.id}</span>
      </div>

      {/* Technique Name & Rationale */}
      <div>
        <div className="evops-tech-row__name" style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span>{technique.object_name || technique.name || technique.id}</span>
          {isParent && (
            <span className="evops-mono" style={{ fontSize: 10, background: "var(--nx-surf-inset)", padding: "1px 5px", borderRadius: 2, color: "var(--nx-faint)" }}>
              PARENT ({subTechniques.length} SUB)
            </span>
          )}
        </div>
        {technique.why_mapped && (
          <div className="evops-tech-row__why">{technique.why_mapped}</div>
        )}

        {/* Render sub-techniques inline if present */}
        {isParent && (
          <div style={{ marginTop: 8, paddingLeft: 12, borderLeft: "1px dashed var(--nx-divider)", display: "flex", flexDirection: "column", gap: 4 }}>
            {subTechniques.map((sub) => (
              <div key={sub.id} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11 }}>
                <ChevronRight size={10} style={{ color: "var(--nx-muted)" }} />
                <span className="evops-mono" style={{ fontWeight: 600, color: "var(--nx-text-dim)" }}>{sub.id}</span>
                <span style={{ color: "var(--nx-text)" }}>{sub.object_name || sub.name}</span>
                <EvidenceState state={sub.confidence === "CONFIRMED" ? "observed" : "supported"} testid={`mitre-sub-state-${sub.id}`} />
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Tactic */}
      <div className="evops-tech-row__tactic" style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <TacticGlyph size={12} />
        <span>{(technique.tactic || "TACTIC").toUpperCase()}</span>
      </div>

      {/* Rollup Counts */}
      <div className="evops-tech-row__rollup">
        <span>{technique.evidence_count || (technique.evidence_ids || []).length || 1} evidence refs</span>
        <span style={{ color: "var(--nx-faint)" }}>{technique.entity_count || 1} blast-radius entity</span>
      </div>

      {/* State & Inspector Trigger */}
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <EvidenceState state={statusState} testid={`mitre-row-state-${technique.id}`} />
        <Action
          label="Inspect"
          icon={FileText}
          capability="cap-full"
          onRun={() => onInspect && onInspect("technique", technique.id)}
          testid={`mitre-row-inspect-${technique.id}`}
        />
        {attackHref && (
          <Action
            label="ATT&CK"
            icon={ExternalLink}
            capability="cap-full"
            onRun={() => window.open(attackHref, "_blank", "noopener,noreferrer")}
            testid={`mitre-row-ext-${technique.id}`}
          />
        )}
      </div>
    </div>
  );
}
