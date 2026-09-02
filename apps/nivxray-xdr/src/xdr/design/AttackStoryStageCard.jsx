/**
 * AttackStoryStageCard · Round 38 / Phase 1 Exemplar.
 * ---------------------------------------------------------------
 * Single visual template used to render each stage of an attack story.
 * Renders stage number, tactic, technique ids, evidence pills,
 * confidence state, affected entities, and trigger for Shared Evidence Inspector.
 */
import React from "react";
import { Clock, FileText, ExternalLink, ChevronRight, ShieldAlert } from "lucide-react";
import EvidenceState from "@/xdr/design/EvidenceState";
import Action from "@/xdr/design/Action";
import Entity from "@/xdr/design/Entity";
import { TacticGlyph, TechniqueGlyph } from "@/xdr/design/glyphs";
import "@/xdr/design/tokens.css";

export default function AttackStoryStageCard({ stage, index, onInspectStage, onInspectRef }) {
  const confidence = stage?.confidence || "CONFIRMED";
  const stateVal   = confidence === "CONFIRMED" ? "observed"
                   : confidence === "SUPPORTED" ? "supported"
                   : "missing";

  const tacticName = (stage?.tactic || "TACTIC").toUpperCase();
  const techIds    = stage?.technique_ids || (stage?.technique_id ? [stage.technique_id] : []);
  const evdIds     = stage?.evidence_ids || (stage?.evidence_id ? [stage.evidence_id] : []);
  const entities   = stage?.entities || [];

  return (
    <div
      className="evops-stage-card"
      data-confidence={confidence}
      data-testid={`xdr-attack-stage-card-${stage?.id || index}`}
    >
      <div className="evops-stage-card__header">
        <div className="evops-stage-card__tactic" data-testid={`xdr-attack-stage-tactic-${index}`}>
          <TacticGlyph size={12} />
          <span>Stage {index + 1} · {tacticName}</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {stage?.timestamp && (
            <span className="evops-mono" style={{ fontSize: 11, color: "var(--nx-faint)", display: "flex", alignItems: "center", gap: 4 }}>
              <Clock size={10} />
              <span>{String(stage.timestamp).slice(11, 19) || String(stage.timestamp)}</span>
            </span>
          )}
          <EvidenceState state={stateVal} testid={`xdr-attack-stage-conf-${index}`} />
        </div>
      </div>

      <div className="evops-stage-card__title" data-testid={`xdr-attack-stage-title-${index}`}>
        {stage?.title || stage?.object_name || `Stage ${index + 1} Execution`}
      </div>

      {stage?.summary && (
        <div className="evops-stage-card__summary" data-testid={`xdr-attack-stage-summary-${index}`}>
          {stage.summary}
        </div>
      )}

      {/* Technique IDs & Evidence Pills */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", marginBottom: 10 }}>
        {techIds.map((tid) => (
          <button
            key={tid}
            className="evops-narration__pill"
            onClick={() => onInspectRef && onInspectRef("technique", tid)}
            data-testid={`xdr-attack-stage-tech-${tid}`}
            title="Inspect ATT&CK technique"
          >
            <TechniqueGlyph size={10} />
            <span>{tid}</span>
          </button>
        ))}

        {evdIds.map((eid) => (
          <button
            key={eid}
            className="evops-narration__pill"
            onClick={() => onInspectRef && onInspectRef("evidence", eid)}
            data-testid={`xdr-attack-stage-evd-${eid}`}
            title="Inspect canonical evidence"
          >
            <FileText size={10} />
            <span>{eid}</span>
          </button>
        ))}
      </div>

      {/* Footer: Entities & Inspect Action */}
      <div className="evops-stage-card__footer">
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          {entities.map((e, idx) => (
            <Entity
              key={idx}
              kind={e.kind || "host"}
              name={e.name || e.value}
              id={e.id}
              testid={`xdr-attack-stage-entity-${idx}`}
            />
          ))}
        </div>

        <Action
          label="Inspect Stage"
          icon={ChevronRight}
          capability="cap-full"
          onRun={() => onInspectStage && onInspectStage(stage)}
          testid={`xdr-attack-stage-inspect-${index}`}
        />
      </div>
    </div>
  );
}
