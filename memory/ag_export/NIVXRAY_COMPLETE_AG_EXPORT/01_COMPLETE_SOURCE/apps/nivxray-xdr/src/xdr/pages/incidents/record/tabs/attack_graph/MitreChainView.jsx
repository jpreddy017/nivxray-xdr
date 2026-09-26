/**
 * Round 36 · MITRE Chain view.
 *
 * Single-question projection: "What ATT&CK behaviour was evidenced,
 * and how did the attack progress?"
 *
 * Reads `graph.views.mitre_chain` produced by the backend projection.
 * No process trees, no IPs, no capabilities on this canvas.
 */
import React, { useState } from "react";
import { ChevronRight, ChevronDown, ShieldAlert } from "lucide-react";

const STATE_TONE = {
  OBSERVED:     { bg: "#166534", fg: "#dcfce7", dot: "●", label: "OBSERVED" },
  SUPPORTED:    { bg: "#1e40af", fg: "#dbeafe", dot: "◐", label: "SUPPORTED" },
  POSSIBLE:     { bg: "#78350f", fg: "#fef3c7", dot: "○", label: "POSSIBLE" },
  NOT_OBSERVED: { bg: "#1e293b", fg: "#94a3b8", dot: "—", label: "NOT OBSERVED" },
};

function EvidenceLine({ label, items, testId }) {
  if (!items || items.length === 0) return null;
  return (
    <div style={{ display: "flex", gap: 8, marginTop: 6 }}
          data-testid={testId}>
      <span style={{ color: "#94a3b8", minWidth: 100,
                        fontSize: 11, fontWeight: 500,
                        textTransform: "uppercase", letterSpacing: 0.3 }}>
        {label}
      </span>
      <div style={{ flex: 1, display: "flex", flexWrap: "wrap", gap: 6 }}>
        {items.map((it, i) => (
          <span key={i}
                 className="mono"
                 style={{ fontSize: 11, color: "#e2e8f0",
                             background: "#1e293b", padding: "2px 8px",
                             borderRadius: 3, border: "1px solid #334155" }}>
            {it}
          </span>
        ))}
      </div>
    </div>
  );
}

function TechniqueCard({ tech, onSelect, selected }) {
  const [expanded, setExpanded] = useState(true);
  const tone = STATE_TONE[tech.state] || STATE_TONE.NOT_OBSERVED;
  const ev = tech.evidence || {};
  return (
    <div style={{
            border: `1px solid ${selected ? "#fbbf24" : "#334155"}`,
            background: "#0f172a", borderRadius: 4,
            padding: 10, marginBottom: 8,
            cursor: "pointer" }}
          onClick={() => onSelect?.(tech)}
          data-testid={`xdr-mitre-technique-${tech.tid}`}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <button onClick={(e) => { e.stopPropagation();
                                            setExpanded(v => !v); }}
                 style={{ background: "transparent", border: 0,
                             color: "#94a3b8", padding: 0,
                             display: "flex", alignItems: "center" }}
                 data-testid={`xdr-mitre-technique-toggle-${tech.tid}`}>
          {expanded ? <ChevronDown size={14} />
                          : <ChevronRight size={14} />}
        </button>
        <span className="mono" style={{ color: "#c4b5fd",
                                                  fontSize: 13,
                                                  fontWeight: 700 }}>
          {tech.tid}
        </span>
        <span style={{ color: "#e2e8f0", fontSize: 13 }}>
          {tech.name && tech.name !== tech.tid ? tech.name : ""}
        </span>
        <span style={{
                marginLeft: "auto",
                background: tone.bg, color: tone.fg,
                fontSize: 10, padding: "2px 8px",
                borderRadius: 2, fontWeight: 600,
                letterSpacing: 0.5 }}>
          {tone.dot} {tone.label}
        </span>
      </div>
      {expanded && (
        <div style={{ marginTop: 8, paddingLeft: 22, borderLeft: "1px solid #1e293b" }}>
          <EvidenceLine label="Detection"
                                items={ev.detection_rules?.map(d => d.label)}
                                testId={`xdr-mitre-ev-detection-${tech.tid}`} />
          <EvidenceLine label="Correlation"
                                items={ev.correlation_matches?.map(m => m.label)}
                                testId={`xdr-mitre-ev-corr-${tech.tid}`} />
          <EvidenceLine label="Processes"
                                items={ev.processes?.map(p => p.label)}
                                testId={`xdr-mitre-ev-procs-${tech.tid}`} />
          <EvidenceLine label="Commands"
                                items={ev.commands?.map(c => c.full || c.label)}
                                testId={`xdr-mitre-ev-cmds-${tech.tid}`} />
          <EvidenceLine label="Events"
                                items={ev.events?.map(e => e.label)}
                                testId={`xdr-mitre-ev-events-${tech.tid}`} />
          <EvidenceLine label="Findings"
                                items={ev.findings?.map(f => f.label)}
                                testId={`xdr-mitre-ev-findings-${tech.tid}`} />
          {(!ev.detection_rules?.length && !ev.correlation_matches?.length
            && !ev.processes?.length && !ev.commands?.length
            && !ev.events?.length && !ev.findings?.length) && (
            <div style={{ color: "#64748b", fontSize: 11, marginTop: 6 }}>
              No supporting evidence surfaced.
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function MitreChainView({ mitre, onSelectTechnique, selectedTid }) {
  if (!mitre) return null;
  const stages = mitre.stages || [];
  if (stages.length === 0) {
    return (
      <div style={{ padding: 32, textAlign: "center",
                       color: "#94a3b8" }}
             data-testid="xdr-mitre-empty">
        <ShieldAlert size={20} style={{ margin: "0 auto 8px", display: "block",
                                                  color: "#475569" }} />
        <div style={{ fontSize: 13, fontWeight: 600, color: "#cbd5e1" }}>
          NO EVIDENCE-BACKED ATT&amp;CK MAPPING
        </div>
        <div style={{ fontSize: 11, marginTop: 4 }}>
          No stage is currently substantiated by observed or supported
          evidence. NivXRay will not fabricate a MITRE chain.
        </div>
      </div>
    );
  }
  return (
    <div style={{ padding: 12 }} data-testid="xdr-mitre-chain-view">
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                        marginBottom: 12, color: "#94a3b8", fontSize: 11 }}>
        <span data-testid="xdr-mitre-totals">
          {mitre.totals?.stages_shown ?? 0} stage(s) ·{" "}
          {mitre.totals?.techniques_observed ?? 0} observed technique(s) ·{" "}
          {mitre.totals?.techniques_total ?? 0} total
        </span>
      </div>
      {stages.map((stage, i) => {
        const tone = STATE_TONE[stage.state] || STATE_TONE.NOT_OBSERVED;
        return (
          <div key={stage.id} style={{ marginBottom: 20 }}
                data-testid={`xdr-mitre-stage-${stage.name.replace(/\s+/g, "-")}`}>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                              marginBottom: 8 }}>
              <div style={{
                      background: "#4c1d95", color: "#f5f3ff",
                      width: 26, height: 26, borderRadius: 13,
                      display: "flex", alignItems: "center",
                      justifyContent: "center",
                      fontSize: 12, fontWeight: 700 }}>
                {String(i + 1).padStart(2, "0")}
              </div>
              <div>
                <div style={{ fontSize: 14, fontWeight: 700,
                                    color: "#f8fafc", letterSpacing: 0.3,
                                    textTransform: "uppercase" }}>
                  {stage.name}
                </div>
                <div style={{ fontSize: 11, color: "#94a3b8" }}>
                  ATT&amp;CK tactic · {stage.techniques.length} evidenced
                  technique(s)
                </div>
              </div>
              <span style={{
                      marginLeft: "auto",
                      background: tone.bg, color: tone.fg,
                      fontSize: 10, padding: "2px 8px",
                      borderRadius: 2, fontWeight: 600,
                      letterSpacing: 0.5 }}>
                {tone.dot} {tone.label}
              </span>
            </div>
            {/* Vertical connector down to next stage. */}
            <div style={{ paddingLeft: 34 }}>
              {stage.techniques.map(t => (
                <TechniqueCard key={t.id} tech={t}
                                       selected={selectedTid === t.tid}
                                       onSelect={onSelectTechnique} />
              ))}
            </div>
          </div>
        );
      })}
      {mitre.orphan_techniques && mitre.orphan_techniques.length > 0 && (
        <div style={{ marginTop: 16 }}
              data-testid="xdr-mitre-orphans">
          <div style={{ fontSize: 12, fontWeight: 700,
                            color: "#94a3b8", marginBottom: 8,
                            textTransform: "uppercase" }}>
            Unattributed techniques
          </div>
          {mitre.orphan_techniques.map(t => (
            <TechniqueCard key={t.id} tech={t}
                                   selected={selectedTid === t.tid}
                                   onSelect={onSelectTechnique} />
          ))}
        </div>
      )}
    </div>
  );
}
