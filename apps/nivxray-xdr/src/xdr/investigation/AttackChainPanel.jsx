/**
 * AttackChainPanel — first-class Investigation surface.
 *
 * Reuses the NivXRay Tool intelligence (RULE_TO_TECHNIQUE,
 * TECHNIQUE_INDEX, KILL_CHAIN, and the existing correlation /
 * incident_summary APIs).  This panel is a projection, NOT a
 * competing analytics engine.
 *
 * Semantic contract (owner-locked · non-negotiable):
 *
 *   Evidence
 *      ↓
 *   Observed Technique      (evidence.rule_id → technique)
 *      ↓
 *   ATT&CK Technique
 *      ↓
 *   ATT&CK Tactic           (KILL_CHAIN order)
 *      ↓
 *   Ordered Attack Chain    ← this panel
 *      ↓
 *   Correlated Evidence Bundle
 *      ↓
 *   IKG → ICE → Verdict     (verdict owned by Verdict Engine only)
 *
 * The chain distinguishes FOUR relationship kinds so the UI is never
 * a decorative attack story:
 *
 *   OBSERVED     evidence directly supports the technique
 *   SEQUENCED    temporal ordering established from timestamps
 *   CORRELATED   technique participates in a correlation match
 *   INFERRED     analytical relationship, not directly observed
 *
 * Clicking a technique synchronises Evidence Trajectory, Process
 * Tree, IOCs and evidence details via the WorkspaceSelection bus.
 * NEVER alters the verdict.  Missing techniques / stages are never
 * fabricated — the chain has honest gaps.
 */
import React, { useEffect, useMemo, useState } from "react";
import { GitBranch, ChevronRight, Info, Clock, Link2 } from "lucide-react";

import { KILL_CHAIN, RULE_TO_TECHNIQUE, TECHNIQUE_INDEX }
    from "@/xdr/mitre/mitreTactics";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";
import api from "@/lib/api";


const REL_COLOR = {
  OBSERVED:   "var(--mint)",
  SEQUENCED:  "var(--cyan)",
  CORRELATED: "#a78bfa",
  INFERRED:   "var(--faint)",
};

const REL_TIP = {
  OBSERVED:
      "Evidence directly supports this technique (rule → technique mapping "
      + "backed by RULE_TO_TECHNIQUE table).",
  SEQUENCED:
      "Temporal ordering established from evidence timestamps.  Sequence "
      + "does not imply causality.",
  CORRELATED:
      "This technique participates in a correlation match.  See Correlation "
      + "for the matched rule + evidence chain.",
  INFERRED:
      "Analytical relationship — not directly observed.  Requires additional "
      + "evidence before the chain is complete.",
};


export default function AttackChainPanel({ incident }) {
  const { selection, setSelection } = useSelection();
  const [correlations, setCorrelations] = useState([]);

  // Best-effort correlation enrichment — never blocks render.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!incident?.id) return;
      try {
        const r = await api.get("/xdr/correlation/matches",
                                    { params: { incident_id: incident.id }});
        if (!cancelled) setCorrelations(r?.data?.data?.matches || []);
      } catch { if (!cancelled) setCorrelations([]); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const chain = useMemo(
    () => buildAttackChain(incident, correlations),
    [incident, correlations]);

  const selectedTech = selection?.kind === "technique"
                                            ? selection?.ref?.technique_id : null;

  if (chain.stages.length === 0) {
    return (
      <section data-testid="xdr-attack-chain-panel"
                       style={{ marginTop: 14 }}>
        <div style={header}>
          <GitBranch size={12} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                    letterSpacing: ".3px" }}>ATT&CK CHAIN</b>
        </div>
        <div style={emptyBox} data-testid="xdr-attack-chain-empty">
          <Info size={12} style={{ marginRight: 6 }} />
          No ATT&CK-mapped evidence in this investigation.  The chain is
          derived from `verdict_stage2.evidence[]` mapped through the
          authoritative RULE_TO_TECHNIQUE table — never from the verdict.
        </div>
      </section>
    );
  }

  return (
    <section data-testid="xdr-attack-chain-panel"
                   style={{ marginTop: 14 }}>
      <div style={header}>
        <GitBranch size={12} style={{ color: "var(--cyan)" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                letterSpacing: ".3px" }}>ATT&CK CHAIN</b>
        <span style={{ padding: "1px 6px", fontSize: 9.5,
                                fontFamily: "var(--mono)", fontWeight: 700,
                                background: "var(--panel2)",
                                border: "1px solid var(--border)",
                                borderRadius: 2, color: "var(--faint)" }}>
          {chain.techniques.length} technique{chain.techniques.length === 1 ? "" : "s"} · {chain.stages.length} tactic{chain.stages.length === 1 ? "" : "s"}
        </span>
        <span style={{ flex: 1 }} />
        <RelLegend />
      </div>

      <div style={chainBox}>
        {chain.stages.map((stage, si) => (
          <div key={stage.tactic}
                     style={{ display: "flex", alignItems: "stretch" }}>
            <div style={tacticCell}
                       data-testid={`xdr-chain-tactic-${stage.tactic}`}>
              <div style={{ fontSize: 9, color: "var(--faint)",
                                        fontFamily: "var(--mono)", fontWeight: 700,
                                        textTransform: "uppercase",
                                        letterSpacing: ".4px" }}>
                {stage.label}
              </div>
              <div style={{ fontSize: 9.5, color: "var(--text-dim)",
                                        fontFamily: "var(--mono)" }}>
                {stage.techniques.length} tech
              </div>
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6,
                                        flex: 1, padding: "6px 8px",
                                        alignItems: "flex-start" }}>
              {stage.techniques.map((t) => (
                <TechniqueChip key={t.technique_id}
                                            t={t}
                                            selected={selectedTech === t.technique_id}
                                            onClick={() => setSelection({
                                              kind: "technique",
                                              ref:  { technique_id: t.technique_id },
                                              source: "attack-chain",
                                            })} />
              ))}
            </div>
            {si < chain.stages.length - 1 && (
              <div style={arrowCell} aria-hidden>
                <ChevronRight size={12} style={{ color: "var(--faint)" }} />
              </div>
            )}
          </div>
        ))}
      </div>

      {chain.gaps.length > 0 && (
        <div style={{ marginTop: 6, padding: "6px 8px", fontSize: 10.5,
                                fontFamily: "var(--mono)",
                                color: "var(--faint)",
                                border: "1px dashed var(--border)", borderRadius: 3 }}
                     data-testid="xdr-chain-gaps">
          Honest gaps — no evidence yet for: {chain.gaps.join(" · ")}.
          The chain is <b>not</b> completed with inferred stages.
        </div>
      )}
    </section>
  );
}


function TechniqueChip({ t, selected, onClick }) {
  const first = t.first_seen ? new Date(t.first_seen).toISOString().slice(11, 19) + "Z" : null;
  return (
    <button type="button"
                  data-testid={`xdr-chain-tech-${t.technique_id}`}
                  onClick={onClick}
                  title={`${t.technique_id} · ${t.name || ""}\n${t.rels.map((r) => `[${r}] ${REL_TIP[r]}`).join("\n")}`}
                  style={{
                    padding: "4px 8px", background: selected ? "rgba(56,189,248,0.18)"
                                                                                                : "var(--panel2)",
                    border: `1px solid ${selected ? "var(--cyan)" : "var(--border)"}`,
                    borderRadius: 3, cursor: "pointer",
                    fontFamily: "var(--mono)", textAlign: "left",
                    minWidth: 160, maxWidth: 260,
                  }}>
      <div style={{ fontSize: 10.5, color: "#f472b6", fontWeight: 700 }}>
        {t.technique_id}
      </div>
      <div style={{ fontSize: 9.5, color: "var(--text)",
                              whiteSpace: "nowrap", overflow: "hidden",
                              textOverflow: "ellipsis" }}>
        {t.name || "—"}
      </div>
      <div style={{ display: "flex", gap: 3, marginTop: 3, flexWrap: "wrap",
                              alignItems: "center" }}>
        {t.rels.map((r) => (
          <span key={r}
                        data-testid={`xdr-chain-rel-${t.technique_id}-${r}`}
                        style={{ padding: "0 4px", fontSize: 8.5,
                                        fontWeight: 700, border: `1px solid ${REL_COLOR[r]}`,
                                        color: REL_COLOR[r], borderRadius: 2 }}>
            {r}
          </span>
        ))}
        <span style={{ fontSize: 9, color: "var(--faint)" }}>
          · {t.evidence_count} evidence
        </span>
        {first && (
          <span style={{ fontSize: 9, color: "var(--faint)",
                                    display: "inline-flex", alignItems: "center", gap: 2 }}>
            <Clock size={8} /> {first}
          </span>
        )}
      </div>
    </button>
  );
}


function RelLegend() {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center",
                            fontSize: 9, fontFamily: "var(--mono)",
                            color: "var(--faint)" }}
                data-testid="xdr-chain-legend">
      {Object.keys(REL_COLOR).map((k) => (
        <span key={k} title={REL_TIP[k]}
                      style={{ padding: "0 4px",
                                      border: `1px solid ${REL_COLOR[k]}`,
                                      color: REL_COLOR[k], borderRadius: 2,
                                      fontWeight: 700 }}>
          {k}
        </span>
      ))}
    </div>
  );
}


// ── Deterministic chain builder ───────────────────────────────────
function buildAttackChain(incident, correlations) {
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);
  if (!evs.length) return { stages: [], techniques: [], gaps: KILL_CHAIN.map((t) => t.label) };

  // 1 · evidence → observed technique + first_seen
  const byTech = new Map();
  const stampAt = (t, ts) => {
    const cur = byTech.get(t);
    if (!cur.first_seen || (ts && ts < cur.first_seen)) cur.first_seen = ts;
    if (!cur.last_seen  || (ts && ts > cur.last_seen))  cur.last_seen  = ts;
  };
  const seedTech = (tech, ev) => {
    if (!byTech.has(tech)) {
      const meta = TECHNIQUE_INDEX[tech] || {};
      byTech.set(tech, {
        technique_id: tech,
        name: meta.name || null,
        tactic: meta.tactic || _fallbackTactic(tech),
        evidence_count: 0,
        rels: new Set(),
        rule_ids: new Set(),
        first_seen: null,
        last_seen: null,
      });
    }
    const cur = byTech.get(tech);
    cur.evidence_count += 1;
    cur.rels.add("OBSERVED");
    if (ev.rule_id) cur.rule_ids.add(ev.rule_id);
    stampAt(tech, ev.timestamp || ev.first_seen || null);
  };

  for (const ev of evs) {
    const tech = ev.technique_id
              || (ev.rule_id && RULE_TO_TECHNIQUE[String(ev.rule_id).toUpperCase()]);
    if (tech) seedTech(tech, ev);
  }

  // 2 · SEQUENCED relationship — if there are ≥2 distinct timestamps we
  //     mark techniques after the first as SEQUENCED (temporal, not
  //     causal).
  const sorted = Array.from(byTech.values())
      .filter((t) => t.first_seen)
      .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""));
  if (sorted.length >= 2) {
    for (let i = 1; i < sorted.length; i++) {
      sorted[i].rels.add("SEQUENCED");
    }
  }

  // 3 · CORRELATED — for every correlation match whose attack_techniques
  //     list contains this technique, mark CORRELATED.
  for (const c of correlations || []) {
    const attks = c.attack_techniques || c.techniques || [];
    for (const at of attks) {
      const cur = byTech.get(at);
      if (cur) cur.rels.add("CORRELATED");
    }
  }

  // 4 · INFERRED (currently disabled — enable when NivXRay Tool's
  //     Behavior Extractor infers a stage we did not directly observe.
  //     We NEVER auto-mark INFERRED from the client; only real
  //     analytical support flips this rel on.).

  // 5 · Group by tactic in KILL_CHAIN order — honest gaps preserved.
  const stages = [];
  const gaps   = [];
  for (const kc of KILL_CHAIN) {
    const bucket = Array.from(byTech.values())
        .filter((t) => t.tactic === kc.key || t.tactic === kc.label);
    if (bucket.length) {
      stages.push({
        tactic: kc.key,
        label: kc.label,
        techniques: bucket
            .sort((a, b) => (a.first_seen || "").localeCompare(b.first_seen || ""))
            .map((t) => ({ ...t, rels: Array.from(t.rels) })),
      });
    } else {
      gaps.push(kc.label);
    }
  }
  return {
    stages,
    techniques: Array.from(byTech.keys()),
    gaps,
  };
}


function _fallbackTactic(technique_id) {
  // Techniques without an authoritative tactic mapping — surface under
  // "Unknown" so we never guess.
  return "unknown";
}


// ── styles ────────────────────────────────────────────────────────
const header = {
  display: "flex", alignItems: "center", gap: 8, marginBottom: 8,
  padding: "0 4px",
};
const emptyBox = {
  padding: "10px 12px", fontSize: 11, fontFamily: "var(--mono)",
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 3, display: "flex", alignItems: "center",
};
const chainBox = {
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel)", overflow: "auto",
};
const tacticCell = {
  minWidth: 120, padding: "8px 10px",
  borderRight: "1px solid var(--border)",
  background: "var(--panel2)", display: "flex",
  flexDirection: "column", justifyContent: "center", gap: 2,
};
const arrowCell = {
  width: 20, display: "flex", alignItems: "center",
  justifyContent: "center", borderLeft: "1px solid var(--border)",
};
