/**
 * ScenarioIntelligencePanel — SOC-100 investigation guidance layer.
 *
 * Locked invariant (owner directive · 2026-02-30):
 *
 *   Scenario knowledge  ≠  Incident evidence  ≠  Detection  ≠  Verdict
 *
 * The panel consumes /api/xdr/investigation/{id}/scenario-match and
 * surfaces:
 *   · matched scenarios (name + category + score)
 *   · recommended pivots for each match
 *   · expected-evidence gap (what the scenario expects but the
 *     incident does not yet have)
 *   · next investigation step + detection-improvement hint
 *
 * The panel NEVER injects techniques, observations or verdicts into
 * the incident.  It only tells the analyst what to LOOK for.
 */
import React, { useEffect, useState } from "react";
import { BookOpen, ArrowRight, AlertCircle, Compass } from "lucide-react";
import api from "@/lib/api";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";


// Deterministic pivot → investigation-surface mapping.  This is
// investigation guidance projected into the existing WorkspaceSelection
// bus — never a second navigation mechanism.  Matching is a lowercase
// substring of the pivot text against a small vocabulary of surface
// facets extracted from the SOC-100 PDF itself.  If no facet matches,
// the pivot is emitted as `kind:"pivot"` for surfaces that want a
// generic "highlight-and-filter" hint (rather than fabricating one).
const PIVOT_TO_SURFACE = [
  { pattern: /process|parent|child|command line|ancestry|process tree|integrity/i,
      surface: "process", panel: "process-tree" },
  { pattern: /network|outbound|beacon|proxy|dns|url|domain|c2/i,
      surface: "network", panel: "network" },
  { pattern: /ioc|indicator|hash|sha256|ti|threat intel|osint/i,
      surface: "ioc", panel: "iocs" },
  { pattern: /timeline|temporal|window|sequence|ordering|first[\-_ ]seen|last[\-_ ]seen/i,
      surface: "timeline", panel: "trajectory" },
  { pattern: /endpoint|host|hostname|device|edr|antivirus/i,
      surface: "endpoint", panel: "endpoint" },
  { pattern: /identity|user|session|mfa|sign[\-_ ]in|token/i,
      surface: "identity", panel: "identity" },
  { pattern: /att&?ck|technique|tactic|mitre/i,
      surface: "technique", panel: "attack-chain" },
];


function resolvePivotSurface(pivotText) {
  const t = String(pivotText || "");
  for (const rule of PIVOT_TO_SURFACE) {
    if (rule.pattern.test(t)) return rule;
  }
  return { surface: "generic", panel: null };
}


export default function ScenarioIntelligencePanel({ incident }) {
  const { setSelection } = useSelection();
  const [data, setData] = useState(null);
  const [err,  setErr]  = useState(null);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!incident?.id) return;
      try {
        const r = await api.post(`/xdr/investigation/${incident.id}/scenario-match`);
        if (!cancelled) setData(r?.data || null);
      } catch (e) {
        if (!cancelled) setErr(String(e?.response?.data?.detail || e));
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const matches = data?.matches || [];

  return (
    <section data-testid="xdr-scenario-panel" style={{ marginTop: 14 }}>
      <div style={header}>
        <BookOpen size={13} style={{ color: "#facc15" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                letterSpacing: 0.3 }}>SCENARIO INTELLIGENCE</b>
        <span style={metaChip}>
          {matches.length} match{matches.length === 1 ? "" : "es"} · SOC-100
        </span>
        <span style={{ fontSize: 9.5, color: "var(--faint)",
                                    fontFamily: "var(--mono)" }}>
          guidance only · never evidence · never verdict
        </span>
        <span style={{ flex: 1 }} />
        <button type="button"
                      data-testid="xdr-scenario-toggle"
                      onClick={() => setCollapsed((c) => !c)}
                      style={ctrlBtn}>
          {collapsed ? "OPEN" : "COLLAPSE"}
        </button>
      </div>

      {collapsed ? null : err ? (
        <div style={emptyBox} data-testid="xdr-scenario-error">
          <AlertCircle size={11} style={{ marginRight: 4 }} />
          Scenario intelligence unavailable · {err}
        </div>
      ) : matches.length === 0 ? (
        <div style={emptyBox} data-testid="xdr-scenario-empty">
          <Compass size={11} style={{ marginRight: 4 }} />
          No SOC-100 scenario currently matches this incident's evidence.
          Add process / IOC / rule evidence to receive investigation
          guidance.  The corpus is investigation guidance only — it never
          concludes anything happened.
        </div>
      ) : (
        <div style={list}>
          {matches.map((m) => (
            <div key={m.scenario_id}
                        data-testid={`xdr-scenario-${m.scenario_id}`}
                        style={card}>
              <div style={{ display: "flex", alignItems: "center", gap: 6,
                                        flexWrap: "wrap" }}>
                <span style={{ ...pill, borderColor: "#facc15",
                                              color: "#facc15" }}>
                  {m.scenario_id}
                </span>
                <b style={{ fontFamily: "var(--mono)", fontSize: 11.5 }}>
                  {m.name}
                </b>
                <span style={{ ...pill, borderColor: "var(--border)",
                                              color: "var(--faint)" }}>
                  {m.category}
                </span>
                <span style={{ fontSize: 9.5, color: "var(--faint)",
                                              fontFamily: "var(--mono)" }}>
                  match score · {m.match_score}
                </span>
                <span style={{ flex: 1 }} />
                <span style={{ fontSize: 9.5, color: "var(--faint)",
                                              fontFamily: "var(--mono)" }}>
                  PDF p.{m.source_page ?? "—"}
                </span>
              </div>
              <div style={{ marginTop: 5, fontSize: 10.5,
                                        color: "var(--text-dim)",
                                        fontFamily: "var(--mono)" }}>
                {m.threat}
              </div>

              <div style={{ marginTop: 8, display: "grid",
                                        gridTemplateColumns: "1fr 1fr", gap: 8 }}>
                <div>
                  <div style={sectTitle}>Recommended pivots</div>
                  <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                    {(m.recommended_pivots || []).slice(0, 8).map((p) => {
                      const { surface, panel } = resolvePivotSurface(p);
                      const isKnown = panel !== null;
                      return (
                        <button key={p}
                                            type="button"
                                            data-testid={`xdr-scenario-pivot-${m.scenario_id}-${p}`}
                                            onClick={() => setSelection({
                                              kind: "pivot",
                                              ref: { pivot: p, surface, panel,
                                                            scenario_id: m.scenario_id },
                                              source: "scenario-intelligence",
                                            })}
                                            title={isKnown
                                                        ? `Pivot to ${panel} · ${p}`
                                                        : `${p} — no mapped surface`}
                                            style={{ ...chip,
                                                            cursor: "pointer",
                                                            borderColor: isKnown ? "var(--cyan)"
                                                                                                        : "var(--border)",
                                                            color:       isKnown ? "var(--cyan)"
                                                                                                        : "var(--text-dim)" }}>
                          {p}
                        </button>
                      );
                    })}
                    {m.recommended_pivots?.length > 8 && (
                      <span style={{ ...chip, color: "var(--faint)" }}>
                        +{m.recommended_pivots.length - 8}
                      </span>
                    )}
                  </div>
                </div>
                <div>
                  <div style={sectTitle}>Missing evidence for this scenario</div>
                  {m.expected_evidence_gap?.length
                    ? (
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                        {m.expected_evidence_gap.slice(0, 6).map((e, i) => (
                          <span key={i}
                                            style={{ ...chip, borderColor: "#f87171",
                                                            color: "#f87171" }}
                                            data-testid={`xdr-scenario-gap-${m.scenario_id}-${i}`}>
                            {e}
                          </span>
                        ))}
                      </div>
                    )
                    : <span style={{ fontSize: 10, color: "var(--faint)",
                                                    fontStyle: "italic" }}>
                          no gaps observed
                      </span>}
                </div>
              </div>

              {m.missing_techniques?.length ? (
                <div style={{ marginTop: 6, fontSize: 10, fontFamily: "var(--mono)" }}>
                  <span style={sectTitle}>Missing ATT&CK: </span>
                  {m.missing_techniques.map((t) => (
                    <span key={t} style={{ ...chip, color: "#f472b6",
                                                                borderColor: "#f472b6",
                                                                marginRight: 3 }}
                                data-testid={`xdr-scenario-tech-${m.scenario_id}-${t}`}>
                      {t}
                    </span>
                  ))}
                </div>
              ) : null}

              <div style={{ marginTop: 8, padding: 6,
                                        background: "rgba(56,189,248,0.06)",
                                        border: "1px solid rgba(56,189,248,0.35)",
                                        borderRadius: 3, fontSize: 10.5,
                                        fontFamily: "var(--mono)" }}
                          data-testid={`xdr-scenario-next-${m.scenario_id}`}>
                <ArrowRight size={10} style={{ color: "var(--cyan)",
                                                                          marginRight: 4 }} />
                <b>Next step:</b> {m.next_step}
              </div>
              {m.detection_improvement && (
                <div style={{ marginTop: 4, fontSize: 10,
                                          color: "var(--faint)",
                                          fontFamily: "var(--mono)" }}>
                  Detection improvement · {m.detection_improvement}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}


// ── styles ────────────────────────────────────────────────────────
const header = {
  display: "flex", alignItems: "center", gap: 8, marginBottom: 8,
  padding: "0 4px", flexWrap: "wrap",
};
const metaChip = {
  padding: "1px 6px", fontSize: 9.5, fontFamily: "var(--mono)",
  fontWeight: 700, background: "var(--panel2)",
  border: "1px solid var(--border)", borderRadius: 2,
  color: "var(--faint)",
};
const list  = { display: "flex", flexDirection: "column", gap: 8 };
const card  = {
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel)", padding: 8,
};
const pill  = {
  padding: "1px 6px", fontSize: 9.5, fontFamily: "var(--mono)",
  fontWeight: 700, border: "1px solid", borderRadius: 2,
};
const chip  = {
  padding: "1px 6px", fontSize: 9.5, fontFamily: "var(--mono)",
  border: "1px solid var(--border)", color: "var(--text-dim)",
  borderRadius: 2,
};
const sectTitle = {
  fontSize: 9, color: "var(--faint)", fontFamily: "var(--mono)",
  fontWeight: 700, letterSpacing: 0.4, textTransform: "uppercase",
  marginBottom: 3,
};
const ctrlBtn = {
  padding: "3px 8px", fontSize: 10, fontWeight: 700,
  background: "var(--panel2)", border: "1px solid var(--border)",
  color: "var(--text-dim)", borderRadius: 2, cursor: "pointer",
  fontFamily: "var(--mono)",
};
const emptyBox = {
  padding: "10px 12px", fontSize: 11, fontFamily: "var(--mono)",
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 3, display: "flex", alignItems: "center",
};
