/**
 * ThreatAssessmentCard · Round 34 · Executive tab intelligence surface.
 *
 * Consumes `GET /api/incidents/{id}/threat-model` (Round 34 backend).
 * Renders the analyst-facing Threat Assessment:
 *   1. Threat Assessment card (overall band + score + progression)
 *   2. Five-dimension breakdown bars
 *   3. 14-stage Attack Path with the 4-state grammar
 *   4. Why-It-Matters (supporting / reducing / unknown)
 *   5. Machine-generated Executive Investigation Summary
 *
 * Every non-NOT_OBSERVED stage is clickable → reveals the evidence /
 * findings / techniques that anchor it.  Nothing is fabricated.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";


const BAND_STYLE = {
  VERY_HIGH: { key: "vhigh",    label: "VERY HIGH" },
  HIGH:      { key: "high",     label: "HIGH"      },
  MODERATE:  { key: "moderate", label: "MODERATE"  },
  LOW:       { key: "low",      label: "LOW"       },
};

const STATE_MARK = {
  OBSERVED:     "●",
  SUPPORTED:    "◐",
  POSSIBLE:     "○",
  NOT_OBSERVED: "—",
};

const DIM_META = [
  ["detection_confidence",   "Detection",    "detection engine + verdict signal"],
  ["threat_likelihood",      "Threat",       "observed + supported stages · high-confidence findings"],
  ["evidence_confidence",    "Evidence",     "observed vs total facts + finding state distribution"],
  ["attack_path_confidence", "Attack Path",  "14-stage coverage from Attack Story"],
  ["impact_confidence",      "Impact",       "independent axis — does NOT inflate likelihood"],
];


function Bar({ value, tone }) {
  return (
    <div className="rl-bar" style={{ position: "relative", height: 8,
                                                width: "100%",
                                                background: "rgba(0,0,0,0.05)",
                                                borderRadius: 4, overflow: "hidden" }}>
      <div style={{ position: "absolute", left: 0, top: 0, bottom: 0,
                       width: `${Math.max(0, Math.min(100, value))}%`,
                       background: tone === "impact" ? "var(--rl-amber, #d97706)"
                                        : "var(--rl-purple, #6b46c1)" }} />
    </div>
  );
}


export default function ThreatAssessmentCard({ incidentId }) {
  const [tm, setTm] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [expanded, setExpanded] = useState(null); // stage index

  useEffect(() => {
    if (!incidentId) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const { data } = await api.get(`/incidents/${incidentId}/threat-model`);
        if (!cancelled) setTm(data);
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e));
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incidentId]);

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-tm-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      COMPOSING THREAT ASSESSMENT…
    </div>
  );
  if (error && !tm) return (
    <div className="rl-error" data-testid="xdr-record-tm-error">{String(error)}</div>
  );
  if (!tm) return null;

  const assessment = tm.threat_assessment || {};
  const bandStyle = BAND_STYLE[assessment.overall_band] || BAND_STYLE.LOW;
  const dims = assessment.dimensions || {};
  const attackPath = tm.attack_path || [];
  const why = tm.why_it_matters || {};
  const exec_ = tm.executive_summary || {};
  const impact = tm.impact || {};

  return (
    <div data-testid="xdr-record-threat-assessment" style={{ marginBottom: 20 }}>
      {/* 1. Threat Assessment card */}
      <div className={`rl-ai-status ${bandStyle.key}`}
            data-testid="xdr-record-tm-header"
            style={{ display: "grid",
                       gridTemplateColumns: "auto 1fr auto", gap: 16,
                       alignItems: "center" }}>
        <div className="badge" data-testid="xdr-record-tm-band">
          <span style={{ fontSize: 13, fontWeight: 600 }}>
            THREAT · {bandStyle.label}
          </span>
        </div>
        <div className="txt">
          <h5 style={{ margin: 0 }}>
            {assessment.progression_summary || "No attack progression yet"}
          </h5>
          <p style={{ margin: "4px 0 0 0", opacity: 0.75 }}>
            {exec_.text || "Composing…"}
          </p>
        </div>
        <div style={{ textAlign: "right", fontVariantNumeric: "tabular-nums" }}>
          <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1 }}
                data-testid="xdr-record-tm-score">
            {assessment.overall_score ?? "—"}
          </div>
          <div style={{ fontSize: 11, opacity: 0.6, marginTop: 4 }}>
            / 100 · risk {assessment.risk_band}
          </div>
        </div>
      </div>

      {/* 2. Five-dimension breakdown */}
      <div className="rl-section" style={{ marginTop: 12 }}>
        <div className="rl-section-title">Dimension breakdown</div>
        <table className="rl-table" data-testid="xdr-record-tm-dimensions">
          <tbody>
            {DIM_META.map(([key, label, hint]) => (
              <tr key={key} data-testid={`xdr-record-tm-dim-${key}`}>
                <td style={{ width: 140 }}>
                  <div style={{ fontWeight: 500 }}>{label}</div>
                  <div style={{ opacity: 0.55, fontSize: 11 }}>{hint}</div>
                </td>
                <td>
                  <Bar value={dims[key] ?? 0}
                         tone={key === "impact_confidence" ? "impact" : "threat"} />
                </td>
                <td className="mono" style={{ width: 60, textAlign: "right",
                                                       fontVariantNumeric: "tabular-nums" }}>
                  {dims[key] ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* 3. 14-stage Attack Path */}
      <div className="rl-section" style={{ marginTop: 12 }}>
        <div className="rl-section-title">Attack Path · 14-stage cycle</div>
        <table className="rl-table" data-testid="xdr-record-tm-attack-path">
          <tbody>
            {attackPath.map((s, idx) => {
              const canClick = s.state !== "NOT_OBSERVED";
              const open = expanded === idx;
              return (
                <React.Fragment key={s.stage}>
                  <tr data-testid={`xdr-record-tm-stage-${idx + 1}`}
                       onClick={() => canClick && setExpanded(open ? null : idx)}
                       style={{ cursor: canClick ? "pointer" : "default",
                                  opacity: canClick ? 1 : 0.55 }}>
                    <td className="mono" style={{ width: 28, fontSize: 16 }}>
                      {STATE_MARK[s.state]}
                    </td>
                    <td style={{ fontWeight: canClick ? 500 : 400 }}>{s.stage}</td>
                    <td className="mono" style={{ width: 120 }}>{s.state}</td>
                    <td className="mono" style={{ width: 240, fontSize: 12 }}>
                      {(s.techniques || []).join(", ") || "—"}
                    </td>
                    <td className="mono" style={{ width: 90 }}>
                      {(s.finding_ids || []).length} finding
                    </td>
                    <td className="mono" style={{ width: 80 }}>
                      {(s.evidence_refs || []).length} evid
                    </td>
                  </tr>
                  {open && (
                    <tr data-testid={`xdr-record-tm-stage-detail-${idx + 1}`}>
                      <td colSpan={6} style={{ background: "rgba(0,0,0,0.03)",
                                                       padding: 12, fontSize: 12 }}>
                        <div><b>Why {s.stage} is {s.state}:</b></div>
                        {(s.techniques || []).length > 0 && (
                          <div style={{ marginTop: 4 }}>
                            MITRE: <span className="mono">
                              {(s.techniques || []).join(", ")}
                            </span>
                          </div>
                        )}
                        {(s.finding_ids || []).length > 0 && (
                          <div style={{ marginTop: 4 }}>
                            Findings: <span className="mono">
                              {(s.finding_ids || []).slice(0, 4).join(", ")}
                              {s.finding_ids.length > 4 ? ` (+${s.finding_ids.length - 4} more)` : ""}
                            </span>
                          </div>
                        )}
                        {(s.evidence_refs || []).length > 0 && (
                          <div style={{ marginTop: 4 }}>
                            Evidence refs: <span className="mono">
                              {(s.evidence_refs || []).slice(0, 4).join(", ")}
                              {s.evidence_refs.length > 4 ? ` (+${s.evidence_refs.length - 4} more)` : ""}
                            </span>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* 4. Why-It-Matters */}
      <div className="rl-section" style={{ marginTop: 12 }}>
        <div className="rl-section-title">Why NivXRay XDR thinks this matters</div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12 }}>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 6 }}>
              Supporting ({(why.supporting_factors || []).length})
            </div>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}
                 data-testid="xdr-record-tm-supporting">
              {(why.supporting_factors || []).slice(0, 8).map((f, i) => (
                <li key={i} style={{ padding: "4px 0", fontSize: 12,
                                          borderBottom: "1px dashed rgba(0,0,0,0.08)" }}>
                  <div>{f.factor || f.summary}</div>
                  {f.techniques && f.techniques.length > 0 && (
                    <div className="mono" style={{ opacity: 0.6, fontSize: 11 }}>
                      {f.techniques.join(", ")}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          </div>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 6 }}>
              Reducing ({(why.reducing_factors || []).length})
            </div>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}
                 data-testid="xdr-record-tm-reducing">
              {(why.reducing_factors || []).map((f, i) => (
                <li key={i} style={{ padding: "4px 0", fontSize: 12,
                                          borderBottom: "1px dashed rgba(0,0,0,0.08)" }}>
                  {f.factor}
                </li>
              ))}
              {(why.reducing_factors || []).length === 0 && (
                <li style={{ opacity: 0.5, fontSize: 12 }}>—</li>
              )}
            </ul>
          </div>
          <div>
            <div style={{ fontWeight: 600, marginBottom: 6 }}>
              Unknown ({(why.unknown || []).length})
            </div>
            <ul style={{ listStyle: "none", padding: 0, margin: 0 }}
                 data-testid="xdr-record-tm-unknown">
              {(why.unknown || []).map((u, i) => (
                <li key={i} style={{ padding: "4px 0", fontSize: 12,
                                          borderBottom: "1px dashed rgba(0,0,0,0.08)" }}>
                  <div className="mono" style={{ fontSize: 11 }}>{u.fact}</div>
                  <div style={{ opacity: 0.55, fontSize: 11 }}>{u.reason}</div>
                </li>
              ))}
              {(why.unknown || []).length === 0 && (
                <li style={{ opacity: 0.5, fontSize: 12 }}>—</li>
              )}
            </ul>
          </div>
        </div>
      </div>

      {/* 5. Impact + blast radius */}
      {impact.score !== undefined && (
        <div className="rl-section" style={{ marginTop: 12 }}>
          <div className="rl-section-title">Impact · independent axis</div>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}
                data-testid="xdr-record-tm-impact">
            <div className={`rl-metric ${impact.current_score > 0 ? "amber" : "na"}`}
                  style={{ flex: 1, minWidth: 140 }}>
              <div className="k">Current</div>
              <div className="v">{impact.current_score}</div>
              <div className="sub">{impact.current_band}</div>
            </div>
            <div className={`rl-metric ${impact.potential_score > 0 ? "info" : "na"}`}
                  style={{ flex: 1, minWidth: 140 }}>
              <div className="k">Potential</div>
              <div className="v">{impact.potential_score}</div>
              <div className="sub">{impact.potential_band}</div>
            </div>
            <div className={`rl-metric ${(impact.blast_radius?.count || 0) > 0 ? "info" : "na"}`}
                  style={{ flex: 1, minWidth: 140 }}>
              <div className="k">Blast radius</div>
              <div className="v">{impact.blast_radius?.count ?? 0}</div>
              <div className="sub">
                {impact.blast_radius?.related_incidents?.length || 0} incidents ·
                {" "}{impact.blast_radius?.related_hosts?.length || 0} hosts
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
