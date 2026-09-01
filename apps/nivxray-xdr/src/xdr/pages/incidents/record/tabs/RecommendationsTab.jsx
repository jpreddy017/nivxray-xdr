/**
 * RecommendationsTab · Round 17.5 · Evidence-derived, entity-bound.
 *
 * Reads the Round 16 synthesized recommendations from the existing
 *   POST /api/admin/content-supply-chain/response/:incident_id/recompute
 * endpoint (idempotent closed-loop recompute).  Every recommendation
 * is bound to a real observed entity, tagged with honest applicability,
 * cites framework rationale and reports capability truthfully.
 *
 * There is NO generic "gap → static verb" fallback here. If the
 * synthesizer produces zero candidates, the tab honestly says so.
 */
import React, { useEffect, useState } from "react";
import { CheckCircle2, ShieldAlert, Loader2, Radar, AlertTriangle, ChevronDown, ChevronRight } from "lucide-react";
import api from "@/lib/api";


const CAT_COLOR = {
  IMMEDIATE:     "#f87171",
  INVESTIGATION: "#38bdf8",
  REMEDIATION:   "var(--amber)",
  PREVENTION:    "var(--mint)",
};

const APP_COLOR = {
  APPLICABLE:              "var(--mint)",
  ALREADY_EXECUTED:        "var(--faint)",
  CAPABILITY_UNAVAILABLE:  "var(--amber)",
  INSUFFICIENT_EVIDENCE:   "var(--faint)",
  NOT_APPLICABLE:          "var(--faint)",
  SUPERSEDED:              "var(--faint)",
};

// Round 18 · Exclusion risk band colours.
const RISK_COLOR = {
  LOW:      "var(--mint)",
  MEDIUM:   "var(--amber)",
  HIGH:     "#f87171",
  CRITICAL: "#dc2626",
  UNKNOWN:  "var(--faint)",
};


export default function RecommendationsTab({ incident }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [err,     setErr]     = useState(null);

  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    setLoading(true); setErr(null);
    (async () => {
      try {
        const r = await api.post(
          `/admin/content-supply-chain/response/${incident.id}/recompute`);
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail
                                          || e?.message || "unavailable");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  if (loading) {
    return (
      <div data-testid="reco-loading" style={emptyBox}>
        <Loader2 size={14} className="rl-spin" /> Synthesizing
        recommendations for this incident…
      </div>
    );
  }
  if (err || !data) {
    return (
      <div data-testid="reco-error" style={{ ...emptyBox,
                                                              color: "var(--amber)" }}>
        {err || "no data"}
      </div>
    );
  }

  const synth  = (data.recommendations?.synthesized || []);
  const active = synth.filter((r) => r.applicability === "APPLICABLE");
  const other  = synth.filter((r) => r.applicability !== "APPLICABLE");

  return (
    <div data-testid="reco-tab" style={{ padding: "0 4px" }}>
      <Header threatFamily={data.threat_family}
                    confidence={data.threat_family_confidence}
                    active={active.length}
                    total={synth.length} />

      {active.length === 0 && (
        <div style={emptyBox}>
          No APPLICABLE recommendation was synthesized for this incident.
          Every candidate below explains honestly why it was not applied
          (missing evidence, capability, or already executed).
        </div>
      )}

      {active.map((r) => (
        <RecoCard key={r.id} r={r} active={true} />
      ))}

      {other.length > 0 && (
        <details style={{ marginTop: 14 }} data-testid="reco-why-not">
          <summary style={{ cursor: "pointer",
                                    fontFamily: "var(--mono)",
                                    fontSize: 11, color: "var(--faint)" }}>
            Why other candidates did not apply ({other.length})
          </summary>
          <div style={{ marginTop: 8 }}>
            {other.map((r) => <RecoCard key={r.id} r={r} active={false} />)}
          </div>
        </details>
      )}
    </div>
  );
}


function Header({ threatFamily, confidence, active, total }) {
  return (
    <div style={{ display: "flex", gap: 10, alignItems: "center",
                        padding: "10px 12px",
                        border: "1px solid var(--border)",
                        borderRadius: 4,
                        background: "var(--panel2)",
                        marginBottom: 12 }}>
      <ShieldAlert size={12} style={{ color: "#a78bfa" }} />
      <b style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
        Recommended Mitigations
      </b>
      <span style={{ flex: 1 }} />
      <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                          color: "var(--text-dim)" }}>
        Threat Family:{" "}
        <b style={{ color: "#a78bfa" }}>{threatFamily || "—"}</b>
        {confidence && <> · {confidence}</>}
        {" "}· {active}/{total} applicable
      </span>
    </div>
  );
}


function RecoCard({ r, active }) {
  const cat = CAT_COLOR[r.category] || "var(--faint)";
  const app = APP_COLOR[r.applicability] || "var(--faint)";
  const fw  = r.framework_rationale || {};
  const risk = r.risk_analysis || null;
  const riskBand = r.risk_band || null;
  const [riskOpen, setRiskOpen] = useState(false);
  // A high-visibility warning border overrides the category border
  // whenever the exclusion risk band is HIGH or CRITICAL.
  const borderColor = active
    ? (riskBand === "CRITICAL" ? RISK_COLOR.CRITICAL
        : riskBand === "HIGH" ? RISK_COLOR.HIGH
        : cat)
    : "var(--border)";
  return (
    <div data-testid={`reco-${r.id}`}
              style={{ padding: 10, marginBottom: 8,
                              border: `1px solid ${borderColor}`,
                              borderRadius: 4, background: "var(--panel2)",
                              opacity: active ? 1 : 0.75 }}>
      <div style={{ display: "flex", gap: 6, alignItems: "center",
                          flexWrap: "wrap" }}>
        <span style={pill(cat)}>{r.category}</span>
        <b style={{ color: "var(--cyan)", fontFamily: "var(--mono)",
                          fontSize: 12 }}>{r.suggested_action}</b>
        <span style={{ color: "var(--text-dim)", fontFamily: "var(--mono)",
                              fontSize: 11 }}>
          → {r.target_entity?.kind}:{r.target_entity?.value}
        </span>
        {riskBand && (
          <span data-testid={`reco-risk-badge-${r.id}`}
                       style={{ ...pill(RISK_COLOR[riskBand] || RISK_COLOR.UNKNOWN),
                                    display: "inline-flex", alignItems: "center",
                                    gap: 3 }}>
            <AlertTriangle size={9} />
            {riskBand} EXCLUSION RISK
          </span>
        )}
        <span style={{ flex: 1 }} />
        <span style={pill(app)}>{r.applicability}</span>
      </div>
      <div style={{ marginTop: 4, fontFamily: "var(--sans)",
                          fontSize: 11.5, color: "var(--text-dim)",
                          lineHeight: 1.5 }}>
        {r.text}
      </div>
      <div style={{ marginTop: 4, fontFamily: "var(--mono)",
                          fontSize: 10, color: "var(--faint)" }}>
        {r.applicability_reason}
      </div>
      {(fw.hint || fw.matched) && (
        <div style={{ marginTop: 4, fontFamily: "var(--mono)",
                            fontSize: 10, color: "var(--faint)" }}>
          <Radar size={9} style={{ marginRight: 4 }} />
          Framework: {fw.hint}{fw.matched
            ? ` · ${fw.detail}`
            : " · not mapped for this incident"}
        </div>
      )}
      {risk && (
        <ExclusionRiskPanel r={r} risk={risk} riskBand={riskBand}
                                        open={riskOpen} setOpen={setRiskOpen} />
      )}
      {active && (
        <div style={{ marginTop: 6, display: "flex", gap: 6 }}>
          <AnalystButton reco={r} decision="ACCEPTED" label="Accept"
                                color="var(--mint)" />
          <AnalystButton reco={r} decision="REJECTED" label="Reject"
                                color="var(--amber)" />
          <AnalystButton reco={r} decision="SUPERSEDED" label="Supersede"
                                color="var(--faint)" />
        </div>
      )}
    </div>
  );
}


// ── Round 18 · Exclusion Risk Analysis panel ────────────────────
// Inline severity badge lives on the card header (see RecoCard).
// This component renders the FULL breakdown when the analyst
// expands it — Detection Method · Affected Engine · Exclusion Type ·
// Scope · Visibility Impact · Security Risk · Safer Alternative ·
// Analyst Decision — plus an unmistakable warning banner when the
// band is HIGH or CRITICAL.
function ExclusionRiskPanel({ r, risk, riskBand, open, setOpen }) {
  const bandColor = RISK_COLOR[riskBand] || RISK_COLOR.UNKNOWN;
  return (
    <div data-testid={`reco-risk-panel-${r.id}`}
              style={{ marginTop: 8,
                              border: `1px solid ${bandColor}`,
                              borderRadius: 3,
                              background: "rgba(0,0,0,0.15)" }}>
      <button data-testid={`reco-risk-toggle-${r.id}`}
                    onClick={() => setOpen(!open)}
                    style={{ width: "100%", padding: "6px 10px",
                                    display: "flex", alignItems: "center",
                                    gap: 6, background: "transparent",
                                    border: "none", cursor: "pointer",
                                    color: bandColor,
                                    fontFamily: "var(--mono)", fontSize: 10,
                                    fontWeight: 700, textAlign: "left" }}>
        {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        Exclusion Risk Analysis
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--faint)", fontWeight: 400 }}>
          {risk.exclusion_type} · {risk.approval_policy}
        </span>
      </button>
      {open && (
        <div style={{ padding: "0 10px 10px 10px",
                              fontFamily: "var(--mono)", fontSize: 10.5,
                              color: "var(--text-dim)", lineHeight: 1.55 }}>
          {risk.warning_banner && (
            <div data-testid={`reco-risk-banner-${r.id}`}
                          style={{ marginBottom: 8, padding: "6px 8px",
                                          border: `1px solid ${bandColor}`,
                                          background: "rgba(220,38,38,0.08)",
                                          color: bandColor, fontWeight: 700,
                                          borderRadius: 2,
                                          display: "flex", gap: 6,
                                          alignItems: "flex-start" }}>
              <AlertTriangle size={11} style={{ marginTop: 1,
                                                                flexShrink: 0 }} />
              {risk.warning_banner}
            </div>
          )}
          <RiskRow k="Detection Method"    v={risk.detection_method} />
          <RiskRow k="Affected Engine"     v={risk.affected_engine} />
          <RiskRow k="Exclusion Type"      v={risk.exclusion_type} />
          <RiskRow k="Scope"               v={risk.scope} />
          <RiskRow k="Visibility Impact"   v={risk.visibility_impact} />
          <RiskRow k="Security Risk"       v={risk.security_risk}
                          valueColor={bandColor} bold />
          <RiskRow k="Safer Alternative"   v={risk.safer_alternative} />
          <RiskRow k="Approval Policy"     v={risk.approval_policy} />
          <RiskRow k="Analyst Decision"
                          v={risk.analyst_decision || "— not yet decided —"} />
        </div>
      )}
    </div>
  );
}

function RiskRow({ k, v, valueColor, bold }) {
  return (
    <div style={{ display: "grid",
                        gridTemplateColumns: "148px 1fr",
                        gap: 8, padding: "3px 0",
                        borderBottom: "1px dashed rgba(255,255,255,0.05)" }}>
      <span style={{ color: "var(--faint)" }}>{k}</span>
      <span style={{ color: valueColor || "var(--text-dim)",
                          fontWeight: bold ? 700 : 400 }}>{v || "—"}</span>
    </div>
  );
}


function AnalystButton({ reco, decision, label, color }) {
  const [state, setState] = useState("idle");
  const isExclusion = !!reco.risk_analysis;
  const highRisk = ["HIGH", "CRITICAL"].includes(reco.risk_band);

  const click = async () => {
    // Round 18.5 · exclusion + high/critical band → require the analyst
    // to explicitly acknowledge visibility loss and pick between the
    // ORIGINAL action or the SAFER ALTERNATIVE. This choice is
    // persisted verbatim into the audit trail.
    let saferAlternativeChosen = null;
    if (decision === "ACCEPTED" && isExclusion) {
      if (highRisk) {
        const safer = reco.risk_analysis.safer_alternative;
        const msg =
          `${reco.risk_band} EXCLUSION RISK\n\n` +
          `${reco.risk_analysis.warning_banner || ""}\n\n` +
          `Visibility Impact: ${reco.risk_analysis.visibility_impact}\n\n` +
          `Safer alternative:\n${safer}\n\n` +
          `OK  → accept SAFER alternative\n` +
          `Cancel → accept ORIGINAL action (records that you were warned)`;
        saferAlternativeChosen = window.confirm(msg)
          ? "SAFER_ALT" : "ORIGINAL_ACTION";
      } else {
        saferAlternativeChosen = "ORIGINAL_ACTION";
      }
    }

    setState("busy");
    try {
      await api.post(
        `/admin/content-supply-chain/recommendations/${reco.id}/decision`,
        {
          decision,
          reason: `analyst ${decision.toLowerCase()}`,
          suggested_action: reco.suggested_action,
          risk_analysis_snapshot: reco.risk_analysis || null,
          safer_alternative_chosen: saferAlternativeChosen,
        });
      setState("done");
    } catch {
      setState("err");
    }
  };
  return (
    <button data-testid={`reco-${decision.toLowerCase()}-${reco.id}`}
                onClick={click} disabled={state === "busy"}
                style={{ padding: "3px 10px", fontSize: 10,
                                fontFamily: "var(--mono)",
                                border: `1px solid ${color}`,
                                color, background: "transparent",
                                borderRadius: 2, cursor: "pointer" }}>
      {state === "done" ? "✓ " : ""}{label}
    </button>
  );
}


const pill = (color) => ({
  padding: "1px 6px", border: `1px solid ${color}`, color,
  borderRadius: 2, fontFamily: "var(--mono)", fontSize: 9,
  fontWeight: 700,
});
const emptyBox = {
  padding: 14, fontFamily: "var(--mono)", fontSize: 11,
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 4, background: "var(--panel2)",
};
