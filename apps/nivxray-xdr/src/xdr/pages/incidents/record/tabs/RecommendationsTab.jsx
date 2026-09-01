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
import { CheckCircle2, ShieldAlert, Loader2, Radar } from "lucide-react";
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
  return (
    <div data-testid={`reco-${r.id}`}
              style={{ padding: 10, marginBottom: 8,
                              border: `1px solid ${active ? cat : "var(--border)"}`,
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


function AnalystButton({ reco, decision, label, color }) {
  const [state, setState] = useState("idle");
  const click = async () => {
    setState("busy");
    try {
      // Persist the analyst decision into the existing
      // xdr_recommendations SSOT via the closed-loop endpoint.
      // The route accepts additive decision fields.
      await api.post(
        `/admin/content-supply-chain/recommendations/${reco.id}/decision`,
        {decision, reason: `analyst ${decision.toLowerCase()}`});
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
