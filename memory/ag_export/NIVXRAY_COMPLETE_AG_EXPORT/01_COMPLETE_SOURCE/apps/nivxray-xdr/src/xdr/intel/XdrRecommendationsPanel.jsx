/**
 * XdrRecommendationsPanel · "Recommended Next Steps"
 * ───────────────────────────────────────────────────
 * Mounted on the Investigation Workspace.  Continuously recalculates
 * as evidence changes.  Every recommendation shows:
 *
 *   · label + priority + kind
 *   · SUPPORTING evidence (rule / MITRE / IOC / verdict / engine)
 *   · RISK MODIFIERS (destructive · production · approval)
 *   · SOURCE (which engine / rule / playbook contributed)
 *
 * Already-executed actions are surfaced as `ALREADY EXECUTED` — the
 * panel never re-recommends what a completed playbook has done.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Lightbulb, ShieldAlert, Search, Beaker, Radar,
  Wand2, RefreshCw, CheckCircle2, Clock } from "lucide-react";

import { IocConsumer, RecommendationsConsumer } from "@/xdr/adopt/baseCapabilities";
import api from "@/lib/api";
import {
  computeRecommendations, deriveMatchedRulesFromIncident,
  deriveIocDispositions, playbooksFromExecutions, REC_KIND,
} from "@/xdr/intel/recommendationEngine";

// Match XDR canonical rule→technique map (already used by canvas)
import { RULE_TO_TECHNIQUE } from "@/xdr/mitre/mitreTactics";


// Fetch response executions for an incident from the AUTHORITATIVE
// base endpoint (POST /api/xdr/response-evidence writes here; this
// is the read counterpart).  Returns [] on any failure — the
// engine never fabricates response state.
async function fetchExecutions(incidentId) {
  if (!incidentId) return [];
  try {
    const r = await api.get(
      `/api/xdr/incidents/${encodeURIComponent(incidentId)}/response-executions`);
    return r?.data?.executions || r?.data?.rows || r?.data || [];
  } catch { return []; }
}


const KIND_ICON = {
  [REC_KIND.INVESTIGATE]: Search,
  [REC_KIND.ENRICH]:      Radar,
  [REC_KIND.COLLECT]:     Beaker,
  [REC_KIND.RESPOND]:     ShieldAlert,
  [REC_KIND.DECODE]:      Wand2,
  [REC_KIND.HUNT]:        Search,
};

const PRIORITY_COLOR = {
  CRITICAL: "#f87171", HIGH: "#fb923c", MEDIUM: "#facc15",
  LOW: "var(--mint)", INFO: "var(--faint)",
};


export default function XdrRecommendationsPanel({ incident }) {
  const [recs, setRecs] = useState({ recommendations: [],
                                                       already_executed: [] });
  const [state, setState] = useState({ loading: true, baseErr: null,
                                                       lastRecalc: null });
  const [refresh, setR] = useState(0);

  const recalc = async () => {
    if (!incident) return;
    setState({ loading: true, baseErr: null, lastRecalc: null });

    // ── 1. Fetch base evidence-driven recommendations (authoritative).
    let baseRecs = null;
    let baseErr = null;
    const seedInput =
        incident?.evidence?.[0]?.command_line
     || incident?.evidence?.[0]?.commandline
     || incident?.command_line || incident?.commandline || "";
    if (seedInput) {
      const r = await RecommendationsConsumer.fromEvidence(seedInput);
      if (r.ok) baseRecs = r.data; else baseErr = r;
    }

    // ── 2. Fetch IOC dispositions.
    const iocDispositions = await deriveIocDispositions(
      incident, (value, kind) => IocConsumer.lookup({ value, kind }));

    // ── 3. Fetch previous response executions on this incident.
    let previousResponses = [];
    let applicablePlaybooks = [];
    try {
      const execs = await fetchExecutions(incident.id);
      previousResponses = execs || [];
      applicablePlaybooks = playbooksFromExecutions(previousResponses);
    } catch { /* engine not wired — skip; never fabricate */ }

    // ── 4. Derive matched rules from incident evidence.
    const matchedRules = deriveMatchedRulesFromIncident(incident,
                                                                                   RULE_TO_TECHNIQUE);

    // ── 5. Compute deterministic recommendations.
    const computed = computeRecommendations({
      incident, baseRecs, iocDispositions, matchedRules,
      applicablePlaybooks, previousResponses,
    });
    setRecs(computed);
    setState({ loading: false, baseErr,
                    lastRecalc: new Date().toISOString() });
  };

  useEffect(() => { recalc(); /* eslint-disable-next-line */ },
    [incident?.id, refresh]);

  const critical = useMemo(() =>
    recs.recommendations.filter((r) => r.priority_label === "CRITICAL"),
    [recs]);

  return (
    <div className="panel" data-testid="xdr-recommendations-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <Lightbulb size={12} /> Recommended Next Steps
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          · evidence-driven · deterministic
        </span>
        <span style={{ flex: 1 }} />
        {state.lastRecalc && (
          <span className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                          marginRight: 6 }}>
            recalculated {new Date(state.lastRecalc).toLocaleTimeString()}
          </span>
        )}
        <button className="btn ghost" onClick={() => setR((n) => n + 1)}
                  data-testid="xdr-recs-refresh"
                  style={{ padding: "2px 8px", fontSize: 10 }}>
          <RefreshCw size={10} /> Recalculate
        </button>
      </div>

      {state.baseErr && (
        <div style={{ fontSize: 10.5, color: "var(--faint)",
                          marginBottom: 6, padding: 6, borderRadius: 3,
                          border: "1px dashed var(--faint)" }}>
          Note: base recommender at{" "}
          <span className="mono" style={{ color: "var(--cyan)" }}>
            /api/decode/mitigations/evidence_driven
          </span>{" "}
          returned {state.baseErr.status || "error"} — showing rule + IOC +
          verdict-derived recommendations only.  NEVER fabricated.
        </div>
      )}

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Computing recommendations from evidence…
        </div>
      )}

      {!state.loading && recs.recommendations.length === 0 &&
       recs.already_executed.length === 0 && (
        <div style={{ fontSize: 11, color: "var(--faint)",
                          padding: 6, borderRadius: 3,
                          border: "1px dashed var(--faint)" }}>
          NO ACTIONABLE RECOMMENDATIONS — insufficient evidence to
          derive a next step.  Add IOC / process / rule evidence to the
          incident and recalculate.
        </div>
      )}

      {critical.length > 0 && (
        <div style={{ marginBottom: 8, padding: 6, borderRadius: 3,
                          border: "1px solid #f87171",
                          background: "rgba(248,113,113,.06)" }}>
          <b className="mono" style={{ fontSize: 10, color: "#f87171",
                                                       textTransform: "uppercase" }}>
            {critical.length} critical action{critical.length === 1 ? "" : "s"} recommended
          </b>
        </div>
      )}

      {recs.recommendations.map((r) => (
        <RecommendationRow key={r.id} rec={r} />
      ))}

      {recs.already_executed.length > 0 && (
        <div style={{ marginTop: 10, paddingTop: 8,
                          borderTop: "1px dashed var(--border)" }}
                data-testid="xdr-recs-already-executed">
          <div className="mono" style={{ fontSize: 10, color: "var(--faint)",
                                                        textTransform: "uppercase",
                                                        marginBottom: 4 }}>
            Already executed ({recs.already_executed.length})
          </div>
          {recs.already_executed.map((r) => (
            <div key={r.id} data-testid={`xdr-rec-already-${r.action}`}
                    style={{ padding: "4px 0", fontSize: 11,
                                color: "var(--faint)",
                                borderBottom: "1px solid var(--border)",
                                display: "flex", alignItems: "center", gap: 6 }}>
              <CheckCircle2 size={11} style={{ color: "var(--mint)" }} />
              <span>{r.label}</span>
              <span style={{ flex: 1 }} />
              <span className="mono" style={{ fontSize: 9.5,
                                                              color: "var(--mint)",
                                                              padding: "1px 4px",
                                                              border: "1px solid var(--mint)",
                                                              borderRadius: 3 }}>
                ALREADY EXECUTED
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


function RecommendationRow({ rec }) {
  const [open, setOpen] = useState(false);
  const Icon = KIND_ICON[rec.kind] || Search;
  const pcolor = PRIORITY_COLOR[rec.priority_label] || "var(--faint)";
  return (
    <div data-testid={`xdr-rec-row-${rec.action}`}
            style={{ padding: "5px 0", fontSize: 11,
                        color: "var(--text-dim)",
                        borderBottom: "1px solid var(--border)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <Icon size={11} style={{ color: pcolor }} />
        <b className="mono" style={{ fontSize: 10.5,
                                                    color: pcolor,
                                                    padding: "1px 4px",
                                                    border: `1px solid ${pcolor}`,
                                                    borderRadius: 3 }}>
          {rec.priority_label}
        </b>
        <span style={{ flex: 1 }}>{rec.label}</span>
        {rec.state === "WAITING_APPROVAL" && (
          <span className="mono" style={{ fontSize: 9.5,
                                                          color: "var(--amber)",
                                                          padding: "1px 4px",
                                                          border: "1px solid var(--amber)",
                                                          borderRadius: 3 }}>
            <Clock size={9} style={{ verticalAlign: "middle",
                                                    marginRight: 2 }} />
            WAITING APPROVAL
          </span>
        )}
        {rec.approval_required && rec.state !== "WAITING_APPROVAL" && (
          <span className="mono" style={{ fontSize: 9.5,
                                                          color: "var(--amber)" }}>
            approval required
          </span>
        )}
        <button className="btn ghost" onClick={() => setOpen((v) => !v)}
                  data-testid={`xdr-rec-why-${rec.action}`}
                  style={{ padding: "1px 6px", fontSize: 10 }}>
          {open ? "hide" : "why?"}
        </button>
      </div>
      {open && (
        <div style={{ marginTop: 4, marginLeft: 22, fontSize: 10.5,
                          color: "var(--faint)" }}
                data-testid={`xdr-rec-explain-${rec.action}`}>
          <div className="mono" style={{ marginBottom: 2,
                                                        color: "var(--text-dim)" }}>
            Source · {rec.source}
          </div>
          {rec.supporting.length > 0 && (
            <div style={{ marginBottom: 2 }}>
              <span className="mono" style={{ color: "var(--mint)" }}>
                supporting:
              </span>
              {rec.supporting.map((s, i) => (
                <div key={i} style={{ marginLeft: 8 }}>
                  ✓ <span className="mono" style={{ color: "var(--cyan)" }}>
                    {s.kind}
                  </span>{" "}
                  {s.ref}
                  {s.note && (
                    <span style={{ color: "var(--faint)" }}> · {s.note}</span>
                  )}
                </div>
              ))}
            </div>
          )}
          {rec.risk_modifiers.length > 0 && (
            <div>
              <span className="mono" style={{ color: "var(--amber)" }}>
                risk modifiers:
              </span>
              {rec.risk_modifiers.map((r, i) => (
                <div key={i} style={{ marginLeft: 8 }}>
                  ⚠ <span>{r.note || r.kind}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
