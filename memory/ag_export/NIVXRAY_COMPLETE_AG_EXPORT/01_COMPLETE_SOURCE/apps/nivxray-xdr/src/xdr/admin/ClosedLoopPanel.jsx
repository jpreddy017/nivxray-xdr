/**
 * ClosedLoopPanel — Round 14 · P0.7.1 · Read-only UI for the
 * closed-loop recompute state.
 *
 * Renders honest values from the pipeline output's `closed_loop`
 * sub-document (already surfaced by /e2e/snort-golden) and from
 *   POST /api/admin/content-supply-chain/response/:id/recompute
 * for on-demand re-recompute.
 */
import React, { useState } from "react";
import { RefreshCw, GitBranch, ChevronRight, ArrowUpCircle,
                Circle, CheckCircle2 } from "lucide-react";
import api from "@/lib/api";


export default function ClosedLoopPanel({ incidentId, initial, testid }) {
  const [state, setState] = useState(initial || null);
  const [busy,  setBusy]  = useState(false);
  const [err,   setErr]   = useState(null);

  const runRecompute = async () => {
    if (!incidentId) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.post(
        `/admin/content-supply-chain/response/${incidentId}/recompute`);
      setState(r.data);
    } catch (e) {
      setErr(e?.response?.data?.detail || e?.message || "unavailable");
    } finally {
      setBusy(false);
    }
  };

  if (!state) return null;

  const recos     = state.recommendations || {};
  const changed   = state.changed;

  return (
    <div data-testid={testid || "closed-loop"}
              className="panel"
              style={{ padding: "14px 16px", marginTop: 14,
                              borderLeft: "3px solid var(--mint)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 10 }}>
        <span style={{
          fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
          letterSpacing: ".6px", textTransform: "uppercase",
          color: "var(--mint)",
        }}>
          Closed-Loop Recompute · {state.incident_id}
        </span>
        <span style={{ flex: 1 }} />
        <button data-testid="closed-loop-recompute-btn"
                    className="btn ghost" onClick={runRecompute}
                    disabled={busy}
                    style={{ padding: "3px 12px", fontSize: 11 }}>
          <RefreshCw size={11} /> {busy ? "Recomputing…" : "Recompute"}
        </button>
      </div>

      {err && (
        <div style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: "var(--amber)", marginBottom: 8 }}>{err}</div>
      )}

      <div style={{ display: "grid",
                          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                          gap: 8, marginBottom: 10 }}>
        <Kpi label="changed" value={String(changed)}
                color={changed ? "var(--mint)" : "var(--faint)"} />
        <Kpi label="new_observations" value={state.new_observations ?? 0} />
        <Kpi label="total_observations" value={state.total_observations ?? 0} />
        <Kpi label="threat_family" value={state.threat_family || "—"}
                color="#a78bfa" />
        <Kpi label="family_conf" value={state.threat_family_confidence || "—"} />
        <Kpi label="investigation" value={state.investigation_state} />
        <Kpi label="decision" value={state.decision}
                color="var(--cyan)" />
      </div>

      {(state.recommendations?.synthesized || []).length > 0 && (
        <div data-testid="synthesized-recos"
                  style={{ border: "1px solid var(--border)", borderRadius: 4,
                                  padding: 10, background: "var(--panel2)",
                                  marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6,
                              marginBottom: 6 }}>
            <b style={{ fontFamily: "var(--mono)", fontSize: 11,
                              color: "var(--text)" }}>
              Recommendation Synthesis
            </b>
            <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                                color: "var(--faint)" }}>
              · {(state.recommendations.synthesized || []).length} candidates
            </span>
          </div>
          {(state.recommendations.synthesized || []).map((r) => (
            <div key={r.id} style={{ padding: "4px 0",
                                                    borderBottom: "1px solid var(--border)",
                                                    fontFamily: "var(--mono)",
                                                    fontSize: 10.5 }}>
              <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
                <span style={{
                  padding: "0 6px",
                  border: `1px solid ${r.applicability === "APPLICABLE"
                                                        ? "var(--mint)" : "var(--amber)"}`,
                  color:  r.applicability === "APPLICABLE"
                              ? "var(--mint)" : "var(--amber)",
                  borderRadius: 2, fontSize: 9, fontWeight: 700,
                }}>{r.applicability}</span>
                <b style={{ color: "var(--cyan)" }}>{r.suggested_action}</b>
                <span style={{ color: "var(--text-dim)" }}>
                  → {r.target_entity?.value}
                </span>
                <span style={{ flex: 1 }} />
                <span style={{ color: "var(--faint)", fontSize: 9 }}>
                  {r.category}
                </span>
              </div>
              <div style={{ marginTop: 2, color: "var(--text-dim)",
                                    fontSize: 10, fontFamily: "var(--sans)" }}>
                {r.text}
              </div>
              <div style={{ marginTop: 2, color: "var(--faint)",
                                    fontSize: 9 }}>
                {r.applicability_reason}
              </div>
            </div>
          ))}
        </div>
      )}

      {(state.playbooks || []).length > 0 && (
        <div data-testid="playbook-applicability"
                  style={{ border: "1px solid var(--border)", borderRadius: 4,
                                  padding: 10, background: "var(--panel2)",
                                  marginBottom: 10 }}>
          <b style={{ fontFamily: "var(--mono)", fontSize: 11,
                            color: "var(--text)" }}>
            Playbook Applicability · family={state.threat_family || "—"}
          </b>
          <div style={{ marginTop: 4, display: "grid",
                              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                              gap: 4 }}>
            {(state.playbooks || []).map((pb) => (
              <div key={pb.id} style={{ fontFamily: "var(--mono)",
                                                        fontSize: 10 }}>
                <span style={{
                  color: pb.applicability === "APPLICABLE"
                              ? "var(--mint)" : "var(--faint)",
                  fontWeight: 700, marginRight: 6,
                }}>{pb.applicability}</span>
                {pb.id}
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ display: "grid",
                          gridTemplateColumns: "1fr 1fr 1fr",
                          gap: 10 }}>
        <List title="Active recommendations"
                 items={recos.active || []}
                 icon={CheckCircle2} color="var(--mint)"
                 testid="closed-loop-active" />
        <List title="Created (this run)"
                 items={recos.created || []}
                 icon={ArrowUpCircle} color="#38bdf8"
                 testid="closed-loop-created" />
        <List title="Superseded"
                 items={recos.superseded || []}
                 icon={GitBranch} color="var(--amber)"
                 testid="closed-loop-superseded" />
      </div>

      <div style={{ marginTop: 10, fontFamily: "var(--mono)",
                          fontSize: 9.5, color: "var(--faint)",
                          lineHeight: 1.5 }}>
        evidence_state_hash: <b style={{ color: "var(--text-dim)" }}>
          {state.evidence_state_hash}
        </b>{state.previous_evidence_state_hash && (
          <> · previous: <span style={{ color: "var(--faint)" }}>
            {state.previous_evidence_state_hash}
          </span></>
        )} · {state.honesty_note}
      </div>
    </div>
  );
}


function Kpi({ label, value, color }) {
  return (
    <div style={{ padding: 8, border: "1px solid var(--border)",
                        borderRadius: 3, background: "var(--panel2)" }}>
      <div style={{ fontSize: 9, color: "var(--faint)",
                          textTransform: "uppercase", letterSpacing: ".4px",
                          fontFamily: "var(--mono)", fontWeight: 700 }}>
        {label}
      </div>
      <div style={{ marginTop: 2, fontFamily: "var(--mono)",
                          fontSize: 13, fontWeight: 700,
                          color: color || "var(--text)" }}>
        {value ?? "—"}
      </div>
    </div>
  );
}

function List({ title, items, icon: Icon, color, testid }) {
  return (
    <div data-testid={testid}
              style={{ padding: 8, border: "1px solid var(--border)",
                              borderRadius: 3, background: "var(--panel2)" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                          marginBottom: 6 }}>
        <Icon size={11} style={{ color }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 11,
                          color: "var(--text)" }}>{title}</b>
        <span style={{ flex: 1 }} />
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color }}>{items.length}</span>
      </div>
      {items.length === 0 && (
        <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                            color: "var(--faint)" }}>none</div>
      )}
      {items.map((id, i) => (
        <div key={id + i} style={{ fontFamily: "var(--mono)",
                                                    fontSize: 10, color: "var(--text-dim)",
                                                    padding: "2px 0" }}>
          <ChevronRight size={9} style={{ marginRight: 4,
                                                          color: "var(--faint)" }} />
          {id}
        </div>
      ))}
    </div>
  );
}
