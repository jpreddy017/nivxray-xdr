/**
 * InvestigationActivityTab · Autonomous Investigation Operating Model
 * (§13, §16, §18, §26).
 *
 * NivXRay XDR does not expose an "Auto-Investigate" button.
 * Investigation is a native operating behavior — this tab
 * communicates STATE, not activation.  The tab renders the current
 * lifecycle state (§26) plus a live activity feed when the
 * Orchestrator writes to `engine_executions`.  Until IUE +
 * Orchestrator ship (rollout §14 items 2-3), the honest state is
 * `WAITING FOR EVIDENCE` — never a mocked "COMPLETE".
 */
import React, { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";

export default function AutoInvestigationTab({ incident }) {
  const [ai, setAi] = useState(incident?.auto_investigation || null);
  const [loading, setLoading] = useState(!incident?.auto_investigation);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (incident?.auto_investigation) { setAi(incident.auto_investigation); return undefined; }
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const { data } = await api.get("/incidents", { params: { limit: 200 } });
        const row = (data?.incidents || []).find(r => r.id === incident.id);
        if (!cancelled) setAi(row?.auto_investigation || null);
      } catch (e) {
        if (!cancelled) setError(e?.message || null);
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id, incident?.auto_investigation]);

  if (loading) return (
    <div className="rl-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING INVESTIGATION ACTIVITY…
    </div>
  );

  const raw   = (ai?.status || "NOT_RUN").toUpperCase();
  const total = ai?.engines_total ?? 0;
  const ok    = ai?.engines_ok ?? 0;
  const dur   = ai?.duration_ms;

  // §26 lifecycle grammar.  Never fabricate a COMPLETE state — an
  // absent Orchestrator yields `WAITING FOR EVIDENCE` honestly.
  const lifecycleFor = (s) => ({
    NOT_RUN:  { key: "waiting",       label: "WAITING FOR EVIDENCE" },
    RUNNING:  { key: "investigating", label: "INVESTIGATING" },
    COMPLETE: { key: "converging",    label: "CONVERGED" },
    PARTIAL:  { key: "converging",    label: "CONVERGED · PARTIAL" },
    FAILED:   { key: "failed",        label: "FAILED" },
  }[s] || { key: "waiting", label: "WAITING FOR EVIDENCE" });
  const state = lifecycleFor(raw);
  const explain = {
    waiting:       "NivXRay XDR is waiting on evidence eligible for autonomous investigation. Investigation will begin automatically as soon as the Orchestrator sees a governed trigger.",
    investigating: `NivXRay XDR is investigating this incident · ${ok}/${total} engines active.`,
    converging:    `NivXRay XDR converged the investigation${dur != null ? ` in ${Math.round(dur/100)/10}s` : ""} · ${ok}/${total} engines succeeded.`,
    failed:        "The autonomous investigation failed to complete against this incident.",
  }[state.key];

  return (
    <div data-testid="xdr-record-auto-investigation">
      {error && <div className="rl-error">{String(error)}</div>}

      <div className={`rl-ai-status ${state.key}`}
            data-testid="xdr-record-ai-status-card">
        <div className="badge">
          <span data-testid="xdr-record-ai-status">● {state.label}</span>
        </div>
        <div className="txt">
          <h5>Investigation Activity</h5>
          <p>{explain}</p>
        </div>
      </div>

      <div className="rl-metric-grid" style={{ marginBottom: 12 }}>
        <div className={`rl-metric ${total > 0 ? "info" : "na"}`}>
          <div className="k">Engines invoked</div>
          <div className="v">{total > 0 ? total : "—"}</div>
          <div className="sub">against this incident</div>
        </div>
        <div className={`rl-metric ${total > 0 ? "ok" : "na"}`}>
          <div className="k">Successful</div>
          <div className="v">{total > 0 ? ok : "—"}</div>
          <div className="sub">produced evidence</div>
        </div>
        <div className={`rl-metric ${dur != null ? "info" : "na"}`}>
          <div className="k">Duration</div>
          <div className="v">{dur != null ? `${Math.round(dur/100)/10}s` : "—"}</div>
          <div className="sub">orchestration wall-clock</div>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Engine executions · provenance</div>
        {(ai?.executions || []).length === 0
          ? <div className="rl-empty" data-testid="xdr-record-ai-empty">
              <b>No "Auto-Investigate" button.</b> Per the NivXRay XDR
              Autonomous Investigation Operating Model, investigation
              is a native operating behavior — the analyst never
              starts the machine.  Autonomous investigation activity
              will surface here as soon as the Orchestrator + IUE +
              Capability Fabric ship.  Human investigation actions
              (Investigate Process · Host · User · IP · Domain · File)
              live in the entity panels on the Related and Attack
              Story tabs.
            </div>
          : <table className="rl-table">
              <thead><tr>
                <th>Engine</th><th>Status</th><th>Duration</th><th>Started</th>
              </tr></thead>
              <tbody>
                {ai.executions.map((e, i) => (
                  <tr key={i} data-testid={`xdr-record-ai-exec-${i}`}>
                    <td className="mono" style={{ color: "var(--rl-purple)" }}>{e.engine}</td>
                    <td className="mono">{String(e.status || "—").toUpperCase()}</td>
                    <td className="mono">{e.duration_ms != null ? `${Math.round(e.duration_ms/100)/10}s` : "—"}</td>
                    <td className="mono">{(e.started_at || "").slice(0, 16).replace("T", " ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>}
      </div>
    </div>
  );
}
