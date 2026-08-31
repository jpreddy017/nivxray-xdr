/**
 * AutoInvestigationTab · Layer 3 v2 · light-first status card.
 *
 * Same honest contract as before: NOT_RUN until Phase 4 wires the
 * xdr_observations + engine_executions collections.  Now presented
 * as a polished light status card with a circular status badge and
 * a placeholder for the per-engine execution table.
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
      LOADING AUTO-INVESTIGATION STATUS…
    </div>
  );

  const status = (ai?.status || "NOT_RUN").toLowerCase();
  const total  = ai?.engines_total ?? 0;
  const ok     = ai?.engines_ok ?? 0;
  const dur    = ai?.duration_ms;
  const cls    = ["not_run", "complete", "partial", "failed", "running"].includes(status)
                    ? status : "not_run";
  const explain = {
    not_run:  "No auto-investigation orchestration has fired against this incident.",
    complete: `${ok}/${total} engines succeeded${dur != null ? ` in ${Math.round(dur/100)/10}s` : ""}.`,
    partial:  `${ok}/${total} engines succeeded — the remainder failed or produced no evidence.`,
    failed:   "The orchestration failed to complete against this incident.",
    running:  "Auto-investigation is currently running against this incident.",
  }[cls];

  return (
    <div data-testid="xdr-record-auto-investigation">
      {error && <div className="rl-error">{String(error)}</div>}

      <div className={`rl-ai-status ${cls}`}
            data-testid="xdr-record-ai-status-card">
        <div className="badge">
          <span data-testid="xdr-record-ai-status">
            {(ai?.status || "NOT_RUN").replace("_", " ")}
          </span>
        </div>
        <div className="txt">
          <h5>Auto-Investigation status</h5>
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
          <div className="sub">completed with evidence</div>
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
          ? <div className="rl-empty">
              NOT_RUN — per-engine execution provenance arrives with
              Phase 4 (<code>xdr_observations</code> + <code>engine_executions</code>).
              <span className="kbd">queue is a projection · never runs an engine</span>
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
