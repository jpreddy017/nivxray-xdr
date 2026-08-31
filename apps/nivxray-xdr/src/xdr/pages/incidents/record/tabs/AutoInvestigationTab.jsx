/**
 * AutoInvestigationTab · Layer 3.
 *
 * The Phase-4 orchestration engine (xdr_observations + engine_executions)
 * is not yet implemented.  This tab surfaces the current honest state:
 * whatever the queue-projection AI status API returns per incident,
 * plus a clear explanation of what Phase 4 will add.
 *
 * We do NOT fabricate engine executions here — every field renders
 * NOT_RUN / NO EVIDENCE / — until Phase 4 wires up real provenance.
 */
import React, { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";

export default function AutoInvestigationTab({ incident }) {
  // Try the queue-scoped API for per-incident status.  If the incident
  // detail already carries auto_investigation payload, use that first.
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
        // Re-derive by pulling this incident's row projection.
        const { data } = await api.get("/incidents", {
          params: { limit: 1 },
        });
        const row = (data?.incidents || []).find(r => r.id === incident.id);
        if (!cancelled) setAi(row?.auto_investigation || null);
      } catch (e) {
        if (!cancelled) setError(e?.message || null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id, incident?.auto_investigation]);

  const status = ai?.status || "NOT_RUN";
  const total  = ai?.engines_total ?? 0;
  const ok     = ai?.engines_ok ?? 0;
  const dur    = ai?.duration_ms;

  const toneFor = (s) => (
    s === "COMPLETE" ? { color: "var(--rd-text)", bg: "#0f2b1c", bd: "#3CE8B8" }
    : s === "PARTIAL" ? { color: "var(--rd-text)", bg: "#2b1e0a", bd: "#F5A623" }
    : s === "FAILED"  ? { color: "var(--rd-text)", bg: "#2b0f10", bd: "#EF5B5B" }
    : s === "RUNNING" ? { color: "var(--rd-text)", bg: "#0d1e2c", bd: "#3FC1E8" }
    :                    { color: "var(--rd-text-dim)", bg: "#1B1F2D", bd: "#4A5162" }
  );

  const tone = toneFor(status);

  if (loading) return (
    <div style={{ padding: 40, textAlign: "center", color: "var(--rd-muted)",
                    fontFamily: "var(--rs-mono)" }}>
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING AUTO-INVESTIGATION STATUS…
    </div>
  );

  return (
    <div data-testid="xdr-record-auto-investigation" style={{ color: "var(--rd-text)" }}>
      {error && (
        <div style={{ padding: 10, marginBottom: 12,
                       background: "#2b0f10", color: "#ff9494",
                       border: "1px solid #EF5B5B", borderRadius: 4,
                       fontFamily: "var(--rs-mono)", fontSize: 11 }}>
          {String(error)}
        </div>
      )}

      {/* Headline status card */}
      <div style={{
        background: "var(--rd-panel)",
        border: `1px solid var(--rd-border)`,
        borderLeft: `3px solid ${tone.bd}`,
        borderRadius: 6, padding: "14px 16px", marginBottom: 12,
      }}>
        <div style={{ fontSize: 10, letterSpacing: 0.5, textTransform: "uppercase",
                        fontWeight: 800, color: "var(--rd-muted)", marginBottom: 4 }}>
          Overall status
        </div>
        <div style={{ fontFamily: "var(--rs-mono)", fontSize: 22,
                        fontWeight: 800, color: tone.bd, letterSpacing: 0.3 }}
              data-testid="xdr-record-ai-status">
          {status}
        </div>
        <div style={{ marginTop: 6, fontSize: 11.5, color: "var(--rd-text-dim)" }}>
          {status === "NOT_RUN"
            ? "No auto-investigation orchestration has fired against this incident."
            : `${ok}/${total} engine(s) succeeded${dur != null ? ` in ${Math.round(dur/100)/10}s` : ""}.`}
        </div>
      </div>

      {/* Engine execution table (Phase 4 placeholder) */}
      <div style={{
        background: "var(--rd-panel)",
        border: "1px solid var(--rd-border)",
        borderRadius: 6, padding: "12px 16px", marginBottom: 12,
      }}>
        <div style={{ fontSize: 10, letterSpacing: 0.5, textTransform: "uppercase",
                        fontWeight: 800, color: "var(--rd-muted)", marginBottom: 8 }}>
          Engine executions
        </div>
        {(ai?.executions || []).length === 0
          ? (
            <div style={{
              padding: 20, textAlign: "center",
              color: "var(--rd-muted)", fontSize: 12,
              border: "1px dashed var(--rd-border)", borderRadius: 4,
              background: "var(--rd-bg)",
            }}>
              NOT_RUN — per-engine execution provenance arrives with
              Phase 4 (xdr_observations + engine_executions).
              <div style={{ marginTop: 4, fontSize: 10.5, color: "var(--rd-faint)",
                             fontFamily: "var(--rs-mono)" }}>
                queue == projection · never runs an engine
              </div>
            </div>
          )
          : (
            <table className="rl-table" style={{ color: "var(--rd-text)" }}>
              <thead><tr style={{ background: "transparent" }}>
                <th style={{ color: "var(--rd-muted)" }}>Engine</th>
                <th style={{ color: "var(--rd-muted)" }}>Status</th>
                <th style={{ color: "var(--rd-muted)" }}>Duration</th>
                <th style={{ color: "var(--rd-muted)" }}>Started</th>
              </tr></thead>
              <tbody>
                {ai.executions.map((e, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: "var(--rd-purple)" }}>{e.engine}</td>
                    <td className="mono" style={{ color: toneFor(e.status).bd }}>{e.status}</td>
                    <td className="mono" style={{ color: "var(--rd-text-dim)" }}>
                      {e.duration_ms != null ? `${Math.round(e.duration_ms/100)/10}s` : "—"}
                    </td>
                    <td className="mono" style={{ color: "var(--rd-text-dim)" }}>
                      {e.started_at || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </div>
    </div>
  );
}
