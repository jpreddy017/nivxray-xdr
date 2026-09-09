/**
 * Investigation Completeness Panel — deterministic gap surface.
 *
 * Consumes:
 *   · incident   (canonical payload)
 *   · executions (Response Engine — /api/xdr/incidents/:id/response-executions)
 *   · verdict    (`/api/verdict/stage2/compute`)
 *   · summary    (`/api/incidents/:id/summary`)
 *
 * Every facet is scored deterministically.  When a facet has NO
 * evidence, the row shows honestly as MISSING with source=missing.
 * No fabrication.
 */
import React, { useEffect, useState } from "react";
import { CheckCircle2, Circle, AlertTriangle, RefreshCw } from "lucide-react";

import api from "@/lib/api";
import { VerdictConsumer } from "@/xdr/adopt/baseCapabilities";
import { ReportConsumer } from "@/xdr/adopt/baseCapabilities";
import { computeCompleteness } from "@/xdr/investigation/completeness";


export default function XdrCompletenessPanel({ incident }) {
  const [state, setState] = useState({ loading: true, result: null });
  const [refresh, setR]   = useState(0);

  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    (async () => {
      setState({ loading: true, result: null });
      const [v, s, execs] = await Promise.all([
        VerdictConsumer.fetch({ incident_id: incident.id }).catch(() => null),
        ReportConsumer.summary(incident.id).catch(() => null),
        _fetchExecs(incident.id),
      ]);
      const result = computeCompleteness({
        incident,
        verdict:   v?.ok ? v.data : null,
        summary:   s?.ok ? s.data : null,
        executions: execs || [],
      });
      if (!cancelled) setState({ loading: false, result });
    })();
    return () => { cancelled = true; };
  }, [incident?.id, refresh]);

  const r = state.result;
  return (
    <div className="panel" data-testid="xdr-completeness-panel"
            style={{ padding: 12, marginTop: 12 }}>
      <div className="section-title" style={{ marginBottom: 6,
                                                            display: "flex", alignItems: "center", gap: 6 }}>
        <AlertTriangle size={12} /> Investigation Completeness
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
          · deterministic gap checker
        </span>
        <span style={{ flex: 1 }} />
        {r && (
          <span className="mono" data-testid="xdr-completeness-score"
                    style={{ fontSize: 11, color: _color(r.score) }}>
            {(r.score * 100).toFixed(0)}%
          </span>
        )}
        <button className="btn ghost" onClick={() => setR((n) => n + 1)}
                  data-testid="xdr-completeness-refresh"
                  style={{ padding: "2px 8px", fontSize: 10, marginLeft: 8 }}>
          <RefreshCw size={10} /> Refresh
        </button>
      </div>

      {state.loading && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          Computing completeness…
        </div>
      )}
      {r && (
        <div>
          <div style={{ display: "grid",
                            gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))",
                            gap: 4 }}>
            {r.facets.map((f) => (
              <div key={f.key}
                      data-testid={`xdr-completeness-facet-${f.key}`}
                      style={{ padding: 6, borderRadius: 3,
                                  border: "1px solid var(--border)",
                                  background: "var(--panel2)",
                                  display: "flex", alignItems: "center", gap: 6 }}>
                {f.present ? (f.partial
                    ? <AlertTriangle size={11} style={{ color: "var(--amber)" }} />
                    : <CheckCircle2  size={11} style={{ color: "var(--mint)" }} />)
                  : <Circle       size={11} style={{ color: "var(--faint)" }} />}
                <span style={{ fontSize: 11, color: "var(--text-dim)",
                                  flex: 1 }}>
                  {f.label}
                </span>
                <span className="mono" style={{ fontSize: 9.5,
                                                              color: f.present
                                                                ? (f.partial ? "var(--amber)" : "var(--mint)")
                                                                : "var(--faint)" }}>
                  {f.present ? (f.partial ? "PARTIAL" : "OK") : "MISSING"}
                </span>
              </div>
            ))}
          </div>
          {r.missing.length > 0 && (
            <div style={{ marginTop: 8, fontSize: 10.5,
                              color: "var(--amber)",
                              fontFamily: "var(--mono)" }}>
              Missing facets: {r.missing.join(", ")}
            </div>
          )}
          <div style={{ marginTop: 6, fontSize: 10, color: "var(--faint)",
                            fontFamily: "var(--mono)" }}>
            score = present + 0.5·partial ÷ total ·
            {r.complete ? " INVESTIGATION COMPLETE"
                                : " INVESTIGATION INCOMPLETE — closure blocked"}
          </div>
        </div>
      )}
    </div>
  );
}


function _color(score) {
  if (score >= 0.9) return "var(--mint)";
  if (score >= 0.6) return "var(--amber)";
  return "#f87171";
}

async function _fetchExecs(incidentId) {
  try {
    const r = await api.get(
      `/api/xdr/incidents/${encodeURIComponent(incidentId)}/response-executions`);
    return r?.data?.executions || r?.data?.rows || r?.data || [];
  } catch { return []; }
}
