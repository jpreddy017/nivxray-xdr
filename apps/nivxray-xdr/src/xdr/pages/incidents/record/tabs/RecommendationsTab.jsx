/**
 * RecommendationsTab · Layer 3 v2 · light-first analyst actions.
 *
 * Reads response executions from the existing endpoint
 *   /api/xdr/incidents/:id/response-executions
 * and derives light recommendations from evidence gaps + verdict.
 * Never invents recommendations — if no gaps exist and no response
 * is required, the tab renders an honest empty state.
 */
import React, { useEffect, useState } from "react";
import { CheckCircle2, ShieldAlert, Zap, Loader2 } from "lucide-react";

import { getIncidentSummary } from "@/lib/incidentsApi";
import api from "@/lib/api";

const PRIO_LABEL = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW" };

function classifyGap(g) {
  // Turn a evidence-gap row into a semantic priority.
  const s = String(g?.state || "").toLowerCase();
  if (s === "error")                     return "critical";
  if (s === "no_matching_evidence")      return "high";
  if (s === "not_available")             return "medium";
  return "low";
}

function actionForGap(g) {
  // Map claim → recommended action verb.
  const c = String(g?.claim || "").toLowerCase();
  if (c.includes("lateral"))           return "Enumerate lateral-movement telemetry sources and confirm collection is active.";
  if (c.includes("exfil"))             return "Correlate outbound traffic and DNS beacons to validate no exfiltration occurred.";
  if (c.includes("rule"))              return "Run the stage-2 rule engine and re-project verdict + risk once evidence lands.";
  if (c.includes("ndr") || c.includes("network"))  return "Confirm the NDR integration is enrolled for this tenant.";
  if (c.includes("itdr") || c.includes("identity")) return "Configure the identity threat detection connector to close this gap.";
  if (c.includes("email"))             return "Enable the email security integration to project delivery-time evidence.";
  if (c.includes("cloud"))             return "Enable the cloud audit connector for this workload.";
  return "Investigate and provide evidence to close this gap.";
}

export default function RecommendationsTab({ incident }) {
  const [summary, setSummary] = useState(null);
  const [execs, setExecs]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const [sum, ex] = await Promise.all([
          getIncidentSummary(incident.id).catch(() => null),
          api.get(`/xdr/incidents/${encodeURIComponent(incident.id)}/response-executions`)
              .then(r => r.data).catch(() => ({ executions: [] })),
        ]);
        if (!cancelled) { setSummary(sum); setExecs(ex); }
      } catch (e) {
        if (!cancelled) setError(e?.message || "Failed to load recommendations.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  if (loading) return (
    <div className="rl-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING RECOMMENDATIONS…
    </div>
  );
  if (error) return <div className="rl-error">{String(error)}</div>;

  const gaps = summary?.evidence_gaps || [];
  const openGaps = gaps.filter(g => String(g.state).toLowerCase() !== "ok");
  const executions = execs?.executions || [];

  // Build honest, evidence-derived recommendation list.
  const recos = [];
  for (const g of openGaps) {
    recos.push({
      priority: classifyGap(g),
      title:    `Close evidence gap · ${g.claim || "Untitled claim"}`,
      body:     g.reason || "Missing evidence prevents deterministic conclusion.",
      basis:    `Evidence Gap · ${String(g.state).toUpperCase()} · searched ${(g.searched || []).join(", ") || "—"}`,
      action:   actionForGap(g),
    });
  }

  return (
    <div data-testid="xdr-record-recommendations">
      <div className="rl-metric-grid" style={{ marginBottom: 12 }}>
        <div className="rl-metric amber">
          <div className="k">Open gaps</div>
          <div className="v">{openGaps.length}</div>
          <div className="sub">actionable now</div>
        </div>
        <div className="rl-metric ok">
          <div className="k">Response actions</div>
          <div className="v">{executions.length}</div>
          <div className="sub">executed against this incident</div>
        </div>
        <div className="rl-metric info">
          <div className="k">Total claims</div>
          <div className="v">{gaps.length}</div>
          <div className="sub">evaluated by completeness engine</div>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Analyst recommendations</div>
        {recos.length === 0
          ? <div className="rl-empty">
              <CheckCircle2 size={18} style={{ marginBottom: 6, color: "var(--rl-green)" }} />
              <div>NO OPEN RECOMMENDATIONS — every evaluated claim is
                    either OK or NOT_CONNECTED (integration-level).</div>
            </div>
          : recos.map((r, i) => (
              <div key={i} className="rl-reco"
                    data-testid={`xdr-record-reco-${i}`}>
                <span className={`rl-reco-prio ${r.priority}`}
                        data-testid={`xdr-record-reco-prio-${i}`}>
                  {PRIO_LABEL[r.priority]}
                </span>
                <div className="rl-reco-body">
                  <h5>{r.title}</h5>
                  <p>{r.body}</p>
                  <p style={{ marginTop: 6 }}>
                    <ShieldAlert size={11} color="var(--rl-orange)"
                                    style={{ display: "inline",
                                             verticalAlign: "-2px",
                                             marginRight: 4 }} />
                    <strong>Action:</strong> {r.action}
                  </p>
                  <div className="rl-reco-basis">{r.basis}</div>
                </div>
                <div className="rl-reco-action">
                  <button type="button" className="rl-btn"
                          data-testid={`xdr-record-reco-open-${i}`}
                          disabled>
                    <Zap size={11} /> Open playbook
                  </button>
                </div>
              </div>
            ))}
      </div>

      {executions.length > 0 && (
        <div className="rl-section" data-testid="xdr-record-reco-executions">
          <div className="rl-section-title">Response executions</div>
          <table className="rl-table">
            <thead><tr>
              <th>Playbook</th><th>Status</th><th>Started</th><th>Notes</th>
            </tr></thead>
            <tbody>
              {executions.map((e, i) => (
                <tr key={i}>
                  <td className="mono">{e.playbook_id || e.name || "—"}</td>
                  <td className="mono">{String(e.status || "—").toUpperCase()}</td>
                  <td className="mono">{(e.started_at || e.created_at || "—").slice(0, 16).replace("T", " ")}</td>
                  <td>{e.note || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--rl-faint)",
                      fontFamily: "var(--rs-mono)", letterSpacing: 0.2 }}>
        Recommendations derived from evidence gaps + response
        executions · never fabricated.
      </div>
    </div>
  );
}
