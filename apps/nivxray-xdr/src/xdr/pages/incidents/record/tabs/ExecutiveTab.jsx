/**
 * ExecutiveTab · Layer 3 · Owner + Manager oriented summary.
 *
 * Sources: `/api/incidents/:id/summary` (deterministic four-state
 * projection).  Renders verdict, risk, contributing signals, observed
 * facts, evidence-gap counts.  Never fabricates.
 */
import React, { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import { getIncidentSummary } from "@/lib/incidentsApi";

const STATE_BADGE = {
  ok:                    { label: "OK",                    cls: "ok"     },
  no_matching_evidence:  { label: "NO MATCHING EVIDENCE",  cls: "miss"   },
  not_connected:         { label: "NOT CONNECTED",         cls: "discon" },
  not_available:         { label: "NOT AVAILABLE",         cls: "na"     },
  error:                 { label: "ERROR",                 cls: "err"    },
};

const StateBadge = ({ s }) => {
  const v = STATE_BADGE[s] || STATE_BADGE.not_available;
  return <span className={`rl-state ${v.cls}`}>{v.label}</span>;
};

export default function ExecutiveTab({ incident }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await getIncidentSummary(incident.id);
        if (!cancelled) setSummary(data);
      } catch (e) {
        if (!cancelled)
          setError(e?.response?.data?.detail || e?.message || "Failed to load summary.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const v = summary?.deterministic_verdict || null;
  const observed = summary?.observed_facts || [];
  const gaps = summary?.evidence_gaps || [];

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-executive-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING SUMMARY…
    </div>
  );
  if (error) return <div className="rl-error" data-testid="xdr-record-executive-error">{String(error)}</div>;

  return (
    <div data-testid="xdr-record-executive">
      {/* Verdict + Risk metrics */}
      <div className="rl-section">
        <div className="rl-section-title">Deterministic verdict</div>
        <div className="rl-metric-grid" data-testid="xdr-record-executive-verdict">
          <Metric tone={v ? verdictTone(v.label) : "na"}
                   k="Verdict"
                   v={v?.label ? String(v.label).toUpperCase() : "UNKNOWN"} />
          <Metric tone={v ? riskTone(v.risk_score) : "na"}
                   k="Risk"
                   v={v?.risk_score != null ? `${v.risk_score}/100` : "—"} />
          <Metric tone={v ? "info" : "na"}
                   k="Confidence"
                   v={v?.confidence ? String(v.confidence).toUpperCase() : "NOT_RUN"} />
          <Metric tone={v?.contributing_signals > 0 ? "ok" : "na"}
                   k="Signals"
                   v={v?.contributing_signals != null ? v.contributing_signals : "—"}
                   sub={v?.engine ? `engine ${v.engine}` : null} />
        </div>
      </div>

      {/* Observed facts */}
      <div className="rl-section" data-testid="xdr-record-executive-observed">
        <div className="rl-section-title">Observed facts</div>
        {observed.length === 0
          ? <div className="rl-empty">
              NO MATCHING EVIDENCE — no observed facts on the case yet.
              <span className="kbd">Facts appear as engines produce evidence.</span>
            </div>
          : <ul className="rl-list">
              {observed.map((f, i) => (
                <li key={i} data-testid={`xdr-record-executive-fact-${i}`}>
                  {f.fact}
                  {f.provenance && <span className="prov">· {f.provenance}</span>}
                </li>
              ))}
            </ul>}
      </div>

      {/* Evidence gaps */}
      <div className="rl-section" data-testid="xdr-record-executive-gaps">
        <div className="rl-section-title">Evidence gaps · negative explainability</div>
        {gaps.length === 0
          ? <div className="rl-empty">
              NO GAPS COMPUTED — the completeness engine has not yet
              scored this case.
            </div>
          : <table className="rl-table">
              <thead><tr><th>Claim</th><th>State</th><th>Searched</th><th>Reason</th></tr></thead>
              <tbody>
                {gaps.map((g, i) => (
                  <tr key={i} data-testid={`xdr-record-executive-gap-${i}`}>
                    <td>{g.claim}</td>
                    <td><StateBadge s={g.state} /></td>
                    <td className="mono">{(g.searched || []).join(", ") || "—"}</td>
                    <td className="mono">{g.reason || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>}
      </div>
    </div>
  );
}

function Metric({ k, v, sub, tone = "info" }) {
  return (
    <div className={`rl-metric ${tone}`}>
      <div className="k">{k}</div>
      <div className="v">{v}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}

function verdictTone(label) {
  const l = String(label || "").toLowerCase();
  if (l === "malicious")  return "crit";
  if (l === "suspicious") return "high";
  if (l === "benign")     return "ok";
  return "na";
}
function riskTone(risk) {
  if (risk == null) return "na";
  if (risk >= 80) return "crit";
  if (risk >= 50) return "high";
  if (risk >= 20) return "amber";
  return "ok";
}
