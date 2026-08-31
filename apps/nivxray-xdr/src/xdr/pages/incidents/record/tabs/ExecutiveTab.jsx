/**
 * ExecutiveTab · Layer 3 · Owner + Manager oriented summary.
 *
 * Sources: `/api/incidents/:id/summary` (deterministic four-state
 * projection).  Never fabricates.
 *
 * §16 composition rules applied:
 *  · When the case has no verdict yet, render a designed truth
 *    state block ("Not yet investigated") — never a wall of
 *    "NOT_RUN / — / UNKNOWN / —" KPI cards.
 *  · Evidence gaps render as a grouped honest summary when every
 *    row is absent, and as a data table only when at least one
 *    row carries a substantive claim.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Loader2, ArrowRight, Search, Radio, AlertOctagon } from "lucide-react";
import { useSearchParams } from "react-router-dom";

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
  const [, setParams]         = useSearchParams();

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

  // A verdict is "produced" only when at least one substantive
  // stage-2 field has been computed.
  const verdictProduced = !!(v && (v.label || v.risk_score != null
                                     || v.confidence
                                     || v.contributing_signals != null));

  // Gaps are collapsed into a group summary when they contain no
  // substantive claim state.
  const gapSummary = useMemo(() => summarizeGaps(gaps), [gaps]);

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-executive-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      Loading summary…
    </div>
  );
  if (error) return <div className="rl-error" data-testid="xdr-record-executive-error">{String(error)}</div>;

  return (
    <div data-testid="xdr-record-executive">
      {/* Verdict block — designed truth state when not produced */}
      {verdictProduced
        ? <VerdictProducedBlock v={v} />
        : <VerdictPendingBlock
              onGoToAI={() => setParams((p) => {
                const n = new URLSearchParams(p);
                n.set("tab", "auto_investigation");
                return n;
              })}
              onGoToEvidence={() => setParams((p) => {
                const n = new URLSearchParams(p);
                n.set("tab", "evidence");
                return n;
              })}
          />}

      {/* Observed facts */}
      <div className="rl-section" data-testid="xdr-record-executive-observed">
        <div className="rl-section-title">Observed facts</div>
        {observed.length === 0
          ? <div className="rl-empty rl-empty-quiet">
              No observed facts yet.
              <span className="kbd">Facts appear here as engines produce evidence.</span>
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

      {/* Evidence gaps — grouped when honest-absence, table when substantive */}
      {gaps.length > 0 && (
        <div className="rl-section" data-testid="xdr-record-executive-gaps">
          <div className="rl-section-title">Evidence coverage</div>
          {gapSummary.substantive
            ? <table className="rl-table">
                <thead><tr><th>Claim</th><th>State</th><th>Searched</th><th>Reason</th></tr></thead>
                <tbody>
                  {gaps.map((g, i) => (
                    <tr key={i} data-testid={`xdr-record-executive-gap-${i}`}>
                      <td>{g.claim}</td>
                      <td><StateBadge s={g.state} /></td>
                      <td className="mono">{(g.searched || []).join(", ") || "—"}</td>
                      <td>{g.reason || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            : <GapSummaryBlock summary={gapSummary} />}
        </div>
      )}
    </div>
  );
}


/* ── Verdict blocks ──────────────────────────────────────────── */

function VerdictProducedBlock({ v }) {
  return (
    <div className="rl-section" data-testid="xdr-record-executive-verdict">
      <div className="rl-section-title">Deterministic verdict</div>
      <div className="rl-metric-grid">
        <Metric tone={verdictTone(v.label)}
                 k="Verdict"
                 v={v?.label ? String(v.label).toUpperCase() : "—"} />
        <Metric tone={riskTone(v.risk_score)}
                 k="Risk"
                 v={v?.risk_score != null ? `${v.risk_score}/100` : "—"} />
        <Metric tone={v?.confidence ? "info" : "na"}
                 k="Confidence"
                 v={v?.confidence ? String(v.confidence).toUpperCase() : "—"} />
        <Metric tone={v?.contributing_signals > 0 ? "ok" : "na"}
                 k="Signals"
                 v={v?.contributing_signals != null ? v.contributing_signals : "—"}
                 sub={v?.engine ? `engine ${v.engine}` : null} />
      </div>
    </div>
  );
}

function VerdictPendingBlock({ onGoToAI, onGoToEvidence }) {
  return (
    <div
      className="rl-verdict-pending"
      data-testid="xdr-record-executive-verdict-pending"
    >
      <div className="rl-verdict-pending-icon" aria-hidden="true">
        <Search size={18} />
      </div>
      <div className="rl-verdict-pending-body">
        <h4 className="rl-verdict-pending-title">Not yet investigated</h4>
        <p className="rl-verdict-pending-copy">
          No verdict has been produced for this incident yet — the
          Auto-Investigation and stage-2 correlation engines have
          not run against the case.  This is the honest state, not
          an error.
        </p>
        <div className="rl-verdict-pending-actions">
          <button
            type="button"
            className="rl-btn primary"
            onClick={onGoToAI}
            data-testid="xdr-record-executive-goto-ai"
          >
            <ArrowRight size={12} /> Open Auto-Investigation
          </button>
          <button
            type="button"
            className="rl-btn"
            onClick={onGoToEvidence}
            data-testid="xdr-record-executive-goto-evidence"
          >
            View evidence surfaces
          </button>
        </div>
      </div>
    </div>
  );
}


/* ── Gap summarisation ───────────────────────────────────────── */

function summarizeGaps(gaps) {
  const groups = { ok: 0, no_matching_evidence: 0, not_connected: 0,
                    not_available: 0, error: 0 };
  gaps.forEach(g => {
    const s = g.state || "not_available";
    if (groups[s] != null) groups[s] += 1; else groups.not_available += 1;
  });
  // A gap set is "substantive" if any row is OK or NO_MATCHING_EVIDENCE
  // — those are the states an analyst reads.  If everything is
  // NOT_CONNECTED / NOT_AVAILABLE, we collapse into a summary.
  const substantive = groups.ok > 0 || groups.no_matching_evidence > 0;
  return { ...groups, substantive, total: gaps.length };
}

function GapSummaryBlock({ summary }) {
  const rows = [
    { key: "not_connected",
      icon: <Radio size={14} />,
      label: "Telemetry surfaces not connected",
      count: summary.not_connected,
      copy: "These evidence surfaces are not connected for this tenant. Connect an integration to enable investigation coverage.",
    },
    { key: "not_available",
      icon: <AlertOctagon size={14} />,
      label: "Stage-2 correlations not computed",
      count: summary.not_available,
      copy: "Stage-2 correlations have not yet been computed for this incident.",
    },
    { key: "no_matching_evidence",
      icon: <Search size={14} />,
      label: "Searched, no matching evidence",
      count: summary.no_matching_evidence,
      copy: "Surfaces were searched but found nothing that matches this incident.",
    },
  ].filter(r => r.count > 0);

  return (
    <div className="rl-gap-summary" data-testid="xdr-record-executive-gap-summary">
      {rows.map(r => (
        <div key={r.key} className={`rl-gap-summary-row ${r.key}`}
                data-testid={`xdr-record-executive-gap-summary-${r.key}`}>
          <div className="rl-gap-summary-icon" aria-hidden="true">{r.icon}</div>
          <div className="rl-gap-summary-body">
            <div className="rl-gap-summary-label">
              {r.label}
              <span className="rl-gap-summary-count">{r.count}</span>
            </div>
            <div className="rl-gap-summary-copy">{r.copy}</div>
          </div>
        </div>
      ))}
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
