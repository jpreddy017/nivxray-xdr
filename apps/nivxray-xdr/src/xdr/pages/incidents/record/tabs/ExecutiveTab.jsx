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
import { Loader2, ArrowRight, Search, Radio, AlertOctagon, CheckCircle2, XCircle, ShieldAlert } from "lucide-react";
import { useSearchParams } from "react-router-dom";

import { getIncidentSummary } from "@/lib/incidentsApi";
import api from "@/lib/api";
import AnnotationsEditor from "../AnnotationsEditor";
import ThreatAssessmentCard from "../ThreatAssessmentCard";

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
  const [exec, setExec]       = useState(null);
  const [reload, setReload]   = useState(0);
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
    // Round 18.5 · pull the deterministic Executive Summary composer.
    // A separate request keeps the legacy 4-state gap projection intact.
    (async () => {
      try {
        const r = await api.get(
          `/admin/content-supply-chain/incidents/${incident.id}/executive-summary`);
        if (!cancelled) setExec(r.data);
      } catch { /* honest UI when composer is unavailable */ }
    })();
    return () => { cancelled = true; };
  }, [incident?.id, reload]);
  const refresh = () => setReload((n) => n + 1);

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
      {/* Round 34 · Threat Assessment · deterministic engine on top */}
      <ThreatAssessmentCard incidentId={incident?.id} />

      {/* Round 18.5 · Deterministic Executive Summary composer */}
      {exec && exec.state === "READY" && (
        <ExecutiveSummaryBlock exec={exec}
                                          incidentId={incident?.id}
                                          onAnnotationsChanged={refresh} />
      )}

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


/* ── Round 18.5 · Executive Summary block ─────────────────────
   Renders the deterministic composer output.  Frontend performs
   ZERO inference — every string comes verbatim from the backend
   composer.  Confirmed facts and insufficient-evidence lines are
   explicitly separated so the analyst reads the truth boundary. */

function ExecutiveSummaryBlock({ exec, incidentId, onAnnotationsChanged }) {
  const es      = exec.executive_summary || {};
  const tech    = exec.technical_summary || {};
  const supp    = exec.supporting_evidence || [];
  const conf    = exec.confirmed_facts || [];
  const insuff  = exec.insufficient_evidence || [];
  const anns    = exec.analyst_annotations || {};
  return (
    <div className="rl-section" data-testid="xdr-record-executive-composer">
      <div className="rl-section-title">
        <ShieldAlert size={12} style={{ marginRight: 6,
                                                        verticalAlign: -1 }} />
        Executive Summary
      </div>
      <p className="rl-exec-lead" data-testid="xdr-record-executive-lead"
          style={{ fontSize: 13.5, lineHeight: 1.55,
                        color: "var(--text)", margin: "6px 0 4px" }}>
        {es.lead}
      </p>
      <p style={{ fontSize: 11.5, color: "var(--text-dim)",
                        margin: "4px 0", fontFamily: "var(--mono)" }}
          data-testid="xdr-record-executive-confidence">
        {es.confidence_line}
      </p>
      <p style={{ fontSize: 12, color: "var(--text-dim)",
                        margin: "4px 0", lineHeight: 1.5 }}
          data-testid="xdr-record-executive-evidence-line">
        {es.evidence_line}
      </p>

      {/* Executive · analyst overlay */}
      {incidentId && (
        <AnnotationsEditor incidentId={incidentId} section="executive"
                                        annotations={anns.executive || []}
                                        defaultKind="finding"
                                        allowedKinds={["finding", "note"]}
                                        onChange={onAnnotationsChanged} />
      )}

      <div style={{ display: "grid",
                          gridTemplateColumns: "1fr 1fr",
                          gap: 12, marginTop: 10 }}>
        <div data-testid="xdr-record-executive-confirmed"
                  style={{ border: "1px solid var(--mint)",
                                  borderRadius: 3, padding: 8,
                                  background: "rgba(52,211,153,0.06)" }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                              color: "var(--mint)", fontWeight: 700,
                              marginBottom: 6, display: "flex",
                              alignItems: "center", gap: 4 }}>
            <CheckCircle2 size={11} /> CONFIRMED FACTS ({conf.length})
          </div>
          {conf.length
            ? <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5,
                                lineHeight: 1.5, color: "var(--text-dim)" }}>
                {conf.map((c, i) =>
                  <li key={i}
                        data-testid={`xdr-record-executive-confirmed-${i}`}>
                    {c}
                  </li>)}
              </ul>
            : <div style={{ fontSize: 11, color: "var(--faint)" }}>
                No fact has been confirmed yet.
              </div>}
        </div>
        <div data-testid="xdr-record-executive-insufficient"
                  style={{ border: "1px solid var(--amber)",
                                  borderRadius: 3, padding: 8,
                                  background: "rgba(245,158,11,0.06)" }}>
          <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                              color: "var(--amber)", fontWeight: 700,
                              marginBottom: 6, display: "flex",
                              alignItems: "center", gap: 4 }}>
            <XCircle size={11} /> INSUFFICIENT EVIDENCE ({insuff.length})
          </div>
          {insuff.length
            ? <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11.5,
                                lineHeight: 1.5, color: "var(--text-dim)" }}>
                {insuff.map((c, i) =>
                  <li key={i}
                        data-testid={`xdr-record-executive-insufficient-${i}`}>
                    {c}
                  </li>)}
              </ul>
            : <div style={{ fontSize: 11, color: "var(--faint)" }}>
                No evidence gaps remain.
              </div>}
        </div>
      </div>

      <details style={{ marginTop: 12 }}
                    data-testid="xdr-record-executive-technical">
        <summary style={{ cursor: "pointer",
                                    fontFamily: "var(--mono)", fontSize: 10.5,
                                    color: "var(--text-dim)" }}>
          Technical Summary (machine-derived · {Object.keys(tech).length} fields)
        </summary>
        <div style={{ marginTop: 6, fontFamily: "var(--mono)",
                              fontSize: 10.5, color: "var(--text-dim)" }}>
          {Object.entries(tech).map(([k, v]) => (
            <div key={k} style={{ display: "grid",
                                                    gridTemplateColumns: "220px 1fr",
                                                    gap: 8,
                                                    padding: "2px 0",
                                                    borderBottom:
                                                      "1px dashed rgba(255,255,255,0.05)" }}>
              <span style={{ color: "var(--faint)" }}>{k}</span>
              <span>
                {v == null ? "—"
                    : typeof v === "object" ? JSON.stringify(v)
                    : String(v)}
              </span>
            </div>
          ))}
        </div>
        {incidentId && (
          <AnnotationsEditor incidentId={incidentId} section="technical"
                                          annotations={anns.technical || []}
                                          defaultKind="override"
                                          allowedKinds={["override", "note"]}
                                          onChange={onAnnotationsChanged}
                                          compact={true} />
        )}
      </details>

      <details style={{ marginTop: 8 }}
                    data-testid="xdr-record-executive-support">
        <summary style={{ cursor: "pointer",
                                    fontFamily: "var(--mono)", fontSize: 10.5,
                                    color: "var(--text-dim)" }}>
          Supporting Evidence ({supp.length})
        </summary>
        <div style={{ marginTop: 6 }}>
          {supp.length === 0 && (
            <div style={{ fontSize: 11, color: "var(--faint)" }}>
              No supporting evidence has been captured yet.
            </div>
          )}
          {supp.map((f, i) => (
            <div key={i}
                    data-testid={`xdr-record-executive-supp-${i}`}
                    style={{ padding: "4px 0",
                                    borderBottom:
                                      "1px dashed rgba(255,255,255,0.05)" }}>
              <div style={{ fontSize: 11.5, color: "var(--text)" }}>
                {f.claim}
              </div>
              <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                                    color: "var(--faint)" }}>
                {f.source}{f.evidence_id ? ` · evidence=${f.evidence_id}` : ""}
                {f.interpretation ? ` · ${f.interpretation}` : ""}
              </div>
            </div>
          ))}
        </div>
        {incidentId && (
          <AnnotationsEditor incidentId={incidentId}
                                          section="supporting_evidence"
                                          annotations={anns.supporting_evidence || []}
                                          defaultKind="finding"
                                          allowedKinds={["finding", "note"]}
                                          onChange={onAnnotationsChanged}
                                          compact={true} />
        )}
      </details>
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
