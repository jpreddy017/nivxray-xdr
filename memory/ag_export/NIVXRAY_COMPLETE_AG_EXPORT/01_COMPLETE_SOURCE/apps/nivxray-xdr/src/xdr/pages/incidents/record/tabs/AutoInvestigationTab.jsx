/**
 * InvestigationActivityTab · Round 31 · Autonomous Investigator feed.
 *
 * Reads the deterministic Round 31 state from
 * `GET /api/incidents/{id}/investigation`.  No "Auto-Investigate"
 * button anywhere — the tab communicates STATE, not activation
 * (§13, §16, §18 of AUTONOMOUS_INVESTIGATION.md).
 *
 * The feed answers §10's six questions per entry:
 *   WHAT · WHY · EVIDENCE · CAPABILITY · RESULT · NEXT
 */
import React, { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";
import IntelligenceOverlayEditor from "@/xdr/components/IntelligenceOverlayEditor";

const STATE_STYLE = {
  WAITING_FOR_EVIDENCE:   { key: "waiting",       label: "WAITING FOR EVIDENCE" },
  UNDERSTANDING_EVIDENCE: { key: "understanding", label: "UNDERSTANDING EVIDENCE" },
  INVESTIGATING:          { key: "investigating", label: "INVESTIGATING" },
  EXPANDING:              { key: "investigating", label: "EXPANDING" },
  WAITING_FOR_CAPABILITY: { key: "waiting",       label: "WAITING FOR CAPABILITY" },
  CONVERGING:             { key: "converging",    label: "CONVERGING" },
  CONVERGED:              { key: "converging",    label: "CONVERGED" },
  REOPENED:               { key: "investigating", label: "REOPENED" },
  FAILED:                 { key: "failed",        label: "FAILED" },
};


function fmtTime(iso) {
  if (!iso) return "—";
  const s = String(iso);
  return s.slice(11, 19); // HH:MM:SS
}

function fmtDate(iso) {
  if (!iso) return "—";
  return String(iso).slice(0, 16).replace("T", " ");
}


export default function AutoInvestigationTab({ incident }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  // Round 46 · overlay index keyed by `finding:{finding_id}:summary`
  const [overlays, setOverlays] = useState({});

  const overlayKey = (fid) => `finding:${fid}:summary`;
  const applyOverlayResult = (fid, overlay) =>
    setOverlays((prev) => ({ ...prev, [overlayKey(fid)]: overlay }));

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const [inv, ovr] = await Promise.all([
          api.get(`/incidents/${incident.id}/investigation`),
          api.get(`/incidents/${incident.id}/intelligence/overlays`)
              .catch(() => ({ data: { overlays: [] } })),
        ]);
        if (cancelled) return;
        setData(inv.data);
        const idx = {};
        for (const o of (ovr.data?.overlays || [])) {
          if (o.target_kind === "finding" && o.field_key === "summary") {
            idx[overlayKey(o.target_id)] = o;
          }
        }
        setOverlays(idx);
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e));
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const style = useMemo(() => {
    return STATE_STYLE[(data?.state || "WAITING_FOR_EVIDENCE").toUpperCase()]
              || STATE_STYLE.WAITING_FOR_EVIDENCE;
  }, [data?.state]);

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-ai-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING INVESTIGATION ACTIVITY…
    </div>
  );

  const counts = data?.counts || {};
  const activity = data?.activity || [];
  const executions = data?.executions || [];
  const findings = data?.findings || [];

  const explain = {
    waiting:       "NivXRay XDR is waiting on evidence eligible for autonomous investigation. Investigation will begin automatically when the ingestion pipeline surfaces a governed trigger.",
    understanding: "NivXRay XDR is consuming the Investigation Understanding Engine artifacts for this incident.",
    investigating: `NivXRay XDR is investigating this incident · ${counts.planned || 0} pivots planned · ${counts.executed || 0} executed.`,
    converging:    `NivXRay XDR converged the investigation · ${counts.executed || 0} capabilities ran · ${counts.findings || 0} finding${counts.findings === 1 ? "" : "s"}.`,
    failed:        "The autonomous investigation encountered an unrecoverable state transition.",
  }[style.key];

  return (
    <div data-testid="xdr-record-auto-investigation">
      {error && <div className="rl-error">{String(error)}</div>}

      <div className={`rl-ai-status ${style.key}`}
            data-testid="xdr-record-ai-status-card">
        <div className="badge">
          <span data-testid="xdr-record-ai-status">● {style.label}</span>
        </div>
        <div className="txt">
          <h5>Investigation Activity</h5>
          <p>{explain}</p>
        </div>
      </div>

      <div className="rl-metric-grid" style={{ marginBottom: 12 }}>
        <div className={`rl-metric ${counts.planned > 0 ? "info" : "na"}`}
              data-testid="xdr-record-ai-metric-planned">
          <div className="k">Pivots planned</div>
          <div className="v">{counts.planned ?? "—"}</div>
          <div className="sub">from IUE gaps</div>
        </div>
        <div className={`rl-metric ${counts.executed > 0 ? "ok" : "na"}`}
              data-testid="xdr-record-ai-metric-executed">
          <div className="k">Executed</div>
          <div className="v">{counts.executed ?? "—"}</div>
          <div className="sub">real capability runs</div>
        </div>
        <div className={`rl-metric ${counts.skipped > 0 ? "amber" : "na"}`}
              data-testid="xdr-record-ai-metric-skipped">
          <div className="k">Skipped</div>
          <div className="v">{counts.skipped ?? "—"}</div>
          <div className="sub">cap-unavailable · Round 32</div>
        </div>
        <div className={`rl-metric ${counts.findings > 0 ? "info" : "na"}`}
              data-testid="xdr-record-ai-metric-findings">
          <div className="k">Findings</div>
          <div className="v">{counts.findings ?? "—"}</div>
          <div className="sub">evidence-anchored</div>
        </div>
      </div>

      <div className="rl-section">
        <div className="rl-section-title">Investigation Activity feed</div>
        {activity.length === 0
          ? <div className="rl-empty" data-testid="xdr-record-ai-empty">
              <b>No investigation activity yet.</b> Per the NivXRay XDR
              Autonomous Investigation Operating Model, investigation
              begins automatically when the ingestion pipeline surfaces
              a governed trigger.  There is no "Auto-Investigate"
              button.
            </div>
          : <table className="rl-table" data-testid="xdr-record-ai-activity-table">
              <thead><tr>
                <th style={{ width: 60 }}>Time</th>
                <th style={{ width: 92 }}>Kind</th>
                <th>What / Why</th>
                <th style={{ width: 160 }}>Capability</th>
                <th style={{ width: 160 }}>Result</th>
              </tr></thead>
              <tbody>
                {activity.map((a, i) => (
                  <tr key={i} data-testid={`xdr-record-ai-activity-${i}`}>
                    <td className="mono">{fmtTime(a.at)}</td>
                    <td className="mono" style={{ color: "var(--rl-purple)" }}>{a.kind}</td>
                    <td>
                      <div style={{ fontWeight: 500 }}>{a.what}</div>
                      <div style={{ opacity: 0.7, fontSize: 12 }}>{a.why}</div>
                      {a.evidence_refs && a.evidence_refs.length > 0 && (
                        <div style={{ opacity: 0.6, fontSize: 11, marginTop: 2 }}>
                          Evidence: {a.evidence_refs.slice(0, 3).join(", ")}
                          {a.evidence_refs.length > 3 && ` +${a.evidence_refs.length - 3} more`}
                        </div>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {a.capability || "—"}
                    </td>
                    <td className="mono" style={{ fontSize: 12 }}>
                      {a.result || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>}
      </div>

      {executions.length > 0 && (
        <div className="rl-section" style={{ marginTop: 16 }}>
          <div className="rl-section-title">Engine executions · provenance</div>
          <table className="rl-table" data-testid="xdr-record-ai-exec-table">
            <thead><tr>
              <th>Capability</th>
              <th>Engine</th>
              <th>Status</th>
              <th>Duration</th>
              <th>Findings</th>
              <th>Started</th>
            </tr></thead>
            <tbody>
              {executions.map((e, i) => (
                <tr key={i} data-testid={`xdr-record-ai-exec-${i}`}>
                  <td className="mono">{e.capability}</td>
                  <td className="mono" style={{ color: "var(--rl-purple)", fontSize: 11 }}>
                    {e.engine}
                  </td>
                  <td className="mono">{String(e.status || "—").toUpperCase()}</td>
                  <td className="mono">{e.duration_ms != null ? `${e.duration_ms}ms` : "—"}</td>
                  <td className="mono">{(e.finding_ids || []).length}</td>
                  <td className="mono">{fmtDate(e.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {findings.length > 0 && (
        <div className="rl-section" style={{ marginTop: 16 }}>
          <div className="rl-section-title">Findings</div>
          <table className="rl-table" data-testid="xdr-record-ai-findings-table">
            <thead><tr>
              <th style={{ width: 140 }}>Capability</th>
              <th>Summary</th>
              <th style={{ width: 120 }}>State</th>
              <th style={{ width: 100 }}>Confidence</th>
            </tr></thead>
            <tbody>
              {findings.map((f, i) => {
                // Round 40 · Sparse-finding empty-state polish.
                // A CONVERGED→REOPENED tick may persist findings whose
                // summary is empty because the capability produced a
                // machine-signal without a natural sentence.  Fall
                // back to kind · subject so the row is never blank,
                // never fabricated.
                const rawSummary = (f.summary || "").trim();
                const rawReason  = (f.reasoning || "").trim();
                const subjectId  = f.subject_kind && f.subject_value
                  ? `${f.subject_kind}:${f.subject_value}` : null;
                const summaryIsEmpty = !rawSummary;
                const reasonIsEmpty  = !rawReason;
                const fallbackTitle = subjectId
                  ? `${f.kind || "signal"} · ${subjectId}`
                  : (f.kind || "signal");
                const confidenceLabel = (f.confidence === null
                                                    || f.confidence === undefined
                                                    || f.confidence === 0)
                  ? "—" : f.confidence;
                const overlay = f.finding_id
                  ? overlays[overlayKey(f.finding_id)] : null;
                const effective = overlay?.analyst_value ?? rawSummary;
                return (
                  <tr key={f.finding_id || i}
                       data-testid={`xdr-record-ai-finding-${i}`}
                       data-empty-summary={summaryIsEmpty || undefined}>
                    <td className="mono">{f.capability || "—"}</td>
                    <td>
                      {summaryIsEmpty && !overlay ? (
                        <div style={{ fontWeight: 500, color: "#64748b",
                                          fontStyle: "italic" }}
                              data-testid={`xdr-record-ai-finding-empty-${i}`}
                              title="This finding was persisted without a natural summary sentence; identity derived from kind + subject.">
                          {fallbackTitle}
                        </div>
                      ) : (
                        <div style={{ fontWeight: 500 }}>
                          {effective || fallbackTitle}
                        </div>
                      )}
                      <div style={{ opacity: 0.6, fontSize: 11, marginTop: 2 }}>
                        {reasonIsEmpty
                          ? <span style={{ fontStyle: "italic" }}>
                              reasoning not recorded
                            </span>
                          : rawReason}
                      </div>
                      {/* Round 46 · Analyst Interpretation overlay.
                          Editable narrative ONLY — the finding's
                          identity, evidence refs, confidence and
                          ATT&CK mapping stay immutable. */}
                      {f.finding_id && (
                        <IntelligenceOverlayEditor
                          incidentId={incident.id}
                          targetKind="finding"
                          targetId={f.finding_id}
                          fieldKey="summary"
                          machineValue={rawSummary || fallbackTitle}
                          overlay={overlay}
                          onChange={(o) =>
                            applyOverlayResult(f.finding_id, o)}
                          label="Analyst Interpretation"
                        />
                      )}
                    </td>
                    <td className="mono">{f.state || "—"}</td>
                    <td className="mono">{confidenceLabel}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
