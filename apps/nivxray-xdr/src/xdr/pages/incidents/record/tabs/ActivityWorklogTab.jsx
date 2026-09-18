/**
 * Activity · the investigation operational event table.
 *
 * Summary first → table for operations → flyout for context → evidence
 * for proof → technical details on demand.
 *
 * ONE dense row per operational event (the analyst reads 40 events in a
 * viewport, not four). Everything that used to be printed as three lines
 * of prose per event now lives in the expanded row: what happened, why,
 * capability, result, confidence, evidence references, timestamps and the
 * raw engine record.
 *
 * Sources (authoritative, unchanged):
 *   · `GET /api/incidents/{id}/investigation` → activity[] · executions[] · counts
 *   · `incident.state_history` → analyst lifecycle transitions
 *
 * Result enums are TRANSLATED for the analyst (`SKIPPED_OUT_OF_SCOPE` →
 * "Skipped · Out of scope") and the exact value is preserved on the row
 * detail. Evidence ids are pivots, not dead text.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Search } from "lucide-react";

import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue,
  ABSENCE, fmtTime,
} from "@/xdr/nx";

/** Engine kind → analyst type. The raw kind stays on the row. */
const TYPE_OF = {
  LIFECYCLE: "Lifecycle", FINDING: "Finding", EXECUTION: "Execution",
  PIVOT_PLANNED: "Pivot", SKIPPED: "Skipped", ERROR: "Error",
  FAILED: "Error",
};

const QUICK = [
  { key: "Finding", label: "Findings" },
  { key: "Execution", label: "Executions" },
  { key: "Pivot", label: "Pivots" },
  { key: "Skipped", label: "Skipped" },
  { key: "Lifecycle", label: "Lifecycle" },
  { key: "Error", label: "Errors" },
];

/** Raw result enum → analyst text. Never guesses: an unknown value is
 *  title-cased and kept verbatim in the detail. */
function resultText(raw) {
  if (!raw) return null;
  const v = String(raw);
  const known = {
    SKIPPED_OUT_OF_SCOPE: "Skipped · Out of scope",
    NOT_RUN: "Not run",
    OK: "OK",
  };
  if (known[v]) return known[v];
  const m = v.match(/^OBSERVED\s*·?\s*confidence\s*(\d+)/i);
  if (m) return `Observed · ${m[1]}% confidence`;
  if (/^OBSERVED/i.test(v)) return "Observed";
  if (/^SKIPPED/i.test(v)) return `Skipped · ${v.replace(/^SKIPPED[_\s·]*/i, "")
    .replace(/_/g, " ").toLowerCase() || "reason not recorded"}`;
  if (/^(FAILED|ERROR)/i.test(v)) return `Failed · ${v.replace(/^[A-Z_]+[_\s·]*/, "")
    .replace(/_/g, " ").toLowerCase() || "reason not recorded"}`;
  if (/^OK\b/i.test(v)) return v.replace(/finding\(s\)/i, "finding(s)");
  return v.replace(/_/g, " ");
}

function confidenceOf(a) {
  if (a?.confidence != null) return a.confidence;
  const m = String(a?.result || "").match(/confidence\s*(\d+)/i);
  return m ? Number(m[1]) : null;
}

const EVIDENCE_RE = /cev_[a-z0-9_]+/i;

export default function ActivityWorklogTab({ incident, onNavigateTab }) {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [types, setTypes] = useState([]);
  const [capability, setCapability] = useState("");
  const [q, setQ] = useState("");

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setLoading(true); setError(null);
    api.get(`/incidents/${encodeURIComponent(incident.id)}/investigation`)
      .then(({ data: d }) => { if (live) setData(d); })
      .catch((e) => {
        const d = e?.response?.data?.detail;
        if (live) setError(typeof d === "object"
          ? (d.reason || d.error || JSON.stringify(d))
          : (d || e?.message || "unavailable"));
      })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [incident?.id]);

  const rows = useMemo(() => {
    const out = [];
    (data?.activity || []).forEach((a, i) => {
      const refs = a.evidence_refs || [];
      out.push({
        id: `e${i}`,
        at: a.at,
        type: TYPE_OF[String(a.kind || "").toUpperCase()]
          || String(a.kind || "Event").replace(/_/g, " "),
        rawKind: a.kind,
        activity: a.what,
        why: a.why,
        capability: a.capability || null,
        rawResult: a.result || null,
        result: resultText(a.result),
        confidence: confidenceOf(a),
        evidence: refs,
        source: a.source || a.actor
          || (String(a.kind).toUpperCase() === "LIFECYCLE" ? "XDR" : "Investigator"),
        raw: a,
      });
    });
    (incident?.state_history || []).forEach((h, i) => out.push({
      id: `l${i}`, at: h.at || h.ts, type: "Lifecycle", rawKind: "STATE_HISTORY",
      activity: `Incident moved ${h.from || "—"} → ${h.to || "—"}`,
      why: h.note || h.reason || null, capability: null,
      rawResult: "APPLIED", result: "Applied", confidence: null,
      evidence: [], source: h.by || h.actor || "Analyst", raw: h,
    }));
    return out.sort((a, b) =>
      (Date.parse(b.at || "") || 0) - (Date.parse(a.at || "") || 0));
  }, [data, incident]);

  const capabilities = useMemo(() => Array.from(new Set(
    rows.map((r) => r.capability).filter(Boolean))).sort(), [rows]);

  const counts = useMemo(() => {
    const c = {};
    rows.forEach((r) => { c[r.type] = (c[r.type] || 0) + 1; });
    return c;
  }, [rows]);

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (types.length && !types.includes(r.type)) return false;
      if (capability && r.capability !== capability) return false;
      if (!needle) return true;
      return [r.activity, r.why, r.capability, r.rawResult, r.source,
              r.rawKind, ...(r.evidence || [])]
        .join(" ").toLowerCase().includes(needle);
    });
  }, [rows, types, capability, q]);

  const pivotEvidence = (ref) => {
    if (onNavigateTab) return onNavigateTab("evidence");
    const next = new URLSearchParams(params);
    next.set("tab", "evidence");
    if (ref) next.set("evidence", ref);
    setParams(next, { replace: false });
  };

  const toggleType = (t) => setTypes(
    types.includes(t) ? types.filter((x) => x !== t) : [...types, t]);

  const c = data?.counts || {};
  const summary = [
    { key: "planned", label: "Planned", value: c.planned, type: "Pivot" },
    { key: "executed", label: "Executed", value: c.executed, type: "Execution" },
    { key: "skipped", label: "Skipped", value: c.skipped ?? counts.Skipped,
      type: "Skipped" },
    { key: "findings", label: "Findings", value: c.findings ?? counts.Finding,
      type: "Finding" },
    { key: "errors", label: "Errors", value: c.errors, type: "Error" },
  ];

  const columns = [
    { key: "at", label: "Time", width: 78,
      render: (r) => <span className="mono">
        {r.at ? String(r.at).slice(11, 19) || fmtTime(r.at) : "—"}</span> },
    { key: "type", label: "Type", width: 92,
      render: (r) => <span className="inv-chip" style={{ cursor: "default",
                       padding: "1px 7px", fontSize: 9.8 }}>{r.type}</span> },
    { key: "activity", label: "Activity / finding",
      render: (r) => <NxInvValue value={r.activity}
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "capability", label: "Capability", width: 160,
      render: (r) => (r.capability
        ? <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8 }}
                  onClick={(e) => { e.stopPropagation();
                    setCapability(capability === r.capability
                      ? "" : r.capability); }}
                  data-testid={`inv-activity-cap-${r.capability}`}>
            {r.capability}
          </button>
        : <span className="inv-tb__na">—</span>) },
    { key: "result", label: "Result", width: 190,
      render: (r) => <NxInvValue value={r.result}
                                 absent={ABSENCE.NOT_EVALUATED} /> },
    { key: "confidence", label: "Conf.", width: 62, num: true,
      render: (r) => (r.confidence == null
        ? <span className="inv-tb__na">—</span> : `${r.confidence}%`) },
    { key: "evidence", label: "Evidence", width: 150,
      render: (r) => (r.evidence?.length
        ? (
          <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8, maxWidth: 140, overflow: "hidden",
                    textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                  title={r.evidence.join("\n")}
                  onClick={(e) => { e.stopPropagation();
                                    pivotEvidence(r.evidence[0]); }}
                  data-testid={`inv-activity-evidence-${r.id}`}>
            {r.evidence[0]}
            {r.evidence.length > 1 && ` +${r.evidence.length - 1}`}
          </button>
        )
        : <span className="inv-tb__na">{ABSENCE.EVIDENCE_INCOMPLETE}</span>) },
    { key: "source", label: "Source", width: 130,
      render: (r) => <NxInvValue value={r.source} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
  ];

  return (
    <div className="inv" data-testid="xdr-record-auto-investigation">
      {/* ── Summary strip · every metric is a filter ─────────── */}
      <NxInvSection
        title="Investigation progress"
        subtitle={data?.state
          ? String(data.state).replace(/_/g, " ").toLowerCase()
          : (loading ? "reading…" : "state not reported")}
        testid="inv-activity-progress">
        <div className="inv-filters" data-testid="inv-activity-summary">
          {summary.map((m) => {
            const measured = m.value != null;
            return (
              <button key={m.key} className="inv-chip"
                      aria-pressed={types.includes(m.type)}
                      disabled={!measured}
                      title={measured ? `Filter to ${m.label.toLowerCase()}`
                        : `${m.label}: ${ABSENCE.NOT_AVAILABLE}`}
                      onClick={() => toggleType(m.type)}
                      data-testid={`inv-activity-summary-${m.key}`}>
                {measured ? m.value : "—"}
                <span className="inv-chip__n">{m.label}</span>
              </button>
            );
          })}
          <span className="inv-filters__sp inv-sec__s">
            {visible.length} of {rows.length} event(s)
          </span>
        </div>
      </NxInvSection>

      {/* ── Operations toolbar + dense event table ───────────── */}
      <NxInvSection title="Investigation activity"
                    subtitle="one row per operational event · expand for the full record"
                    testid="xdr-record-ai-activity-sec">
        <div className="inv-filters" data-testid="inv-activity-toolbar">
          <span className="inv-cov__k" style={{ display: "inline-flex",
                  alignItems: "center", gap: 5 }}>
            <Search size={11} />
            <input value={q} onChange={(e) => setQ(e.target.value)}
                   data-testid="inv-activity-search"
                   placeholder="Search activity — capability · result · evidence id · entity…"
                   style={{ fontSize: 11, background: "transparent",
                            border: "none", outline: "none", width: 330,
                            color: "var(--nx-text, var(--text))",
                            textTransform: "none", letterSpacing: 0 }} />
          </span>
          <button className="inv-chip" aria-pressed={types.length === 0
                    && !capability && !q}
                  onClick={() => { setTypes([]); setCapability(""); setQ(""); }}
                  data-testid="inv-activity-filter-all">
            All
          </button>
          {QUICK.map((t) => (
            <button key={t.key} className="inv-chip"
                    aria-pressed={types.includes(t.key)}
                    onClick={() => toggleType(t.key)}
                    data-testid={`inv-activity-filter-${t.key.toLowerCase()}`}>
              {t.label}
              <span className="inv-chip__n">{counts[t.key] || 0}</span>
            </button>
          ))}
          {capabilities.length > 0 && (
            <select value={capability}
                    onChange={(e) => setCapability(e.target.value)}
                    data-testid="inv-activity-capability-filter"
                    style={{ fontSize: 10.6, padding: "2px 6px",
                             borderRadius: 3, background: "transparent",
                             color: "var(--nx-text, var(--text))",
                             border: "1px solid var(--nx-bd-quiet, var(--border))" }}>
              <option value="">Any capability</option>
              {capabilities.map((k) => <option key={k} value={k}>{k}</option>)}
            </select>
          )}
        </div>

        <NxInvTable testid="xdr-record-ai-activity" columns={columns}
                    rows={visible.slice(0, 500)} rowKey={(r) => r.id}
                    detail={(r) => (
                      <dl className="inv-kv">
                        <dt>What happened</dt>
                        <dd><NxInvValue value={r.activity}
                                        absent={ABSENCE.NOT_RECORDED} /></dd>
                        <dt>Why</dt>
                        <dd><NxInvValue value={r.why}
                                        absent={ABSENCE.NOT_RECORDED} /></dd>
                        <dt>Capability</dt>
                        <dd className="mono"><NxInvValue value={r.capability}
                                        absent="NOT APPLICABLE" /></dd>
                        <dt>Result</dt>
                        <dd><NxInvValue value={r.result}
                                        absent={ABSENCE.NOT_EVALUATED} /></dd>
                        <dt>Confidence</dt>
                        <dd className="mono">{r.confidence == null
                          ? <span className="inv-tb__na">{ABSENCE.NOT_EVALUATED}</span>
                          : `${r.confidence}%`}</dd>
                        <dt>Evidence</dt>
                        <dd>
                          {r.evidence?.length ? r.evidence.map((ref) => (
                            <button key={ref} className="inv-chip"
                                    style={{ marginRight: 6, padding: "1px 7px",
                                             fontSize: 9.8 }}
                                    onClick={() => pivotEvidence(ref)}
                                    data-testid={`inv-activity-evref-${ref}`}>
                              {ref} →
                            </button>
                          )) : <span className="inv-tb__na">
                            {ABSENCE.EVIDENCE_INCOMPLETE}</span>}
                        </dd>
                        <dt>Activity time</dt>
                        <dd className="mono"><NxInvValue value={fmtTime(r.at)}
                                        absent={ABSENCE.NOT_RECORDED} /></dd>
                        <dt>Source</dt>
                        <dd className="mono"><NxInvValue value={r.source}
                                        absent={ABSENCE.NOT_ATTRIBUTED} /></dd>
                        <dt>Raw engine values</dt>
                        <dd className="mono">
                          kind={String(r.rawKind)} · result={String(r.rawResult)}
                        </dd>
                        <dt>Engine record</dt>
                        <dd className="mono">{JSON.stringify(r.raw)}</dd>
                      </dl>
                    )}
                    empty={
                      <NxInvEmpty
                        testid="inv-activity-empty"
                        title={error
                          ? `${ABSENCE.NOT_AVAILABLE} — the activity record could not be read`
                          : rows.length === 0
                            ? "Nothing has acted on this incident yet"
                            : "No event matches the current search or filters"}
                        body={error ? String(error)
                          : rows.length === 0
                            ? "No autonomous capability has run and no analyst action is recorded against this incident. This log reports what happened — it never implies that work succeeded."
                            : "Clear the search and filters to see every event."}
                        points={error || rows.length ? [] : [
                          "Automated investigation starts when the pipeline surfaces a governed trigger.",
                          "Analyst lifecycle transitions appear here as soon as the incident is worked.",
                        ]} />
                    } />
        {visible.length > 500 && (
          <div className="inv-empty" data-testid="inv-activity-truncated">
            Showing the 500 most recent of {visible.length} matching events.
            Narrow the search or filters to reach older activity.
          </div>
        )}

        <NxInvTech label="Technical details · investigation record"
                   testid="inv-activity-tech">
          <dl className="inv-kv">
            <dt>Read</dt>
            <dd className="mono">GET /api/incidents/{incident?.id}/investigation</dd>
            <dt>Engine state</dt>
            <dd className="mono">
              <NxInvValue value={data?.state} absent={ABSENCE.NOT_EVALUATED} />
            </dd>
            <dt>Counts</dt>
            <dd className="mono">{JSON.stringify(c)}</dd>
          </dl>
        </NxInvTech>
      </NxInvSection>

      {(data?.executions || []).length > 0 && (
        <NxInvSection title="Engine executions"
                      subtitle="provenance of every capability that ran"
                      testid="xdr-record-ai-exec-sec">
          <NxInvTable testid="xdr-record-ai-exec-table" rows={data.executions}
                      rowKey={(r, i) => `${r.capability}-${i}`}
                      columns={[
                        { key: "capability", label: "Capability", width: 200 },
                        { key: "engine", label: "Engine", width: 200,
                          render: (r) => <NxInvValue value={r.engine} mono
                                           absent={ABSENCE.NOT_RECORDED} /> },
                        { key: "status", label: "Status", width: 150,
                          render: (r) => <NxInvValue
                            value={resultText(r.status)} mono
                            absent={ABSENCE.NOT_EVALUATED} /> },
                        { key: "duration_ms", label: "Duration", width: 100,
                          num: true,
                          render: (r) => (r.duration_ms == null
                            ? <span className="inv-tb__na">{ABSENCE.NOT_RECORDED}</span>
                            : `${r.duration_ms} ms`) },
                        { key: "finding_ids", label: "Findings", width: 90,
                          num: true,
                          render: (r) => (r.finding_ids || []).length },
                        { key: "started_at", label: "Started", width: 158,
                          render: (r) => <NxInvValue value={fmtTime(r.started_at)}
                                           mono absent={ABSENCE.NOT_RECORDED} /> },
                      ]} />
        </NxInvSection>
      )}
    </div>
  );
}
