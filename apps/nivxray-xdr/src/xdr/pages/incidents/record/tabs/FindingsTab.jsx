/**
 * Findings · the investigation's dense findings table (owner directive §A).
 *
 *   Finding | Category | Capability | State | Confidence | Evidence |
 *   Entities | MITRE | Source | Time            → row select opens the
 *   contextual details pane.
 *
 * The pane — never the row — carries Summary · Evidence · Entities ·
 * Relationships · MITRE · Provenance · Analyst interpretation · History ·
 * Technical details. The SYSTEM assessment and the ANALYST interpretation
 * are separate facts and are never merged: the machine value stays visible
 * beside any overlay, and `ANALYST INTERPRETATION / NIVXRAY GENERATED /
 * EDIT / HISTORY` appear once, in the pane, not on every row.
 *
 * Source: `GET /api/incidents/{id}/investigation` → findings[] ·
 * executions[]; overlays from `GET /api/incidents/{id}/intelligence/overlays`.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Loader2, Search } from "lucide-react";

import api from "@/lib/api";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue,
  ABSENCE, fmtTime,
} from "@/xdr/nx";
import { capabilityLabel, capabilityIsMapped } from "@/xdr/nx/capabilityLabels";
import IntelligenceOverlayEditor from "@/xdr/components/IntelligenceOverlayEditor";
import "@/xdr/nx/nx-workspace.css";

/** Analyst category for a finding kind — the raw kind stays in the pane. */
const CATEGORY = {
  detection_intel: "Detection", process_ancestry: "Execution",
  commandline_decode: "Execution", lolbas_lookup: "Execution",
  mitre_expansion: "ATT&CK", ioc_pivot: "Indicator",
  historical_correlation: "Correlation", correlation: "Correlation",
  network_pivot: "Network", identity_pivot: "Identity",
  dns_pivot: "Network", file_reputation: "File",
};

function mitreOf(f) {
  const p = f?.provenance || {};
  const ids = [p.technique_id, p.technique, ...(p.mitre_ids || []),
               ...(f.mitre_ids || [])].filter(Boolean);
  return Array.from(new Set(ids));
}

function entityOf(f) {
  return f.subject_kind && f.subject_value
    ? `${f.subject_kind}:${f.subject_value}` : null;
}

export default function FindingsTab({ incident, onNavigateTab }) {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState(null);
  const [overlays, setOverlays] = useState({});
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);

  const [sel, setSel] = useState(null);
  const [paneTab, setPaneTab] = useState("summary");
  const [q, setQ] = useState("");
  const [cap, setCap] = useState("");
  const [state, setState] = useState("");

  const overlayKey = (fid) => `finding:${fid}:summary`;

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setLoading(true); setErr(null);
    const id = encodeURIComponent(incident.id);
    Promise.all([
      api.get(`/incidents/${id}/investigation`),
      api.get(`/incidents/${id}/intelligence/overlays`)
        .catch(() => ({ data: { overlays: [] } })),
    ]).then(([inv, ovr]) => {
      if (!live) return;
      setData(inv.data);
      const idx = {};
      (ovr.data?.overlays || []).forEach((o) => {
        if (o.target_kind === "finding" && o.field_key === "summary")
          idx[overlayKey(o.target_id)] = o;
      });
      setOverlays(idx);
    }).catch((e) => {
      const d = e?.response?.data?.detail;
      if (live) setErr(typeof d === "object"
        ? (d.reason || d.message || JSON.stringify(d))
        : (d || e?.message || "unavailable"));
    }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [incident?.id]);

  const execById = useMemo(() => {
    const m = new Map();
    (data?.executions || []).forEach((e) => {
      m.set(e.execution_id, e);
      if (e.pivot_id) m.set(e.pivot_id, e);
    });
    return m;
  }, [data]);

  const rows = useMemo(() => (data?.findings || []).map((f) => ({
    ...f,
    _title: (overlays[overlayKey(f.finding_id)]?.analyst_value
      || (f.summary || "").trim() || entityOf(f) || f.kind || "signal"),
    _machine: (f.summary || "").trim(),
    _overlay: overlays[overlayKey(f.finding_id)] || null,
    _category: CATEGORY[f.capability] || "Investigation",
    _mitre: mitreOf(f),
    _entity: entityOf(f),
    _exec: execById.get(f.execution_id) || null,
  })), [data, overlays, execById]);

  const caps = useMemo(() => Array.from(new Set(
    rows.map((r) => r.capability).filter(Boolean))).sort(), [rows]);
  const statesList = useMemo(() => Array.from(new Set(
    rows.map((r) => r.state).filter(Boolean))).sort(), [rows]);

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return rows.filter((r) => {
      if (cap && r.capability !== cap) return false;
      if (state && r.state !== state) return false;
      if (!needle) return true;
      return [r._title, r._machine, r.reasoning, r.capability, r._entity,
              r.state, ...(r._mitre || []), ...(r.evidence_refs || [])]
        .join(" ").toLowerCase().includes(needle);
    });
  }, [rows, q, cap, state]);

  const selected = useMemo(
    () => rows.find((r) => r.finding_id === sel) || null, [rows, sel]);

  const pivotEvidence = (ref) => {
    if (onNavigateTab) return onNavigateTab("evidence");
    const next = new URLSearchParams(params);
    next.set("tab", "evidence");
    if (ref) next.set("evidence", ref);
    setParams(next, { replace: false });
  };

  if (loading) return (
    <div className="inv-empty" data-testid="inv-findings-loading">
      <Loader2 size={12} className="rl-spin"
               style={{ verticalAlign: -2, marginRight: 6 }} />
      READING FINDINGS…
    </div>
  );

  const columns = [
    { key: "_title", label: "Finding",
      render: (r) => <NxInvValue value={r._title}
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "_category", label: "Category", width: 110,
      render: (r) => r._category },
    { key: "capability", label: "Capability", width: 170,
      render: (r) => (r.capability
        ? <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8 }}
                  onClick={(e) => { e.stopPropagation();
                    setCap(cap === r.capability ? "" : r.capability); }}
                  title={`Backend capability id · ${r.capability}`}
                  data-testid={`inv-findings-cap-${r.capability}`}>
            {capabilityLabel(r.capability)}
          </button>
        : <span className="inv-tb__na">{ABSENCE.NOT_ATTRIBUTED}</span>) },
    { key: "state", label: "State", width: 110,
      render: (r) => <NxInvValue value={r.state} mono
                                 absent={ABSENCE.NOT_EVALUATED} /> },
    { key: "confidence", label: "Conf.", width: 64, num: true,
      render: (r) => (r.confidence == null || r.confidence === 0
        ? <span className="inv-tb__na">—</span> : `${r.confidence}%`) },
    { key: "evidence_refs", label: "Evidence", width: 140,
      render: (r) => ((r.evidence_refs || []).length
        ? <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8, maxWidth: 132, overflow: "hidden",
                    whiteSpace: "nowrap", textOverflow: "ellipsis" }}
                  title={(r.evidence_refs || []).join("\n")}
                  onClick={(e) => { e.stopPropagation();
                                    setSel(r.finding_id);
                                    setPaneTab("evidence"); }}
                  data-testid={`inv-findings-ev-${r.finding_id}`}>
            {r.evidence_refs[0]}
            {r.evidence_refs.length > 1 && ` +${r.evidence_refs.length - 1}`}
          </button>
        : <span className="inv-tb__na">{ABSENCE.EVIDENCE_INCOMPLETE}</span>) },
    { key: "_entity", label: "Entities", width: 170,
      render: (r) => (r._entity
        ? <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8, maxWidth: 160, overflow: "hidden",
                    whiteSpace: "nowrap", textOverflow: "ellipsis" }}
                  onClick={(e) => { e.stopPropagation();
                                    setSel(r.finding_id);
                                    setPaneTab("entities"); }}
                  data-testid={`inv-findings-entity-${r.finding_id}`}>
            {r._entity}
          </button>
        : <span className="inv-tb__na">{ABSENCE.NOT_OBSERVED}</span>) },
    { key: "_mitre", label: "MITRE", width: 120,
      render: (r) => (r._mitre.length
        ? <button className="inv-chip" style={{ padding: "1px 7px",
                    fontSize: 9.8 }}
                  onClick={(e) => { e.stopPropagation();
                                    setSel(r.finding_id);
                                    setPaneTab("mitre"); }}
                  data-testid={`inv-findings-mitre-${r.finding_id}`}>
            {r._mitre.join(" ")}
          </button>
        : <span className="inv-tb__na">{ABSENCE.NOT_EVALUATED}</span>) },
    { key: "engine", label: "Source", width: 150,
      render: (r) => <NxInvValue value={r.engine} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
    { key: "created_at", label: "Time", width: 148,
      render: (r) => <NxInvValue value={fmtTime(r.created_at)} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "actions", label: "Actions", width: 132,
      render: (r) => (
        <span style={{ display: "inline-flex", gap: 4 }}>
          <button className="inv-chip" style={{ padding: "1px 6px",
                    fontSize: 9.4 }}
                  onClick={(e) => { e.stopPropagation();
                                    setSel(r.finding_id);
                                    setPaneTab("summary"); }}
                  data-testid={`inv-findings-inspect-${r.finding_id}`}>
            Inspect
          </button>
          <button className="inv-chip" style={{ padding: "1px 6px",
                    fontSize: 9.4 }}
                  disabled={!(r.evidence_refs || []).length}
                  title={(r.evidence_refs || []).length
                    ? "Open this finding's evidence in the Evidence tab"
                    : ABSENCE.EVIDENCE_INCOMPLETE}
                  onClick={(e) => { e.stopPropagation();
                                    pivotEvidence(r.evidence_refs?.[0]); }}
                  data-testid={`inv-findings-pivot-${r.finding_id}`}>
            Evidence →
          </button>
        </span>
      ) },
  ];

  return (
    <div className="inv" data-testid="incident-findings">
      <NxInvSection title="Findings"
        subtitle={`${visible.length} of ${rows.length} evidence-anchored finding(s) · select a row to inspect it`}
        testid="inv-findings-head">
        <div className="inv-filters" data-testid="inv-findings-toolbar">
          <span className="inv-cov__k" style={{ display: "inline-flex",
                  alignItems: "center", gap: 5 }}>
            <Search size={11} />
            <input value={q} onChange={(e) => setQ(e.target.value)}
                   data-testid="inv-findings-search"
                   placeholder="Search findings — entity · evidence id · technique…"
                   style={{ fontSize: 11, background: "transparent",
                            border: "none", outline: "none", width: 300,
                            color: "var(--nx-text, var(--text))",
                            textTransform: "none", letterSpacing: 0 }} />
          </span>
          <button className="inv-chip" aria-pressed={!cap && !state && !q}
                  onClick={() => { setCap(""); setState(""); setQ(""); }}
                  data-testid="inv-findings-filter-all">All</button>
          {statesList.map((s) => (
            <button key={s} className="inv-chip" aria-pressed={state === s}
                    onClick={() => setState(state === s ? "" : s)}
                    data-testid={`inv-findings-state-${s}`}>
              {s}
              <span className="inv-chip__n">
                {rows.filter((r) => r.state === s).length}</span>
            </button>
          ))}
          {caps.length > 0 && (
            <select value={cap} onChange={(e) => setCap(e.target.value)}
                    data-testid="inv-findings-capability-filter"
                    style={{ fontSize: 10.6, padding: "2px 6px",
                             borderRadius: 3, background: "transparent",
                             color: "var(--nx-text, var(--text))",
                             border: "1px solid var(--nx-bd-quiet, var(--border))" }}>
              <option value="">Any capability</option>
              {caps.map((k) => (
                <option key={k} value={k}>{capabilityLabel(k)}</option>
              ))}
            </select>
          )}
        </div>
      </NxInvSection>

      <div className="inv-split" data-testid="inv-findings-wk"
           data-pane={selected ? "open" : "closed"}>
        <div className="inv-split__t">
          <NxInvTable testid="inv-findings-table" columns={columns}
                      rows={visible} rowKey={(r) => r.finding_id}
                      onRowClick={(r) => { setSel(r.finding_id);
                                           setPaneTab("summary"); }}
                      empty={<NxInvEmpty testid="inv-findings-empty"
                        title={err
                          ? `${ABSENCE.NOT_AVAILABLE} — findings could not be read`
                          : rows.length === 0
                            ? "No finding has been produced for this incident"
                            : "No finding matches the current search or filters"}
                        body={err ? String(err)
                          : rows.length === 0
                            ? "Findings appear when an investigation capability produces an evidence-anchored result. An empty findings table means nothing was concluded — it never means the incident is benign."
                            : "Clear the search and filters to see every finding."} />} />
        </div>

        {selected && (
          <div className="inv-split__p" data-testid="inv-findings-pane">
            <div className="inv-pane__h">
              <span style={{ minWidth: 0 }}>
                <div className="inv-pane__k">
                  {selected._category} · {capabilityLabel(selected.capability)
                    || ABSENCE.NOT_ATTRIBUTED}
                </div>
                <div className="inv-pane__t"
                     data-testid="inv-findings-pane-title">
                  {selected._title}
                </div>
              </span>
              <button className="inv-chip" style={{ marginLeft: "auto" }}
                      onClick={() => setSel(null)}
                      data-testid="inv-findings-pane-close">Close</button>
            </div>

            <div className="inv-pane__tabs" role="tablist">
              {[["summary", "Summary"],
                ["evidence", `Evidence (${(selected.evidence_refs || []).length})`],
                ["entities", "Entities"],
                ["mitre", "MITRE"],
                ["interpretation", "Interpretation"],
                ["provenance", "Provenance"]].map(([k, label]) => (
                <button key={k} className="inv-pane__tab" role="tab"
                        aria-selected={paneTab === k}
                        onClick={() => setPaneTab(k)}
                        data-testid={`inv-findings-pane-tab-${k}`}>
                  {label}
                </button>
              ))}
            </div>

            <div className="inv-pane__b">
              {paneTab === "summary" && (
                <dl className="inv-kv" data-testid="inv-findings-pane-summary">
                  <dt>System assessment</dt>
                  <dd><NxInvValue value={selected._machine}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                  <dt>Engine reasoning</dt>
                  <dd><NxInvValue value={selected.reasoning}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                  <dt>State</dt>
                  <dd className="mono"><NxInvValue value={selected.state}
                        absent={ABSENCE.NOT_EVALUATED} /></dd>
                  <dt>Confidence</dt>
                  <dd className="mono">{selected.confidence == null
                    || selected.confidence === 0
                    ? <span className="inv-tb__na">
                        {ABSENCE.NOT_EVALUATED}</span>
                    : `${selected.confidence}%`}</dd>
                  <dt>Observed at</dt>
                  <dd className="mono"><NxInvValue
                        value={fmtTime(selected.created_at)}
                        absent={ABSENCE.NOT_RECORDED} /></dd>
                </dl>
              )}

              {paneTab === "evidence" && (
                (selected.evidence_refs || []).length === 0
                  ? <NxInvEmpty testid="inv-findings-pane-ev-empty"
                      title={ABSENCE.EVIDENCE_INCOMPLETE}
                      body="This finding carries no canonical evidence reference. It is an engine assessment, and it is presented as one." />
                  : (selected.evidence_refs || []).map((ref) => (
                    <button className="inv-pane__row" key={ref}
                            onClick={() => pivotEvidence(ref)}
                            data-testid={`inv-findings-pane-ev-${ref}`}>
                      <span className="inv-pane__verb">evidence</span>
                      <span className="mono" style={{ wordBreak: "break-all" }}>
                        {ref} →
                      </span>
                    </button>
                  ))
              )}

              {paneTab === "entities" && (
                selected._entity
                  ? <button className="inv-pane__row"
                            onClick={() => onNavigateTab
                              && onNavigateTab("entities")}
                            data-testid="inv-findings-pane-entity">
                      <span className="inv-pane__verb">
                        {selected.subject_kind}</span>
                      <span className="mono">{selected.subject_value} →</span>
                    </button>
                  : <NxInvEmpty testid="inv-findings-pane-entity-empty"
                      title={ABSENCE.NOT_OBSERVED}
                      body="No entity subject is recorded on this finding." />
              )}

              {paneTab === "mitre" && (
                selected._mitre.length
                  ? selected._mitre.map((t) => (
                    <button className="inv-pane__row" key={t}
                            onClick={() => onNavigateTab
                              && onNavigateTab("mitre")}
                            data-testid={`inv-findings-pane-mitre-${t}`}>
                      <span className="inv-pane__verb">technique</span>
                      <span className="mono">{t} →</span>
                    </button>
                  ))
                  : <NxInvEmpty testid="inv-findings-pane-mitre-empty"
                      title={ABSENCE.NOT_EVALUATED}
                      body="No ATT&CK technique is attributed to this finding by the engine. The MITRE tab shows only techniques evidence substantiates." />
              )}

              {paneTab === "interpretation" && (
                <div data-testid="inv-findings-pane-interpretation">
                  <div className="inv-sec__s" style={{ marginBottom: 6 }}>
                    The analyst narrative is separate from the system
                    assessment. Editing it never changes the finding's
                    identity, evidence, confidence or ATT&CK mapping.
                  </div>
                  <IntelligenceOverlayEditor
                    incidentId={incident.id}
                    targetKind="finding"
                    targetId={selected.finding_id}
                    fieldKey="summary"
                    machineValue={selected._machine}
                    overlay={selected._overlay}
                    onChange={(o) => setOverlays((prev) => ({
                      ...prev, [overlayKey(selected.finding_id)]: o }))}
                    label="Analyst Interpretation" />
                </div>
              )}

              {paneTab === "provenance" && (
                <>
                  <dl className="inv-kv" data-testid="inv-findings-pane-prov">
                    <dt>Producing engine</dt>
                    <dd className="mono"><NxInvValue value={selected.engine}
                          absent={ABSENCE.NOT_ATTRIBUTED} /></dd>
                    <dt>Capability id</dt>
                    <dd className="mono">
                      <NxInvValue value={selected.capability}
                                  absent={ABSENCE.NOT_ATTRIBUTED} />
                      {selected.capability && !capabilityIsMapped(
                        selected.capability) && " · UNMAPPED LABEL"}
                    </dd>
                    <dt>Execution</dt>
                    <dd className="mono"><NxInvValue
                          value={selected.execution_id}
                          absent={ABSENCE.NOT_RECORDED} /></dd>
                    <dt>Duration</dt>
                    <dd className="mono">{selected._exec?.duration_ms == null
                      ? <span className="inv-tb__na">
                          {ABSENCE.NOT_RECORDED}</span>
                      : `${selected._exec.duration_ms} ms`}</dd>
                    <dt>Finding id</dt>
                    <dd className="mono">{selected.finding_id}</dd>
                  </dl>
                  <NxInvTech label="Technical details · engine record"
                             testid="inv-findings-pane-tech">
                    <pre>{JSON.stringify(selected.provenance || {}, null, 1)}</pre>
                    <pre>{JSON.stringify({
                      kind: selected.kind, state: selected.state,
                      subject_kind: selected.subject_kind,
                      subject_value: selected.subject_value,
                      tenant_id: selected.tenant_id,
                    }, null, 1)}</pre>
                  </NxInvTech>
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
