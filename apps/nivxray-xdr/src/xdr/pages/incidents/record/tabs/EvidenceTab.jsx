/**
 * Evidence · the incident evidence workspace.
 *
 * Coverage first, then the evidence itself:
 *
 *   1. a compact per-domain coverage strip that preserves the four
 *      DISTINCT truths the backend reports —
 *        RELATED        the domain produced evidence
 *        SEARCHED       the domain was queried and produced no hit
 *        NO EVIDENCE    the domain applies, nothing was found
 *        NOT CONNECTED  the integration does not exist here
 *      `NOT CONNECTED` is not 0 and `NO EVIDENCE` is not `NOT AVAILABLE`;
 *   2. one evidence table over every authoritative pointer bullet, with
 *      the domain filter driven by the strip above.
 *
 * Source of truth: `incident.evidence_pointers` exactly as the backend
 * projected it. No bullet is rewritten and no count is inferred.
 */
import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { productHref, productMode } from "@/productOrigins";
import EvidenceInspector from "@/xdr/components/EvidenceInspector";
import { getIncidentDeviceTrajectory, getIncidentCanonicalEvidence }
  from "@/lib/incidentsApi";
import { framesForAnchor, chainFor, canonicalIdsFor }
  from "@/xdr/incidents/anchorEvidence";
import CanonicalEvidenceRecords, { BridgeChip }
  from "@/xdr/incidents/CanonicalEvidenceRecords";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue, NxChip,
  NxState, ABSENCE, fmtTime,
} from "@/xdr/nx";

function openTarget(p) {
  const link = p?.deep_link;
  if (!link || typeof link !== "string") return null;
  if (link.startsWith("/xdr/")) return { to: link, mode: "IN_PRODUCT" };
  if (link.startsWith("/edr")) {
    const to = productHref("edr", link);
    return { to, mode: productMode("edr") === "CONFIGURED"
      ? "CROSS_PRODUCT" : "IN_PRODUCT" };
  }
  return null;
}

const DOMAINS = [
  { key: "endpoint", label: "Endpoint", sub: "process · file · registry · trajectory" },
  { key: "identity", label: "Identity", sub: "authentication · privilege" },
  { key: "file",     label: "Files",    sub: "artifacts · hashes · decoded payloads" },
  { key: "network",  label: "Network",  sub: "DNS · flow · beacon" },
  { key: "email",    label: "Email",    sub: "message · sender · attachment" },
  { key: "cloud",    label: "Cloud",    sub: "control plane · SaaS" },
];

const STATUS_LABEL = {
  related: "RELATED", searched: "SEARCHED",
  no_evidence: "NO EVIDENCE", not_connected: "NOT CONNECTED",
};
const STATUS_MEANING = {
  related: "this domain produced evidence for the incident",
  searched: "the domain was queried and returned no matching evidence",
  no_evidence: "the domain applies to this incident but nothing was found",
  not_connected: "no integration for this domain exists in this deployment, "
               + "so it was never queried — this is not zero evidence",
};

function normalizeStatus(p) {
  if (!p) return "not_connected";
  const bullets = Array.isArray(p.bullets) ? p.bullets : [];
  const status = String(p.status || "");
  if (status === "available") return bullets.length > 0 ? "related" : "searched";
  if (status === "not_connected" || status === "not_available") return "not_connected";
  if (status === "no_matching_evidence") return "no_evidence";
  const r = String(p.reason || "").toLowerCase();
  if (r.includes("not connected") || r.includes("not configured")
      || r.includes("integration") || r.includes("not enabled")) return "not_connected";
  if (bullets.length > 0) return "related";
  return "no_evidence";
}

/** A bullet may be a string or a record. Read it, never reshape it. */
function bulletRow(domain, b, i) {
  if (b && typeof b === "object") {
    return {
      id: `${domain}-${i}`, domain,
      at: b.at || b.time || b.observed_at || b.timestamp || null,
      type: b.type || b.kind || b.evidence_type || null,
      entity: b.entity || b.host || b.device || b.subject || null,
      value: b.value || b.text || b.detail || b.summary || b.title || null,
      source: b.source || b.engine || b.detected_by || null,
      state: b.state || b.status || b.confidence || null,
      provenance: b.provenance || b.evidence_id || b.ref || null,
      raw: b,
    };
  }
  return { id: `${domain}-${i}`, domain, at: null, type: null, entity: null,
           value: String(b), source: null, state: null, provenance: null, raw: b };
}

/**
 * S3-D · evidence supporting ONE causal anchor.
 *
 * Reached from Story → Causal anchors → "View evidence" as
 * `?tab=evidence&focus=<anchor id>`. The anchor id is resolved ONLY through
 * the structured entity slots of the device-trajectory frames that cite it —
 * never by matching a label, and never by falling back to the nearest
 * similar record.
 *
 * CONTRACT GAP, stated rather than hidden: the incident Evidence table below
 * is projected from `incident.evidence_pointers` and the incident's own
 * `canonical_evidence_ids` live in a different namespace from the engine's
 * `tf_…`/`evt_…` references, so there is no authoritative join between a
 * causal anchor and a row of that table. The supporting records are
 * therefore shown here with their own chain, and each reference stays
 * inspectable through the existing shared inspector, which reports honestly
 * when a reference is not present in the canonical store.
 */
function AnchorEvidence({ incident, anchorId, onClear, canonical,
                          onCanonicalIds }) {
  const [frames, setFrames] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (!incident?.id || !anchorId) return undefined;
    let live = true;
    setFrames(null); setErr(null);
    getIncidentDeviceTrajectory(incident.id)
      .then((t) => { if (live) setFrames(t?.frames || []); })
      .catch((e) => { if (live) setErr(e?.message || String(e)); });
    return () => { live = false; };
  }, [incident?.id, anchorId]);

  const citing = useMemo(
    () => framesForAnchor(frames || [], anchorId), [frames, anchorId]);

  useEffect(() => {
    onCanonicalIds?.(canonicalIdsFor(citing));
  }, [citing, onCanonicalIds]);

  /** The incident's canonical evidence record for a frame — never a guess. */
  const recordFor = (frame) => (canonical?.rows || []).find(
    (r) => r.canonical_evidence_id === frame?.canonical_evidence_id) || null;

  const columns = [
    { key: "at", label: "Activity time", width: 150,
      render: (r) => <NxInvValue value={fmtTime(r.ts)} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "lane", label: "Lane", width: 100,
      render: (r) => <NxInvValue value={r.lane} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
    { key: "label", label: "Observed activity",
      render: (r) => <NxInvValue value={r.label || r.action}
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "ref", label: "Observation reference", width: 200,
      render: (r) => <NxInvValue mono
                                 value={(r.evidence_ids || []).join(", ")
                                        || r.frame_iid}
                                 absent={ABSENCE.EVIDENCE_INCOMPLETE} /> },
    { key: "canonical", label: "Canonical evidence", width: 300,
      render: (r) => (
        <div style={{ display: "grid", gap: 3 }}>
          <NxInvValue mono value={r.canonical_evidence_id}
                      absent={ABSENCE.EVIDENCE_INCOMPLETE} />
          <BridgeChip state={r.bridge_state || "LEGACY_UNBRIDGED"} />
        </div>) },
    { key: "source", label: "Source", width: 140,
      render: (r) => <NxInvValue value={r.provenance?.source} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
  ];

  return (
    <NxInvSection
      title="Evidence supporting the selected causal anchor"
      subtitle={anchorId}
      actions={
        <button className="inv-chip" onClick={onClear}
                data-testid="xdr-record-evidence-anchor-clear">
          Clear anchor
        </button>}
      testid="xdr-record-evidence-anchor">
      <div className="inv-sec__b--pad" style={{ display: "grid", gap: 10 }}>
        {err && (
          <div data-testid="xdr-record-evidence-anchor-refused">
            <NxState value="NOT_AUTHORIZED" size="sm" /> {err}
          </div>)}
        {!err && frames === null && (
          <div style={{ fontSize: 11.5 }}
               data-testid="xdr-record-evidence-anchor-loading">
            resolving the records that cite this anchor…
          </div>)}
        {frames !== null && citing.length === 0 && (
          <div data-testid="xdr-record-evidence-anchor-unmatched"
               style={{ display: "grid", gap: 6 }}>
            <NxChip tone="not_connected" variant="dashed" size="sm">
              REFERENCE NOT MATCHED
            </NxChip>
            <NxInvEmpty
              title="No recorded evidence cites this reference"
              body={`Nothing in this incident's evidence plane cites `
                    + `${anchorId}.`}
              points={[
                "NivXRay will not show the nearest similar record instead — "
                + "the same entity label is not provenance.",
                "This is an absence of a citation, not a finding that the "
                + "entity was benign.",
              ]}
              testid="xdr-record-evidence-anchor-unmatched-empty" />
          </div>)}
        {citing.length > 0 && (
          <>
            <div style={{ fontSize: 11.5 }}
                 data-testid="xdr-record-evidence-anchor-count">
              <b>{citing.length}</b> recorded evidence item
              {citing.length === 1 ? " cites" : "s cite"} this anchor. Every
              one of them is listed — none is chosen as "the" evidence.
            </div>
            <NxInvTable testid="xdr-record-evidence-anchor-table"
                        columns={columns} rows={citing}
                        rowKey={(r) => r.frame_iid}
                        openKey={citing.length === 1
                          ? citing[0].frame_iid : undefined}
                        detail={(r) => (
                          <div style={{ display: "grid", gap: 8 }}>
                            <dl className="inv-kv">
                              <dt>Provenance chain</dt>
                              <dd className="mono" style={{ fontSize: 11 }}>
                                {chainFor(r).join("  →  ")}
                              </dd>
                              <dt>Ingested</dt>
                              <dd className="mono">
                                <NxInvValue
                                  value={fmtTime(r.provenance?.ingested_at)}
                                  absent={ABSENCE.NOT_RECORDED} />
                              </dd>
                              <dt>Incident evidence record</dt>
                              <dd className="mono" style={{ fontSize: 11 }}>
                                {recordFor(r)
                                  ? [recordFor(r).record?.event_type,
                                     [recordFor(r).record?.source_vendor,
                                      recordFor(r).record?.source_product]
                                       .filter(Boolean).join(" · ")]
                                      .filter(Boolean).join("  ·  ")
                                    || recordFor(r).canonical_evidence_id
                                  : <NxInvValue value={null}
                                      absent={ABSENCE.EVIDENCE_INCOMPLETE} />}
                              </dd>
                            </dl>
                            {r.canonical_evidence_id
                             && r.bridge_state === "BRIDGED" ? (
                              <div data-testid={`xdr-record-evidence-anchor-inspect-${r.canonical_evidence_id}`}>
                                <EvidenceInspector incidentId={incident?.id}
                                                   kind="event"
                                                   refId={r.canonical_evidence_id}
                                                   embedded />
                              </div>
                            ) : (
                              <div style={{ fontSize: 11.5 }}
                                   data-testid={`xdr-record-evidence-anchor-unbridged-${r.frame_iid}`}>
                                This record carries no resolvable canonical
                                evidence reference, so it keeps its own
                                namespace. NivXRay will not attach it to a
                                similar canonical record — an unbridged
                                reference is not missing evidence and is not a
                                benign finding.
                              </div>
                            )}
                          </div>)} />
            <div style={{ fontSize: 11, color: "var(--nx-text-dim)" }}>
              These records are cited by the incident's causal evidence plane.
              Each one that carries a canonical evidence identity resolves to
              the incident's own canonical evidence record below, on the
              deterministic identifier the pipeline persisted — never on a
              label, a time window or a nearest match.
            </div>
          </>)}
      </div>
    </NxInvSection>
  );
}

export default function EvidenceTab({ incident }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState(null);
  const [params, setParams] = useSearchParams();
  const [canonical, setCanonical] = useState(null);
  const [anchorCanonicalIds, setAnchorCanonicalIds] = useState(new Set());
  const focus = params.get("focus");

  useEffect(() => {
    if (!incident?.id) return undefined;
    let live = true;
    setCanonical(null);
    getIncidentCanonicalEvidence(incident.id)
      .then((d) => { if (live) setCanonical(d); })
      .catch(() => { if (live) setCanonical({ rows: [], counts: {} }); });
    return () => { live = false; };
  }, [incident?.id]);

  const clearFocus = () => {
    const next = new URLSearchParams(params);
    next.delete("focus");
    setParams(next);
  };

  const byDomain = useMemo(() => {
    const alias = { edr: "endpoint", endpoint: "endpoint", itdr: "identity",
                    identity: "identity", file: "file", files: "file",
                    ndr: "network", network: "network", email: "email",
                    cloud: "cloud" };
    const map = {};
    for (const p of (incident.evidence_pointers || [])) {
      const k = alias[p.domain] || p.domain;
      if (!map[k]) map[k] = { bullets: [], reason: null, status: null,
                              deep_link: null, domain: p.domain };
      map[k].bullets.push(...(Array.isArray(p.bullets) ? p.bullets : []));
      if (p.reason) map[k].reason = p.reason;
      if (p.status) map[k].status = p.status;
      if (p.deep_link) map[k].deep_link = p.deep_link;
    }
    return map;
  }, [incident.evidence_pointers]);

  const rows = useMemo(() => {
    const out = [];
    DOMAINS.forEach((d) => {
      const p = byDomain[d.key];
      (p?.bullets || []).forEach((b, i) => out.push(bulletRow(d.key, b, i)));
    });
    return out;
  }, [byDomain]);

  const visible = filter ? rows.filter((r) => r.domain === filter) : rows;
  const related = DOMAINS.filter((d) => normalizeStatus(byDomain[d.key]) === "related");

  const columns = [
    { key: "at", label: "Time", width: 150,
      render: (r) => <NxInvValue value={fmtTime(r.at)} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "domain", label: "Domain", width: 96,
      render: (r) => DOMAINS.find((d) => d.key === r.domain)?.label || r.domain },
    { key: "type", label: "Evidence type", width: 140,
      render: (r) => <NxInvValue value={r.type} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "entity", label: "Entity", width: 170,
      render: (r) => <NxInvValue value={r.entity} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
    { key: "value", label: "Observed value",
      render: (r) => <NxInvValue value={r.value} absent={ABSENCE.NO_DATA} /> },
    { key: "source", label: "Source", width: 140,
      render: (r) => <NxInvValue value={r.source} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "state", label: "State", width: 110,
      render: (r) => <NxInvValue value={r.state} mono
                                 absent={ABSENCE.NOT_EVALUATED} /> },
    { key: "provenance", label: "Provenance", width: 150,
      render: (r) => <NxInvValue value={r.provenance} mono
                                 absent={ABSENCE.EVIDENCE_INCOMPLETE} /> },
  ];

  return (
    <div className="inv" data-testid="xdr-record-evidence">
      {focus && (
        <AnchorEvidence incident={incident} anchorId={focus}
                        onClear={clearFocus} canonical={canonical}
                        onCanonicalIds={setAnchorCanonicalIds} />
      )}
      <CanonicalEvidenceRecords incidentId={incident?.id} data={canonical}
                                highlight={anchorCanonicalIds} />
      <NxInvSection title="Evidence coverage"
                    subtitle="which domains were asked, and what they answered"
                    testid="xdr-record-evidence-grid">
        <div className="inv-cov">
          {DOMAINS.map((d) => {
            const p = byDomain[d.key];
            const status = normalizeStatus(p);
            const count = p?.bullets?.length || 0;
            const selectable = count > 0;
            return (
              <button key={d.key} className="inv-cov__i"
                      aria-pressed={filter === d.key}
                      disabled={!selectable}
                      title={`${STATUS_LABEL[status]} — ${STATUS_MEANING[status]}`
                        + (p?.reason ? ` · ${p.reason}` : "")}
                      onClick={() => setFilter(filter === d.key ? null : d.key)}
                      data-testid={`xdr-record-evidence-${d.key}`}
                      data-status={status}>
                <span className="inv-cov__k">{d.label}</span>
                <span className="inv-cov__v">
                  {status === "not_connected"
                    ? <span className="inv-tb__na" style={{ fontSize: 11 }}>
                        not queried</span>
                    : `${count} item(s)`}
                </span>
                <span className="inv-cov__s" data-s={status}>
                  {STATUS_LABEL[status]}
                </span>
              </button>
            );
          })}
        </div>
      </NxInvSection>

      <NxInvSection
        title="Evidence"
        subtitle={filter
          ? `${visible.length} item(s) · filtered to ${
              DOMAINS.find((d) => d.key === filter)?.label}`
          : `${rows.length} item(s) across ${related.length} domain(s)`}
        actions={filter && (
          <button className="inv-chip" onClick={() => setFilter(null)}
                  data-testid="xdr-record-evidence-clear-filter">
            Clear filter
          </button>
        )}
        testid="inv-evidence">
        <NxInvTable testid="inv-evidence-table" columns={columns} rows={visible}
                    rowKey={(r) => r.id}
                    detail={(r) => (
                      <dl className="inv-kv">
                        <dt>Domain</dt><dd>{r.domain}</dd>
                        <dt>Provenance</dt>
                        <dd className="mono">
                          <NxInvValue value={r.provenance}
                                      absent={ABSENCE.EVIDENCE_INCOMPLETE} />
                        </dd>
                        <dt>Record</dt>
                        <dd className="mono">
                          {typeof r.raw === "object"
                            ? JSON.stringify(r.raw) : String(r.raw)}
                        </dd>
                      </dl>
                    )}
                    empty={
                      <NxInvEmpty
                        testid="inv-evidence-empty"
                        title="No evidence item is attached to this incident"
                        body="The coverage strip above states which domains were asked and what each answered. A domain reported NOT CONNECTED was never queried, so its silence is not a finding."
                        points={DOMAINS.map((d) => {
                          const st = normalizeStatus(byDomain[d.key]);
                          return `${d.label}: ${STATUS_LABEL[st]} — ${STATUS_MEANING[st]}`;
                        })} />
                    } />

        {related.length > 0 && (
          <div className="inv-filters">
            {DOMAINS.map((d) => {
              const t = openTarget(byDomain[d.key]);
              if (!t) return null;
              return (
                <button key={d.key} className="inv-chip"
                        data-testid={`xdr-record-evidence-${d.key}-open`}
                        data-open-to={t.to} data-open-mode={t.mode}
                        onClick={() => {
                          if (t.mode === "CROSS_PRODUCT")
                            window.open(t.to, "_blank", "noopener,noreferrer");
                          else navigate(t.to);
                        }}>
                  Inspect {d.label} evidence →
                </button>
              );
            })}
          </div>
        )}

        <NxInvTech label="Technical details · evidence pointers"
                   testid="inv-evidence-tech">
          <pre>{JSON.stringify(incident.evidence_pointers || [], null, 1)}</pre>
        </NxInvTech>
      </NxInvSection>
    </div>
  );
}

export const STATUS_ORDER = ["related", "searched", "no_evidence", "not_connected"];
