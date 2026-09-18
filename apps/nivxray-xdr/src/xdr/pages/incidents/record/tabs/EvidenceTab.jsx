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
import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { productHref, productMode } from "@/productOrigins";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue,
  ABSENCE, fmtTime,
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

export default function EvidenceTab({ incident }) {
  const navigate = useNavigate();
  const [filter, setFilter] = useState(null);

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
