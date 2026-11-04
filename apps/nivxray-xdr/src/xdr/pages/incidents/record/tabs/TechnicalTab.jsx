/**
 * Detections · rule-fired findings for this incident.
 *
 * The enterprise table language of the incident queue, applied to the
 * analyst's deepest technical surface. Every column is an authoritative
 * field from `GET /api/incidents/{id}/summary` or the incident record;
 * engine strings such as `NOT_RUN` are TRANSLATED for the analyst and the
 * exact value is preserved under Technical details.
 */
import React, { useEffect, useMemo, useState } from "react";

import { getIncidentSummary } from "@/lib/incidentsApi";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvMetrics,
  NxInvValue, ABSENCE,
} from "@/xdr/nx";

const IOC_KINDS = ["url", "domain", "ip", "hash", "file", "email"];

export default function TechnicalTab({ incident }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await getIncidentSummary(incident.id);
        if (!cancelled) setSummary(data);
      } catch (e) {
        if (!cancelled) {
          const d = e?.response?.data?.detail;
          setError(typeof d === "object"
            ? (d.reason || d.error || JSON.stringify(d))
            : (d || e?.message || "Failed to load detections."));
        }
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const detections = summary?.suspicious_elements || [];
  const iocs = incident.iocs || {};
  const chain = incident.chain_ids || [];

  const iocRows = useMemo(() => IOC_KINDS
    .map((k) => ({ kind: k.toUpperCase(),
                   list: Array.isArray(iocs[k]) ? iocs[k] : [] }))
    .filter((r) => r.list.length > 0), [iocs]);

  const columns = [
    { key: "rule_id", label: "Detection / rule", width: 260,
      render: (r) => <NxInvValue value={r.rule_id || r.name} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "weight", label: "Weight", width: 80, num: true,
      render: (r) => (r.weight == null
        ? <span className="inv-tb__na">{ABSENCE.NOT_EVALUATED}</span>
        : `+${r.weight}`) },
    { key: "technique", label: "Technique", width: 110,
      render: (r) => <NxInvValue value={r.technique || r.technique_id} mono
                                 absent={ABSENCE.NOT_OBSERVED} /> },
    { key: "entity", label: "Entity", width: 170,
      render: (r) => <NxInvValue value={r.entity || r.subject || r.host} mono
                                 absent={ABSENCE.NOT_ATTRIBUTED} /> },
    { key: "detected_by", label: "Source", width: 160,
      render: (r) => <NxInvValue value={r.detected_by} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "provenance", label: "Provenance",
      render: (r) => <NxInvValue value={r.provenance} mono
                                 absent={ABSENCE.EVIDENCE_INCOMPLETE} /> },
  ];

  return (
    <div className="inv" data-testid="xdr-record-technical">
      <NxInvSection title="Detection coverage"
                    subtitle="what fired, what was decoded, what was enriched"
                    testid="inv-detections-coverage">
        <NxInvMetrics testid="inv-detections-metrics" items={[
          { key: "fired", label: "Rules fired",
            value: loading ? null : detections.length,
            absent: error ? ABSENCE.ERROR : ABSENCE.NOT_EVALUATED },
          { key: "indicators", label: "Indicators",
            value: iocRows.reduce((n, r) => n + r.list.length, 0) || null,
            absent: ABSENCE.NOT_OBSERVED,
            sub: iocRows.length ? `${iocRows.length} kind(s)` : undefined },
          { key: "decode", label: "Decoder chain",
            value: chain.length ? `${chain.length} stage(s)` : null,
            absent: "NOT RUN — no decode stage recorded" },
          { key: "verdict", label: "Verdict engine",
            value: incident?.verdict_card?.engine
              || incident?.verdict_stage2?.engine || null,
            absent: ABSENCE.NOT_RECORDED },
        ]} />
      </NxInvSection>

      <NxInvSection
        title="Detections"
        subtitle={loading ? "reading the authoritative summary…"
          : error ? "not available" : `${detections.length} rule-fired finding(s)`}
        testid="xdr-record-technical-suspicious">
        {error ? (
          <NxInvEmpty testid="inv-detections-error"
                      title={`${ABSENCE.ERROR} — detections could not be read`}
                      body={String(error)} />
        ) : (
          <NxInvTable testid="inv-detections-table" columns={columns}
                      rows={detections} rowKey={(r, i) => r.rule_id || i}
                      detail={(r) => (
                        <dl className="inv-kv">
                          <dt>Rule</dt>
                          <dd className="mono">
                            <NxInvValue value={r.rule_id}
                                        absent={ABSENCE.NOT_RECORDED} />
                          </dd>
                          <dt>Why it fired</dt>
                          <dd><NxInvValue value={r.reason || r.description
                            || r.summary} absent={ABSENCE.NOT_RECORDED} /></dd>
                          <dt>Provenance</dt>
                          <dd className="mono">
                            <NxInvValue value={r.provenance}
                                        absent={ABSENCE.EVIDENCE_INCOMPLETE} />
                          </dd>
                          <dt>Record</dt>
                          <dd className="mono">{JSON.stringify(r)}</dd>
                        </dl>
                      )}
                      empty={
                        <NxInvEmpty
                          testid="inv-detections-empty"
                          title="No detection rule has fired on this incident"
                          body="This incident exists because of the evidence recorded against it, not because a detection rule matched. That is a legitimate state, not a gap in this page."
                          points={[
                            "Indicators below list every observable projected onto the case.",
                            "The verdict and its derivation are on the Overview tab.",
                          ]} />
                      } />
        )}
      </NxInvSection>

      <NxInvSection title="Indicators"
                    subtitle="from the canonical IOC set — never enriched here"
                    testid="xdr-record-technical-iocs">
        <NxInvTable testid="inv-indicators-table" rows={iocRows}
                    rowKey={(r) => r.kind}
                    columns={[
                      { key: "kind", label: "Kind", width: 110 },
                      { key: "count", label: "Count", width: 80, num: true,
                        render: (r) => r.list.length },
                      { key: "sample", label: "Observed values",
                        render: (r) => (
                          <span className="mono" style={{ wordBreak: "break-all" }}>
                            {r.list.slice(0, 4).join("  ·  ")}
                            {r.list.length > 4 && `  +${r.list.length - 4} more`}
                          </span>
                        ) },
                    ]}
                    empty={
                      <NxInvEmpty
                        testid="inv-indicators-empty"
                        title={`${ABSENCE.NOT_OBSERVED} — no indicator is projected onto this incident`}
                        body="Indicators appear here only when the canonical IOC set carries them for this case. An empty set is an observation, not a zero." />
                    } />
      </NxInvSection>

      <NxInvTech label="Technical details · engine state and original input"
                 testid="inv-detections-tech">
        <dl className="inv-kv">
          <dt>Decoder chain</dt>
          <dd className="mono">
            {chain.length
              ? chain.map((c, i) => `${i + 1}·${c}`).join("  →  ")
              : "NOT_RUN (chain_ids is empty)"}
          </dd>
          <dt>Summary read</dt>
          <dd className="mono">GET /api/incidents/{incident?.id}/summary</dd>
        </dl>
        {incident.input_preview && (
          <pre style={{ marginTop: 10 }}>{incident.input_preview}</pre>
        )}
      </NxInvTech>
    </div>
  );
}
