/**
 * CanonicalEvidenceRecords · P1 Evidence Namespace Bridge.
 *
 * The incident's CANONICAL EVIDENCE RECORDS — a different object from the
 * capability pointers rendered by the Evidence table: a pointer says which
 * domain could be asked, a canonical evidence record IS one piece of
 * evidence, identified by `canonical_evidence_id`
 * (`xdr_canonical_evidence.event_id`).
 *
 * Source of truth: `GET /api/incidents/{id}/canonical-evidence`, projected
 * server-side from the identifiers the incident itself persists. Nothing is
 * matched on labels, hashes, timestamps or positions, and no row identity is
 * invented in the browser.
 *
 * Three states are reported exactly as the backend states them:
 *   BRIDGED                  the canonical record resolves
 *   REFERENCED_RECORD_ABSENT the reference is deterministic, the record is
 *                            not retained — NOT "no evidence", NOT benign
 *   LEGACY_UNBRIDGED         no canonical identifier was ever persisted, so
 *                            no deterministic bridge can be established now
 */
import React from "react";

import EvidenceInspector from "@/xdr/components/EvidenceInspector";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvValue, NxChip,
  ABSENCE, fmtTime,
} from "@/xdr/nx";

const STATE_TONE = {
  BRIDGED: "related",
  REFERENCED_RECORD_ABSENT: "no_evidence",
  LEGACY_UNBRIDGED: "not_connected",
};

export function BridgeChip({ state }) {
  return (
    <NxChip tone={STATE_TONE[state] || "not_connected"} size="sm"
            variant={state === "BRIDGED" ? "solid" : "dashed"}>
      {state}
    </NxChip>
  );
}

export default function CanonicalEvidenceRecords({ incidentId, data,
                                                   highlight }) {
  const rows = data?.rows || [];
  const legacy = data?.legacy_unbridged_observations || [];
  const counts = data?.counts || {};
  const marked = highlight instanceof Set ? highlight : new Set();

  const columns = [
    { key: "id", label: "Canonical evidence id", width: 300,
      render: (r) => (
        <span className="mono" style={{ fontSize: 11 }}>
          {r.canonical_evidence_id}
          {marked.has(r.canonical_evidence_id) && (
            <span style={{ marginLeft: 6 }}>
              <NxChip tone="related" size="sm">SELECTED ANCHOR</NxChip>
            </span>)}
        </span>) },
    { key: "state", label: "Bridge", width: 210,
      render: (r) => <BridgeChip state={r.bridge_state} /> },
    { key: "type", label: "Evidence type", width: 150,
      render: (r) => <NxInvValue value={r.record?.event_type} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "at", label: "Activity time", width: 160,
      render: (r) => <NxInvValue value={fmtTime(r.record?.event_time)} mono
                                 absent={ABSENCE.NOT_RECORDED} /> },
    { key: "source", label: "Source", width: 190,
      render: (r) => <NxInvValue
                       value={[r.record?.source_vendor, r.record?.source_product]
                         .filter(Boolean).join(" · ")}
                       absent={ABSENCE.NOT_RECORDED} /> },
  ];

  return (
    <NxInvSection
      title="Canonical evidence records"
      subtitle={`${counts.BRIDGED || 0} bridged · `
        + `${counts.REFERENCED_RECORD_ABSENT || 0} referenced record absent · `
        + `${counts.LEGACY_UNBRIDGED || 0} legacy unbridged`}
      testid="xdr-record-canonical-evidence">
      <NxInvTable testid="xdr-record-canonical-evidence-table"
                  columns={columns} rows={rows}
                  rowKey={(r) => r.canonical_evidence_id}
                  openKey={rows.length === 1
                    ? rows[0].canonical_evidence_id
                    : rows.find((r) => marked.has(r.canonical_evidence_id))
                      ?.canonical_evidence_id}
                  detail={(r) => (
                    <div style={{ display: "grid", gap: 8 }}
                         data-testid={`xdr-record-canonical-evidence-row-${r.canonical_evidence_id}`}>
                      <dl className="inv-kv">
                        <dt>Referenced by</dt>
                        <dd className="mono" style={{ fontSize: 11 }}>
                          {(r.referenced_by || [])
                            .map((c) => `${c.source} · ${c.field}`).join("  |  ")}
                        </dd>
                        <dt>Observation identities</dt>
                        <dd className="mono" style={{ fontSize: 11 }}>
                          <NxInvValue value={(r.observation_iids || []).join(", ")}
                                      absent={ABSENCE.NOT_RECORDED} />
                        </dd>
                        <dt>Ingested</dt>
                        <dd className="mono">
                          <NxInvValue value={fmtTime(r.record?.ingest_time)}
                                      absent={ABSENCE.NOT_RECORDED} />
                        </dd>
                        <dt>Normalizer</dt>
                        <dd className="mono">
                          <NxInvValue value={r.record?.normalizer_id}
                                      absent={ABSENCE.NOT_RECORDED} />
                        </dd>
                        <dt>Raw source</dt>
                        <dd className="mono" style={{ fontSize: 11 }}>
                          <NxInvValue
                            value={r.record?.raw_reference
                              ? (r.record.raw_reference.kind === "POINTER"
                                ? `${r.record.raw_reference.collection} · `
                                  + `${r.record.raw_reference.id}`
                                : "retained on the canonical record")
                              : null}
                            absent={ABSENCE.EVIDENCE_INCOMPLETE} />
                        </dd>
                      </dl>
                      {r.bridge_state === "BRIDGED" ? (
                        <div data-testid={`xdr-record-canonical-evidence-inspect-${r.canonical_evidence_id}`}>
                          <EvidenceInspector incidentId={incidentId}
                                             kind="event"
                                             refId={r.canonical_evidence_id}
                                             embedded />
                        </div>
                      ) : (
                        <div style={{ fontSize: 11.5 }}
                             data-testid={`xdr-record-canonical-evidence-absent-${r.canonical_evidence_id}`}>
                          {r.reason}
                        </div>
                      )}
                    </div>)}
                  empty={
                    <NxInvEmpty
                      testid="xdr-record-canonical-evidence-empty"
                      title="This incident references no canonical evidence record"
                      body="Canonical evidence records are projected from the identifiers this incident itself persists. None is present, and NivXRay will not substitute a similar record."
                      points={[
                        "An absent canonical reference is not a finding that "
                        + "nothing happened.",
                        "The evidence coverage strip below states which "
                        + "domains were asked and what each answered.",
                      ]} />} />
      {legacy.length > 0 && (
        <div className="inv-sec__b--pad" style={{ fontSize: 11.5 }}
             data-testid="xdr-record-canonical-evidence-legacy">
          <BridgeChip state="LEGACY_UNBRIDGED" />{" "}
          {legacy.length} observation{legacy.length === 1 ? "" : "s"} on this
          incident were persisted before the canonical identifier existed, so
          they cannot be bridged deterministically. They are reported in their
          own namespace and are never guessed onto a canonical record.
        </div>)}
    </NxInvSection>
  );
}
