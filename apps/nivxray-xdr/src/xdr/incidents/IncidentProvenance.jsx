/**
 * IncidentProvenance · how this incident came to be believed.
 *
 * The chain is `Raw → Parsed → Normalized → Canonical evidence → Detection
 * → Incident`, and each stage carries ONLY what the incident record can
 * prove. The per-event ingest stages (raw/parsed/normalized) are recorded
 * per canonical event, not on the incident, so they are reported as
 * `NOT_REPORTED` with that reason and a pivot to the surface that does hold
 * them — never drawn as complete to make the chain look finished.
 */
import React from "react";
import { useNavigate } from "react-router-dom";

import { NxSection, NxProvenanceChain, NxButton, NxProvenanceChip }
  from "@/xdr/nx";

const PER_EVENT_REASON =
  "recorded per canonical event, not on the incident record";

export function provenanceStages(incident) {
  const canonical = incident?.canonical_evidence_ids || [];
  const rows = incident?.verdict_stage2?.evidence_rows || [];
  const signals = incident?.verdict_stage2?.contributing_signals || [];
  const chain = incident?.verdict_stage2?.provenance_chain || [];

  return [
    { stage: "Raw", state: "NOT_REPORTED", reason: PER_EVENT_REASON },
    { stage: "Parsed", state: "NOT_REPORTED", reason: PER_EVENT_REASON },
    { stage: "Normalized", state: "NOT_REPORTED", reason: PER_EVENT_REASON },
    canonical.length
      ? { stage: "Canonical evidence", state: "MATERIALISED",
          reason: `${canonical.length} canonical evidence row(s) attached`,
          evidence_ref: canonical[0] }
      : { stage: "Canonical evidence", state: "NOT_OBSERVED",
          reason: "no canonical evidence row is attached to this incident" },
    signals.length || rows.length
      ? { stage: "Detection", state: "MATCHED",
          reason: `${signals.length || rows.length} detection contribution(s)`
            + (rows[0]?.canonical_field_matched
              ? ` · matched ${rows[0].canonical_field_matched}` : ""),
          evidence_ref: rows[0]?.row_id }
      : { stage: "Detection", state: "NOT_OBSERVED",
          reason: "no detection contribution is recorded" },
    { stage: "Incident", state: "OBSERVED",
      reason: chain.length
        ? `written by ${chain.join(" → ")}`
        : "no writer chain recorded on the verdict",
      evidence_ref: incident?.number || incident?.id },
  ];
}

export default function IncidentProvenance({ incident,
                                             testid = "incident-provenance-chain" }) {
  const navigate = useNavigate();
  const canonical = incident?.canonical_evidence_ids || [];

  return (
    <NxSection
      title="Provenance"
      aside={<NxProvenanceChip provenance={incident?.provenance}
                               basis={incident?.provenance_basis}
                               isReal={incident?.provenance_is_real} />}
      note={incident?.provenance_basis
        || "No provenance basis was recorded for this incident."}
      action={canonical.length ? (
        <NxButton
          onClick={() => navigate(
            `/xdr/events?q=${encodeURIComponent(canonical[0])}`)}
          title="Open the canonical event in Event Explorer, where the raw, normalized and canonical projections of that event are held"
          testid={`${testid}-open-source`}
        >
          Open source event
        </NxButton>
      ) : null}
      testid={testid}
    >
      <NxProvenanceChain stages={provenanceStages(incident)}
                         testid={`${testid}-stages`} />
    </NxSection>
  );
}
