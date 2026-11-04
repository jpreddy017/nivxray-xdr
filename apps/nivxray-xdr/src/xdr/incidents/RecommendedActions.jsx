/**
 * RecommendedActions · deterministic, evidence-backed next steps.
 *
 * There is NO model here and no "AI recommends" wording. Every row is
 * derived from a fact the incident record carries, and it states the fact it
 * came from, the evidence that supports it, the pivot it opens and — when
 * the step would change the estate — the authorization it requires.
 *
 * If the record supports nothing, the section says so. An empty
 * recommendation list is a true statement about this incident, not a gap to
 * be filled with generic advice.
 */
import React from "react";
import { useNavigate } from "react-router-dom";

import { NxSection, NxButton, NxChip } from "@/xdr/nx";
import { incidentEntities } from "./IncidentEntities";
import {
  pivotTrajectory, pivotIocIntelligence, pivotDetectionEvidence,
  pivotRelatedEvents,
} from "./investigationPivots";

/** @returns [{ id, action, reason, evidence, pivot, authorization }] */
export function recommendationsFor(incident) {
  if (!incident) return [];
  const out = [];
  const entities = incidentEntities(incident);
  const signals = incident.verdict_stage2?.contributing_signals || [];
  const rows = incident.verdict_stage2?.evidence_rows || [];
  const canonical = incident.canonical_evidence_ids || [];
  const available = (incident.evidence_pointers || [])
    .filter((p) => p.status === "available");

  signals.forEach((s) => {
    const pivot = pivotDetectionEvidence(s.rule_id, incident);
    if (!pivot) return;
    const row = rows.find((r) => r.rule_id === s.rule_id);
    out.push({
      id: `detection-${s.rule_id}`,
      action: `Review the detection ${s.rule_id} that moved this verdict`,
      reason: s.description
        || `${s.rule_id} contributed ${s.weight == null ? "an unrecorded weight" : `+${s.weight}`} toward "${s.label_effect || "the verdict"}"`,
      evidence: row?.event_ids?.length
        ? `${row.event_ids.length} canonical event(s) · matched ${row.canonical_field_matched || "field not stated"}`
        : "No evidence row is recorded for this contribution",
      pivot,
      authorization: null,
    });
  });

  const device = entities.find((e) => e.kind === "device" && e.id);
  if (device) {
    const pivot = pivotTrajectory(device, incident);
    if (pivot) {
      out.push({
        id: `trajectory-${device.id}`,
        action: `Inspect the endpoint trajectory for ${device.value}`,
        reason: "The incident cites this endpoint identity in its endpoint campaign",
        evidence: (incident.endpoint_campaign?.rule_ids || []).length
          ? `endpoint rules ${incident.endpoint_campaign.rule_ids.join(", ")}`
          : "No endpoint rule is recorded on the campaign",
        pivot,
        authorization: null,
      });
    }
  }

  entities.forEach((e) => {
    const pivot = pivotIocIntelligence(e, incident);
    if (!pivot) return;
    out.push({
      id: `ioc-${e.value}`,
      action: `Check intelligence for the ${e.kind} ${e.value}`,
      reason: `The record carries this observable in ${e.source}`,
      evidence: "Observable read from the incident record",
      pivot,
      authorization: null,
    });
  });

  if (canonical.length && available.length) {
    const first = entities[0];
    const pivot = first ? pivotRelatedEvents(first, incident) : null;
    if (pivot) {
      out.push({
        id: "canonical-events",
        action: "Read the canonical events behind this incident",
        reason: `${canonical.length} canonical evidence row(s) are attached, and ${available.length} evidence domain(s) report available evidence`,
        evidence: `${canonical.length} canonical evidence id(s)`,
        pivot,
        authorization: null,
      });
    }
  }

  return out;
}

export default function RecommendedActions({ incident,
                                             testid = "incident-recommended" }) {
  const navigate = useNavigate();
  const items = recommendationsFor(incident);

  return (
    <NxSection
      title="Recommended next actions"
      aside={items.length ? `${items.length}` : null}
      note={items.length === 0
        ? "The record carries no fact that justifies a next step. NivXRay states that rather than generating generic advice."
        : "Derived deterministically from this record — every row cites the fact it came from. No action is recommended by a model."}
      testid={testid}
    >
      {items.map((r, i) => (
        <div key={r.id}
             style={{ display: "grid", gap: 4, padding: "8px 0",
                      borderBottom: "1px solid var(--nx-divider)" }}
             data-testid={`${testid}-item-${i}`}>
          <div style={{ display: "flex", alignItems: "center", gap: 10,
                        flexWrap: "wrap" }}>
            <strong style={{ fontSize: 12.5, color: "var(--nx-text)" }}>
              {r.action}
            </strong>
            <span style={{ flex: 1 }} />
            {r.authorization && (
              <NxChip tone="medium" variant="dashed"
                      title="This step changes the estate and is authorized separately">
                requires {r.authorization}
              </NxChip>
            )}
            <NxButton onClick={() => navigate(r.pivot.to)}
                      title={r.pivot.why}
                      testid={`${testid}-pivot-${i}`}>
              {r.pivot.label}
            </NxButton>
          </div>
          <span style={{ fontSize: 11.5, color: "var(--nx-text-dim)",
                         lineHeight: 1.55 }}>
            Reason · {r.reason}
          </span>
          <span style={{ fontSize: 11, color: "var(--nx-muted)",
                         lineHeight: 1.5 }}>
            Evidence · {r.evidence}
          </span>
        </div>
      ))}
    </NxSection>
  );
}
