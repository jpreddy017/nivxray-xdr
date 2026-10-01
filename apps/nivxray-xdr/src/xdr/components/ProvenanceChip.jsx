/**
 * ProvenanceChip · "is that a real incident?" answered on the row.
 *
 * Owner directive 2026-06. The vocabulary is closed and defined by the
 * backend (`services/incident_provenance.py`); this component renders it
 * and never derives it.
 *
 * `PROVENANCE_UNKNOWN` is deliberately toned NEUTRAL, not as an error:
 * it means the origin could not be established from evidence, which is
 * an honest absence — not a claim that the incident is fabricated.
 * Only `REAL_SENSOR_DERIVED` may read as real-world activity.
 */
import React from "react";
import { NxChip } from "@/xdr/nx";

const SPEC = {
  REAL_SENSOR_DERIVED:    ["REAL", "mint",
    "Every piece of evidence traces to telemetry delivered by an "
    + "authenticated sensor on a real endpoint."],
  SEEDED_FOR_DEVELOPMENT: ["SEEDED", "amber",
    "Created by a seed or development fixture. Declared at write time, "
    + "never inferred."],
  SYNTHETIC_TEST:         ["SYNTHETIC", "amber",
    "Produced by a test harness or a test principal."],
  REPLAY_DERIVED:         ["REPLAY", "low",
    "Derived from a replayed corpus: real-shaped evidence, but not "
    + "observed live in this environment."],
  MIXED_PROVENANCE:       ["MIXED", "purple",
    "Evidence of more than one provenance class was consolidated into "
    + "this incident."],
  PROVENANCE_UNKNOWN:     ["UNKNOWN", "faint",
    "Origin could NOT be established from evidence. This is an honest "
    + "absence, not a guess, and not a claim that the incident is fake."],
};

export const ProvenanceChip = ({ value, basis }) => {
  const key = SPEC[value] ? value : "PROVENANCE_UNKNOWN";
  const [label, tone, meaning] = SPEC[key];
  return (
    <NxChip
      tone={tone}
      variant={key === "REAL_SENSOR_DERIVED" ? "solid" : "tinted"}
      size="sm"
      data-testid={`incident-provenance-${key}`}
      data-provenance={key}
      title={`${key}\n\n${meaning}${basis ? `\n\nBasis: ${basis}` : ""}`}
    >
      {label}
    </NxChip>
  );
};

export default ProvenanceChip;
