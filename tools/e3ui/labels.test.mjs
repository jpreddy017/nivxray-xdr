import test from "node:test";
import assert from "node:assert/strict";
import { ACTIVITY_FILTERS, EVENT_LABEL, KIND, LEGEND, SYSTEM_FILTERS, enforcementLabel, hasPresentTense } from "../../apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/labels.js";

test("lint itself catches present-tense standalone verbs", () => {
  for (const bad of ["Execute", "Execute blocked", "File delete", "Create", "Move", "Scan", "Quarantine", "Quarantine failed"]) assert.ok(hasPresentTense(bad), bad);
  for (const good of ["Executed", "Execution Blocked", "Deleted", "Quarantine Failed — access denied", "Scan Detected"]) assert.ok(!hasPresentTense(good), good);
});

test("every rendered event label is past tense (chips, Activity rows, tooltip, legend, Filters)", () => {
  const labels = [...Object.values(EVENT_LABEL), ...Object.values(KIND).map((k) => k.label), ...Object.values(KIND).map((k) => k.verb),
    ...ACTIVITY_FILTERS.map((x) => x[1]), ...SYSTEM_FILTERS.map((x) => x[1]), ...LEGEND.map((x) => x[1])];
  const bad = labels.filter((l) => hasPresentTense(l));
  assert.deepEqual(bad, []);
  assert.equal(KIND.process_create.label, "Executed");
});

test("quarantine outcomes state the reason from evidence only", () => {
  assert.equal(enforcementLabel(null), "No enforcement/response evidence recorded.");
  assert.equal(enforcementLabel({ outcome: "QUARANTINED" }), "Quarantined");
  assert.equal(enforcementLabel({ outcome: "QUARANTINE_FAILED", reason: "access denied" }), "Quarantine Failed — access denied");
  assert.equal(enforcementLabel({ outcome: "QUARANTINE_FAILED", detail: "x" }), "Quarantine Failed — reason not reported by sensor");
  assert.equal(enforcementLabel({ outcome: "NOT_QUARANTINED", reason: "audit mode" }), "Not Quarantined — audit mode");
  assert.equal(enforcementLabel({ outcome: "NOT_QUARANTINED" }), "Not Quarantined — reason not reported");
});
