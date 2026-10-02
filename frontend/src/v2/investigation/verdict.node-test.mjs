// Run: node --test frontend/src/v2/investigation/*.node-test.mjs  (no install needed)
import test from "node:test";
import assert from "node:assert/strict";
import { VERDICT_LABEL, attributionOf, chainCounts, chainCountsText, machineAssessmentOf,
  trajectoryVerdict } from "./activityView.mjs";

const MATCH = { rule_id: "E3-SEQ-1", rule_version: 1, outcome: "MATCH", mitre: ["T1059.001"],
  contributing_frame_ids: ["f1"], evidence_refs: ["cev_1"] };
const F = { frame_iid: "f1", ts: "2026-09-05T09:00:00Z", lane: "process", mitre: ["T1059.001"] };
const HIST = [
  { version: 1, at: "2026-09-05T09:01:40Z", trigger: "INITIAL", assessment: "UNKNOWN" },
  { version: 2, at: "2026-09-05T11:41:00Z", trigger: "INTEL_CHANGE", assessment: "MALICIOUS", supersedes: 1 }];

test("a behavioral MATCH is DETECTED, never MALICIOUS", () => {
  const f = { ...F, investigation: { behavior: [MATCH] } };
  assert.equal(attributionOf(f), "detected");
  assert.equal(machineAssessmentOf(f), "NOT_ASSESSED");
  assert.equal(trajectoryVerdict(f), "detected");
  assert.equal(VERDICT_LABEL[trajectoryVerdict(f)], "DETECTED");
});

test("a rule detection is DETECTED, never MALICIOUS", () => {
  assert.equal(trajectoryVerdict({ ...F, rule_id: "R-1" }), "detected");
});

test("a real evidence-backed MALICIOUS assessment still renders MALICIOUS", () => {
  const f = { ...F, mitre: [], investigation: { history: HIST } };
  assert.equal(machineAssessmentOf(f), "MALICIOUS");
  assert.equal(trajectoryVerdict(f), "malicious");
  assert.equal(VERDICT_LABEL.malicious, "ASSESSED MALICIOUS");
});

test("an assessment that is not MALICIOUS keeps the detection distinct", () => {
  const f = { ...F, investigation: { behavior: [MATCH], history: [HIST[0]] } };
  assert.equal(trajectoryVerdict(f), "detected");
});

test("chain counts label what they count", () => {
  const c = chainCounts([{ detected: true, malicious: false }, { detected: true, malicious: false }, {}]);
  assert.deepEqual(c, { stages: 3, detected: 2, malicious: 0 });
  assert.equal(chainCountsText(c), "3 stages · 2 detected · 0 assessed malicious");
});
