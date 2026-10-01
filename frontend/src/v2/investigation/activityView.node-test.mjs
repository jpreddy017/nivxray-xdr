// Run: node --test frontend/src/v2/investigation/activityView.node-test.mjs  (no install needed)
import test from "node:test";
import assert from "node:assert/strict";
import { ABSENCE, NO_DETECTION, SECTION_KEYS, attributionOf, buildActivityView, mitreItems } from "./activityView.mjs";

const FRAME = { frame_iid: "tf_1", ts: "2026-09-05T03:00:02Z", lane: "process", action: "process_create",
  label: "powershell.exe", canonical_evidence_id: "cev_1", evidence_ids: ["a-p"], mitre: ["T1059.001", "T1027"],
  parent: { iid: "proc_AW" }, entity: { iid: "proc_AP" }, bridge_state: "BRIDGED", sha256: "a".repeat(64) };
const sec = (v, k) => v.sections.find((s) => s.key === k);

test("15 sections in contract order; unwired sources say NOT_WIRED", () => {
  const v = buildActivityView(FRAME);
  assert.deepEqual(v.sections.map((s) => s.key), SECTION_KEYS);
  for (const k of ["behavioral", "ml", "retrospection", "response", "verification"])
    assert.equal(sec(v, k).state, "NOT_WIRED");
  assert.equal(v.machine_assessment, "NOT_ASSESSED");
});

test("no MITRE and no rule is UNKNOWN, never benign", () => {
  assert.equal(attributionOf({}), "unknown");
  assert.equal(attributionOf({ mitre: [] }), "unknown");
});

test("MITRE without a detection is unattributed and neutral (F1-F3)", () => {
  assert.equal(attributionOf({ mitre: ["T1003"] }), "unattributed");
  assert.deepEqual(new Set(mitreItems(FRAME).map((m) => m.style)), new Set(["neutral"]));
  const v = buildActivityView(FRAME);
  assert.deepEqual(sec(v, "detection_attribution").statements, [NO_DETECTION, ABSENCE]);
  assert.equal(sec(v, "detection_attribution").state, "EMPTY");
});

test("rule-attributed frame is detected, chips threat-styled", () => {
  const f = { ...FRAME, rule_id: "R-1" };
  assert.equal(attributionOf(f), "detected");
  assert.ok(mitreItems(f).every((m) => m.style === "threat"));
  assert.equal(sec(buildActivityView(f), "detection_attribution").items[0].rule_id, "R-1");
});

test("missing parent yields UNKNOWN edge, never an inferred one", () => {
  const v = buildActivityView({ ...FRAME, parent: null });
  const [edge] = sec(v, "causal_context").items;
  assert.equal(edge.state, "UNKNOWN");
  assert.equal(edge.target, null);
  assert.ok(sec(v, "missing_evidence").items.some((m) => m.source === "causal"));
});

test("TI for observables is UNKNOWN (not served), never benign; output is deterministic", () => {
  const v = buildActivityView(FRAME);
  assert.ok(sec(v, "threat_intel").items.every((i) => i.state === "UNKNOWN"));
  assert.deepEqual(buildActivityView(structuredClone(FRAME)), v);
  assert.ok(!JSON.stringify(v).toLowerCase().includes('"benign"'));
  assert.ok(!JSON.stringify(v).toLowerCase().includes('"clean"'));
});

import { participatingFrameIds } from "./activityView.mjs";

test("behavioral MATCH attributes only claimed techniques and lists only contributing frames", () => {
  const f = { ...FRAME, investigation: { synthetic: true, behavior: [{ rule_id: "E3-SEQ-001", rule_version: 2,
    outcome: "MATCH", mitre: ["T1059.001"], contributing_frame_ids: ["tf_1", "tf_0"], evidence_refs: ["k1"] }] } };
  assert.equal(attributionOf(f), "detected");
  assert.deepEqual(participatingFrameIds(f), ["tf_0", "tf_1"]);
  assert.deepEqual(Object.fromEntries(mitreItems(f).map((m) => [m.technique, m.style])),
                   { "T1027": "neutral", "T1059.001": "threat" });
  assert.equal(sec(buildActivityView(f), "detection_attribution").items[0].rule_version, 2);
  assert.deepEqual(participatingFrameIds(FRAME), []);
});

test("TI outage is UNAVAILABLE, never benign; provider-less reputation is UNKNOWN", () => {
  const f = { ...FRAME, investigation: { ti: [{ indicator: "203.0.113.7", type: "ip", provider: "abuseipdb",
    state: "UNAVAILABLE" }, { indicator: "x", type: "ip", provider: null, state: "BENIGN" }] } };
  const t = sec(buildActivityView(f), "threat_intel");
  assert.deepEqual(t.items.map((i) => i.state), ["UNAVAILABLE", "UNKNOWN"]);
  assert.ok(t.statements.some((s) => s.includes("unavailable")));
});

test("retrospective history is append-only and drives machine assessment; V1 retained", () => {
  const h = [{ version: 1, at: "09:00", trigger: "INITIAL", assessment: "UNKNOWN" },
             { version: 2, at: "11:41", trigger: "INTEL_CHANGE", assessment: "MALICIOUS", supersedes: 1 }];
  const v = buildActivityView({ ...FRAME, investigation: { history: h } });
  assert.equal(v.machine_assessment, "MALICIOUS");
  assert.deepEqual(sec(v, "retrospection").items.map((i) => i.assessment), ["UNKNOWN", "MALICIOUS"]);
  assert.throws(() => buildActivityView({ ...FRAME, investigation: { history: [h[1]] } }));
});

test("response REQUESTED/ACCEPTED/EXECUTED are not verified; nothing says contained", () => {
  const r = ["REQUESTED", "ACCEPTED", "EXECUTED", "VERIFIED", "BOGUS"].map((s, i) =>
    ({ command_id: `c${i}`, action: "ISOLATE_ENDPOINT", state: s }));
  const v = buildActivityView({ ...FRAME, investigation: { response: r } });
  assert.deepEqual(sec(v, "verification").items.map((i) => i.verified), [false, false, false, true, false]);
  assert.equal(sec(v, "response").items[4].state, "UNKNOWN_STATE");
  assert.ok(!JSON.stringify(sec(v, "response").items).toLowerCase().includes("contained"));
});

test("ML TESTING and cold-start reasons surface as missing evidence, never a verdict", () => {
  const v = buildActivityView({ ...FRAME, investigation: { ml: [{ model_id: "ml.rarity.process_tree",
    model_version: "1.0.0", lifecycle: "TESTING", outcome: "INSUFFICIENT_BASELINE", reasons: ["coverage 0 < 0.75"] }] } });
  assert.equal(sec(v, "ml").items[0].lifecycle, "TESTING");
  assert.ok(sec(v, "missing_evidence").items.some((m) => m.source === "edr_ml"));
  assert.equal(v.machine_assessment, "NOT_ASSESSED");
});
