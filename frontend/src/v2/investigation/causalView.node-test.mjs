// Run: node --test frontend/src/v2/investigation/*.node-test.mjs  (no install needed)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ACTOR_UNKNOWN, NET_CORRELATED, PARENT_PID_ONLY, PARENT_UNKNOWN, buildCausalContext, frameEdges,
  identityOf } from "./causalView.mjs";
import { buildActivityView } from "./activityView.mjs";

const FR = JSON.parse(readFileSync(new URL("../../../../backend/tests/edr_investigation/fixtures/dt_causal_frames.json",
  import.meta.url)));
const ctx = (id) => buildCausalContext(FR, id);
const states = (es) => es.map((e) => e.relationship_state);

test("1 proven parent/child", () => {
  const c = ctx("c_b");
  assert.deepEqual(states(c.groups.caused_by), ["PROVEN_CAUSAL"]);
  assert.equal(c.groups.caused_by[0].linkage, "SOURCE_PROCESS_GUID");
  assert.equal(c.groups.caused_by[0].source_entity, "proc_A");
});

test("2/3 process->file and process->network are SUPPORTED by the shared process identity", () => {
  const f = ctx("c_f").groups.caused_by[0], n = ctx("c_n").groups.caused_by[0];
  assert.deepEqual([f.relationship_type, f.relationship_state, f.source_entity], ["wrote", "SUPPORTED_RELATIONSHIP", "proc_B"]);
  assert.deepEqual([n.relationship_type, n.relationship_state, n.target_entity], ["connected_to", "SUPPORTED_RELATIONSHIP", "198.51.100.7"]);
  assert.deepEqual(ctx("c_b").groups.produced.map((e) => e.relationship_type), ["wrote", "connected_to"]);
});

test("4 proximity alone creates no relationship", () => {
  const q = ctx("c_q");
  assert.deepEqual(q.groups.caused_by, []);
  assert.equal(q.groups.unknown[0].reason, ACTOR_UNKNOWN);
  const b = ctx("c_b").groups;
  const corr = b.correlated.find((e) => e.provenance.frame_iid === "c_q");
  assert.equal(corr.relationship_state, "CORRELATED");
  assert.equal(corr.reason, NET_CORRELATED);
  assert.ok(!b.produced.some((e) => e.provenance.frame_iid === "c_q"));
  // 09:00 A, 09:01 B, 09:02 file C, 09:03 net D with no identities: no chain.
  const bare = ["a", "b", "c", "d"].map((x, i) => ({ frame_iid: x, ts: `2026-09-05T09:0${i}:00.000Z`,
    lane: ["process", "process", "file", "network"][i], label: x, remote_ip: "203.0.113.1" }));
  const all = bare.flatMap((f) => buildCausalContext(bare, f.frame_iid).edges);
  assert.ok(all.every((e) => ["UNKNOWN", "CORRELATED"].includes(e.relationship_state)));
});

test("5 missing parent identity is UNKNOWN, never guessed", () => {
  const w = ctx("c_w");
  assert.deepEqual(w.groups.caused_by, []);
  assert.equal(w.groups.unknown[0].reason, PARENT_UNKNOWN);
});

test("6 mixed chain keeps proven and unknown edges distinct", () => {
  const u = ctx("c_u").groups;
  assert.equal(u.unknown[0].reason, PARENT_PID_ONLY);
  assert.deepEqual(states(u.produced), ["PROVEN_CAUSAL"]);
  assert.equal(u.produced[0].target_entity, "proc_V");
});

test("PID equality never establishes identity", () => {
  assert.equal(identityOf({ pid: 4242 }).id, null);
  assert.equal(identityOf({ iid: "proc_Z", identity_basis: "PID_ONLY_NOT_GLOBALLY_STABLE" }).id, null);
  const e = frameEdges({ frame_iid: "p", ts: "2026-09-05T09:00:00Z", lane: "process",
    entity: { iid: "proc_C" }, parent: { pid: 100 } })[0];
  assert.equal(e.relationship_state, "UNKNOWN");
});

test("deterministic regardless of input order; chronology kept separate", () => {
  const rev = [...FR].reverse();
  assert.deepEqual(buildCausalContext(rev, "c_b"), ctx("c_b"));
  assert.ok(ctx("c_b").groups.preceded_by.every((p) => p.relation === "CHRONOLOGICAL_ONLY"));
});

test("Activity Details causal_context section carries the causal edges", () => {
  const v = buildActivityView(FR.find((f) => f.frame_iid === "c_u"), ctx("c_u"));
  const s = v.sections.find((x) => x.key === "causal_context");
  assert.equal(s.state, "AVAILABLE");
  assert.ok(v.sections.find((x) => x.key === "missing_evidence").items.some((m) => m.detail === PARENT_PID_ONLY));
});
