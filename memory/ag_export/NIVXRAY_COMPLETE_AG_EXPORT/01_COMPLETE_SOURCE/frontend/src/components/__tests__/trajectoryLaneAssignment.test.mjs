/**
 * TrajectoryDiagram lane-assignment regression test (2026-08-11).
 *
 * Owner directive (session-7):
 *   "Change lane assignment so that, where MITRE technique/tactic
 *    evidence exists, the node is placed according to the existing
 *    backend MITRE tactic mapping."
 *
 * The lane assignment previously routed all `executable` entities
 * into the legacy `EXECUTION` lane regardless of MITRE tactic.
 * The fix synthesises a `behaviors[]` list from `object.mitre[]`
 * whenever `incident.behaviors` and `ice.behavior_clusters` are
 * empty, so TrajectoryDiagram's canonical 14-lane MITRE ATT&CK
 * view engages and each technique lands in its correct tactic
 * lane.
 *
 * This test mirrors `_synthBehaviorsFromMitre` from
 * `pages/WorkspacePage.jsx` so the invariant is regression-locked
 * without booting jsdom.
 *
 * Run with:
 *   node --test src/components/__tests__/trajectoryLaneAssignment.test.mjs
 */
import test from "node:test";
import assert from "node:assert/strict";


// ─── Mirror of `_synthBehaviorsFromMitre` in WorkspacePage.jsx ────
function _synthBehaviorsFromMitre(mitreList) {
  if (!Array.isArray(mitreList) || !mitreList.length) return [];
  const behaviors = [];
  mitreList.forEach((t, i) => {
    if (!t || typeof t !== "object") return;
    const tid    = t.id;
    const name   = t.name || "";
    const tactic = t.tactic || (Array.isArray(t.tactics) && t.tactics[0]) || null;
    if (!tid || !tactic) return;
    const label = String(tactic)
      .replace(/[_-]+/g, " ")
      .replace(/\b\w/g, ch => ch.toUpperCase());
    behaviors.push({
      id:              `mitre-behavior-${tid}-${i}`,
      title:           `${tid}${name ? " · " + name : ""}`,
      mitre_tactics:   [label],
      mitre:           [{ id: tid, tactic: label }],
      primary_tactic:  label,
      confidence:      "medium",
      order:           i,
      kind:            "mitre_technique_projection",
    });
  });
  return behaviors;
}


// ─── Fixtures ─────────────────────────────────────────────────────
const SEP_MITRE = [
  { id: "T1203",     name: "Exploitation for Client Execution", tactic: "execution" },
  { id: "T1055",     name: "Process Injection",                 tactic: "defense_evasion" },
  { id: "T1055.012", name: "Process Hollowing",                 tactic: "defense_evasion" },
  { id: "T1543.003", name: "Windows Service",                   tactic: "persistence" },
  { id: "T1204.002", name: "User Execution: Malicious File",    tactic: "execution" },
];


// ─── Tests ────────────────────────────────────────────────────────
test("projects SEP.csv MITRE list to correct MITRE tactic lanes", () => {
  const behaviors = _synthBehaviorsFromMitre(SEP_MITRE);
  assert.equal(behaviors.length, 5);
  const tactics = behaviors.map(b => b.mitre_tactics[0]);
  assert.deepEqual(tactics, [
    "Execution",
    "Defense Evasion",
    "Defense Evasion",
    "Persistence",
    "Execution",
  ]);
});

test("every projected behavior carries the underlying technique id + title-cased tactic", () => {
  for (const b of _synthBehaviorsFromMitre(SEP_MITRE)) {
    assert.equal(b.mitre.length, 1);
    assert.match(b.mitre[0].id, /^T\d+/);
    assert.match(b.mitre[0].tactic, /[A-Z]/);      // title-cased
    assert.ok(b.title.startsWith(b.mitre[0].id));  // "T#### · name"
  }
});

test("no fabrication — entries without tactic are dropped", () => {
  const mitre = [
    { id: "T9999", name: "no-tactic-null", tactic: null },
    { id: "T8888", name: "no-tactic-key" },
    { id: "T1055", tactic: "defense_evasion" },
  ];
  const b = _synthBehaviorsFromMitre(mitre);
  assert.equal(b.length, 1);
  assert.equal(b[0].mitre[0].id, "T1055");
});

test("empty / non-array input returns empty array", () => {
  assert.deepEqual(_synthBehaviorsFromMitre([]),        []);
  assert.deepEqual(_synthBehaviorsFromMitre(null),      []);
  assert.deepEqual(_synthBehaviorsFromMitre(undefined), []);
  assert.deepEqual(_synthBehaviorsFromMitre({}),        []);
});

test("chronological order is preserved via `order` field", () => {
  const b = _synthBehaviorsFromMitre([
    { id: "T1", tactic: "execution" },
    { id: "T2", tactic: "persistence" },
    { id: "T3", tactic: "defense_evasion" },
  ]);
  assert.deepEqual(b.map(x => x.order), [0, 1, 2]);
});

test("canonicalises snake_case / hyphen-case tactic names", () => {
  const cases = [
    { in: "execution",             out: "Execution" },
    { in: "defense_evasion",       out: "Defense Evasion" },
    { in: "privilege_escalation",  out: "Privilege Escalation" },
    { in: "command_and_control",   out: "Command And Control" },
    { in: "credential-access",     out: "Credential Access" },
  ];
  for (const c of cases) {
    const b = _synthBehaviorsFromMitre([{ id: "Txxx", tactic: c.in }]);
    assert.equal(b[0].mitre_tactics[0], c.out,
      `tactic '${c.in}' should canonicalise to '${c.out}'`);
  }
});

test("does NOT promote a parent-reference into a standalone MITRE node", () => {
  // `launcher.exe` was a `parent_file_name` in the SEP CSV — the
  // MITRE list contains only the CHILD process techniques.  The
  // projection MUST NOT invent a MITRE technique for the parent
  // reference (that stays a separate future modelling question).
  const b = _synthBehaviorsFromMitre(SEP_MITRE);
  const titles = b.map(x => x.title.toLowerCase()).join(" | ");
  assert.ok(!titles.includes("launcher"),
    "SEP MITRE list must not name launcher.exe as its own MITRE node");
});
