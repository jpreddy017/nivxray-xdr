/**
 * DT2-3 · PROCESS / RELATIONSHIP / TIME — focused acceptance.
 *
 * The contract under test is "the client infers nothing": lanes, lifelines,
 * connectors, attached activity, ordering and WHY all come from the
 * server-composed graph, and anything the evidence does not contain is
 * absent rather than guessed.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import {
  ACTIVITY_FAMILIES, FOCUS_UNRESOLVED, GRAPH_ABSENT, GRAPH_EMPTY, GRAPH_READY,
  SPAN_OBSERVED, SPAN_TERMINATED, activitiesFor, activityTimeMs,
  availabilityOf, childrenOf, edgeFor, familiesPresent, focusOf,
  graphBoundsOf, graphStateOf, laneRowsOf, lifelineOf, neighbourStep,
  parentOf, stepsOf, whyOf,
} from "../graphModel";

const CANVAS = readFileSync(
  new URL("../../RelationshipCanvas.jsx", import.meta.url), "utf8");

const ref = (v) => [{ kind: "raw_event_id", value: v }];
const pnode = (iid, over = {}) => ({
  node_id: `pnode:${iid}`, node_type: "PROCESS", process_iid: iid,
  label: iid, image: `/bin/${iid}`, pid: "100", process_guid: null,
  depth: 0, parent_node_id: null, parent_state: "NO_PARENT_EVIDENCE",
  child_node_ids: [], activity_node_ids: [],
  lifeline: { first_evidence_at: "2026-06-01T10:00:00Z",
              last_evidence_at: "2026-06-01T10:05:00Z", end_time: null,
              end_state: "PROCESS_END_EVIDENCE_UNAVAILABLE",
              exit_observed: false,
              basis: "EVIDENCE_SPAN_NOT_PROCESS_LIFETIME" },
  evidence_ref: ref(`raw-${iid}`), focus_targets: {}, ...over,
});

const GRAPH = {
  contract_version: "dt2.2e",
  endpoint_id: "dev_test",
  process_nodes: [
    pnode("parent", { child_node_ids: ["pnode:child"] }),
    pnode("child", {
      depth: 1, parent_node_id: "pnode:parent", parent_state: "OBSERVED",
      activity_node_ids: ["anode:child:dns", "anode:child:net",
                          "anode:child:file", "anode:child:reg"],
      lifeline: { first_evidence_at: "2026-06-01T10:01:00Z",
                  last_evidence_at: "2026-06-01T10:03:00Z",
                  end_time: "2026-06-01T10:03:30Z", end_state: "EXITED",
                  exit_observed: true, basis: "PROCESS_END_EVIDENCE" },
    }),
    pnode("orphan"),
  ],
  activity_nodes: ACTIVITY_FAMILIES.map((fam, i) => ({
    node_id: `anode:child:${fam.toLowerCase().slice(0, 4)}`,
    node_type: "ACTIVITY", family: fam, label: `${fam}-object`,
    process_iid: "child", process_node_id: "pnode:child",
    edge_id: `aedge:child:${fam}`,
    times: { source_time: `2026-06-01T10:0${i + 1}:30Z`,
             ordering_time: `2026-06-01T10:0${i + 1}:30Z` },
    evidence_ref: ref(`raw-${fam}`), focus_targets: {},
  })),
  edges: [
    { edge_id: "pedge:parent:child", relationship_type: "PROCESS_PROCESS",
      source_node_id: "pnode:parent", target_node_id: "pnode:child",
      derivation_basis: "CANONICAL_PARENT_PROCESS_IDENTITY",
      reason: "The child observation carried a canonical parent identity.",
      authority: "UNKNOWN", downgraded: true, evidence_ref: ref("raw-edge") },
    ...ACTIVITY_FAMILIES.map((fam) => ({
      edge_id: `aedge:child:${fam}`, relationship_type: `PROCESS_${fam}`,
      source_node_id: "pnode:child",
      target_node_id: `anode:child:${fam.toLowerCase().slice(0, 4)}`,
      derivation_basis: "SAME_OBSERVATION_PROCESS_IDENTITY",
      reason: "The activity was carried by the process's own observation.",
      authority: "DERIVED", downgraded: true, evidence_ref: ref(`raw-${fam}`) })),
  ],
  root_node_ids: ["pnode:parent", "pnode:orphan"],
  order: [
    { step_id: "s0", node_id: "pnode:child", actor_node_id: "pnode:parent",
      edge_id: "pedge:parent:child", edge_kind: "PROCESS_EDGE",
      link_to_previous: null, link_reason: "First step of the sequence." },
    { step_id: "s1", node_id: "anode:child:dns", actor_node_id: "pnode:child",
      edge_id: "aedge:child:DNS", edge_kind: "ACTIVITY_EDGE",
      link_to_previous: "CAUSALITY_UNKNOWN",
      link_reason: "Nearness in time is not causality." },
  ],
  navigation: { ordered_step_ids: ["s0", "s1"] },
  availability: { relationships: "AVAILABLE",
                  process_end_evidence: "UNAVAILABLE" },
  ranges: {}, focus: null, behaviors: [], sequences: [],
  detection_pivots: [], coverage: [], provenance: {},
};

// ── A/B · lifelines come from evidence, exits are never invented ──
describe("A/B · process lifelines", () => {
  it("renders one lane per server process node, ordered by evidence", () => {
    const lanes = laneRowsOf(GRAPH);
    expect(lanes.map((l) => l.nodeId))
      .toEqual(["pnode:parent", "pnode:child", "pnode:orphan"]);
    expect(graphStateOf({ graph: GRAPH })).toBe(GRAPH_READY);
    expect(graphStateOf({ graph: { process_nodes: [] } })).toBe(GRAPH_EMPTY);
    expect(graphStateOf({})).toBe(GRAPH_ABSENT);
  });

  it("never invents a process exit", () => {
    const open = lifelineOf(GRAPH.process_nodes[0]);
    expect(open.terminated).toBe(false);
    expect(open.semantics).toBe(SPAN_OBSERVED);
    expect(open.endState).toBe("PROCESS_END_EVIDENCE_UNAVAILABLE");
    expect(open.endMs).toBe(Date.parse("2026-06-01T10:05:00Z")); // last seen
    expect(availabilityOf(GRAPH).process_end_evidence).toBe("UNAVAILABLE");
    // only real exit evidence draws a terminated span
    expect(lifelineOf(GRAPH.process_nodes[1]).semantics)
      .toBe(SPAN_TERMINATED);
    // the canvas dashes the open span and only caps a terminated one
    expect(CANVAS).toMatch(/lane\.lifeline\.terminated \? "" : "4 3"/);
    expect(CANVAS).toMatch(/data-lifeline-semantics/);
  });

  it("bounds come only from observed evidence", () => {
    const b = graphBoundsOf(GRAPH);
    expect(b.min).toBe(Date.parse("2026-06-01T10:00:00Z"));
    expect(b.max).toBe(Date.parse("2026-06-01T10:05:00Z"));
  });
});

// ── C/D · a connector requires an evidence-backed edge ────────────
describe("C/D · parent/child relationships", () => {
  it("draws only where the server produced an edge", () => {
    expect(edgeFor(GRAPH, "pnode:parent", "pnode:child").edge_id)
      .toBe("pedge:parent:child");
    expect(edgeFor(GRAPH, "pnode:parent", "pnode:orphan")).toBeNull();
    expect(CANVAS).toMatch(/if \(!edge\) return null;/);
  });

  it("gives a process with no parent edge no parent", () => {
    expect(parentOf(GRAPH, "pnode:orphan")).toBeNull();
    expect(childrenOf(GRAPH, "pnode:orphan")).toEqual([]);
    expect(parentOf(GRAPH, "pnode:child").node_id).toBe("pnode:parent");
    expect(childrenOf(GRAPH, "pnode:parent").map((n) => n.node_id))
      .toEqual(["pnode:child"]);
  });

  it("infers nothing from time, image, user or pid", () => {
    // identical image/pid/user and adjacent times, no edge → no relationship
    const twins = { ...GRAPH, edges: [], root_node_ids: [],
                    process_nodes: [pnode("a"), pnode("b")] };
    expect(laneRowsOf(twins).every((l) => l.parentNodeId === null)).toBe(true);
    expect(edgeFor(twins, "pnode:a", "pnode:b")).toBeNull();
    for (const banned of ["proximity", "sameImage", "sameUser", "guessParent",
                          "inferParent"]) {
      expect(CANVAS).not.toContain(banned);
    }
  });
});

// ── E–H · attached activity, on the right process, at its own time ─
describe("E/F/G/H · attached DNS / NETWORK / FILE / REGISTRY", () => {
  it.each(ACTIVITY_FAMILIES)("%s attaches to its owning process", (fam) => {
    const a = activitiesFor(GRAPH, "pnode:child")
      .find((x) => x.family === fam);
    expect(a).toBeTruthy();
    expect(a.process_node_id).toBe("pnode:child");
    expect(activityTimeMs(a)).toBe(Date.parse(a.times.ordering_time));
    // the activity time is its own, not the process's start
    expect(activityTimeMs(a))
      .not.toBe(lifelineOf(GRAPH.process_nodes[1]).startMs);
  });

  it("attaches nothing to a process without activity evidence", () => {
    expect(activitiesFor(GRAPH, "pnode:parent")).toEqual([]);
    expect(activitiesFor(GRAPH, "pnode:orphan")).toEqual([]);
  });

  it("reports each family honestly, and fabricates none (S)", () => {
    expect(familiesPresent(GRAPH))
      .toEqual({ DNS: "OBSERVED", NETWORK: "OBSERVED", FILE: "OBSERVED",
                 REGISTRY: "OBSERVED" });
    expect(familiesPresent({ ...GRAPH, activity_nodes: [] }))
      .toEqual({ DNS: "NOT_OBSERVED", NETWORK: "NOT_OBSERVED",
                 FILE: "NOT_OBSERVED", REGISTRY: "NOT_OBSERVED" });
    // no sample/demo objects are baked into the renderer
    expect(CANVAS).not.toMatch(/example\.com|payload\.dll|1\.2\.3\.4/);
  });
});

// ── I · selection keeps the analyst's context ─────────────────────
describe("I · process selection", () => {
  it("changes only selection, never the viewport", () => {
    const onSelect = CANVAS.slice(CANVAS.indexOf("onClick={() => onSelect"));
    expect(onSelect).not.toMatch(/onView|setView|fitRange|centreOn/);
    expect(CANVAS).toMatch(/data-lane-selected/);
    expect(CANVAS).toMatch(/data-dt2-selected=\{selectedNodeId/);
  });
});

// ── J/K · parent / child navigation ──────────────────────────────
describe("J/K · relationship navigation", () => {
  it("parent navigation focuses the evidenced parent", () => {
    expect(parentOf(GRAPH, "pnode:child").node_id).toBe("pnode:parent");
    expect(CANVAS).toMatch(/dt2-goto-parent/);
    expect(CANVAS).toMatch(/disabled=\{!parent\}/);
  });

  it("child navigation focuses an evidenced child", () => {
    expect(childrenOf(GRAPH, "pnode:parent")[0].node_id).toBe("pnode:child");
    expect(CANVAS).toMatch(/dt2-goto-child/);
    expect(CANVAS).toMatch(/disabled=\{!kids\.length\}/);
  });
});

// ── L/M · before/after is ordering, not causality ────────────────
describe("L/M · before / after", () => {
  it("steps through the server's evidence ordering", () => {
    expect(stepsOf(GRAPH).map((s) => s.step_id)).toEqual(["s0", "s1"]);
    const after = neighbourStep(GRAPH, { stepId: "s0" }, 1);
    expect(after.step.step_id).toBe("s1");
    const before = neighbourStep(GRAPH, { stepId: "s1" }, -1);
    expect(before.step.step_id).toBe("s0");
    expect(neighbourStep(GRAPH, { stepId: "s1" }, 1)).toBeNull();
  });

  it("never turns temporal order into a causal claim", () => {
    const after = neighbourStep(GRAPH, { stepId: "s0" }, 1);
    expect(after.causality).toBe("CAUSALITY_UNKNOWN");
    expect(after.implies_causality).toBe(false);
    expect(after.causalityReason).toMatch(/not causality/i);
    expect(CANVAS).toMatch(/data-causality=\{step\.causality\}/);
  });
});

// ── N/O · exact focus or an explicit unresolved state ────────────
describe("N/O · exact focus", () => {
  it("resolves the exact evidence when the server did", () => {
    const f = focusOf({ ...GRAPH,
      focus: { state: "RESOLVED_EXACT", basis: "RAW_EVENT_ID",
               process_iid: "child", process_node_id: "pnode:child",
               observation_id: "evt_1" } });
    expect(f.exact).toBe(true);
    expect(f.nodeId).toBe("pnode:child");
    expect(f.observationId).toBe("evt_1");
  });

  it("stays explicitly unresolved instead of picking something near", () => {
    const f = focusOf({ ...GRAPH,
      focus: { state: "RESOLVED_TIMESTAMP_ONLY", basis: "TIMESTAMP",
               timestamp_only: "2026-06-01T10:02:00Z", process_iid: "child" } });
    expect(f.exact).toBe(false);
    expect(f.nodeId).toBeNull();
    expect(f.state).toBe("RESOLVED_TIMESTAMP_ONLY");
    expect(focusOf(GRAPH).state).toBe(FOCUS_UNRESOLVED);
  });
});

// ── P · WHY corresponds to the real edge ─────────────────────────
describe("P · relationship basis", () => {
  it("reports the server's own basis, reason and evidence count", () => {
    const why = whyOf(edgeFor(GRAPH, "pnode:parent", "pnode:child"));
    expect(why.basis).toBe("CANONICAL_PARENT_PROCESS_IDENTITY");
    expect(why.reason).toBe(GRAPH.edges[0].reason);
    expect(why.downgraded).toBe(true);
    expect(why.evidenceCount).toBe(1);
    expect(whyOf(null)).toBeNull();
  });

  it("invents no explanation when there is no edge", () => {
    expect(CANVAS).toMatch(/dt2-why-none/);
    expect(CANVAS).toMatch(/NO PARENT EDGE IN EVIDENCE/);
  });
});

// ── Q/R · bounded rendering and stale-request safety ─────────────
describe("Q/R · density and request safety", () => {
  it("caps rendered lanes with the DT2-1 bound", () => {
    const many = { ...GRAPH, root_node_ids: [],
                   process_nodes: Array.from({ length: 400 },
                                             (_, i) => pnode(`p${i}`)) };
    expect(laneRowsOf(many).length).toBe(120);
    expect(laneRowsOf(many, { max: 20 }).length).toBe(20);
    expect(CANVAS).toMatch(/MAX_RENDERED_LANES/);
    expect(CANVAS).toMatch(/lanes\.slice\(0, rows\)/);
  });

  it("issues no request of its own, so none can arrive stale", () => {
    expect(CANVAS).not.toMatch(/fetch\(|api\.get|api\.post|axios/);
    expect(CANVAS).toMatch(/graph, view, bounds/);       // props only
  });
});

// ── T · tenant authority stays server-derived ────────────────────
describe("T · tenant authority", () => {
  it("the trajectory view never touches tenant state", () => {
    expect(CANVAS).not.toMatch(/localStorage|X-Tenant-Id|tenant/i);
  });
});
