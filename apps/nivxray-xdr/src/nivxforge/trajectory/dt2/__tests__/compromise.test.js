/**
 * DT2-3c · the compromise / IOC model contains NO inference.
 *
 * Contributor membership arrives already proven by an authority and
 * resolved by the server against `observation_id`. The client may only
 * join on identity — never on time, PID, lane, label or render
 * adjacency — and an absent compromise is never softened into "clean".
 */
import { readFileSync } from "node:fs";
import { describe, expect, test } from "vitest";

import {
  CONTRIBUTORS_NOT_PROVEN,
  NOT_OBSERVED,
  attachContributors,
  compromisesInWindow,
  compromisesOfRow,
  contributionBasisOf,
  contributorIdsOf,
  indexCompromise,
  isProvenContributor,
  mitreOf,
} from "../compromise";

/** The source with comments stripped: the prose EXPLAINS which
 *  inferences are forbidden, so only executable code is scanned. */
const CODE = readFileSync(
  new URL("../compromise.js", import.meta.url), "utf8")
  .replace(/\/\*[\s\S]*?\*\//g, "")
  .replace(/^\s*\/\/.*$/gm, "");
const GRAPH_SRC = readFileSync(
  new URL("../graphModel.js", import.meta.url), "utf8");

const OBS_A = "obs_aaaa";
const OBS_TWIN = "obs_bbbb";
const OBS_MISSING = "obs_gone";

const payload = (over = {}) => ({
  compromise_contract: {
    state: "AUTHORITATIVE_COMPROMISES_RESOLVED",
    reference_identity: "observation_id",
    resolved_server_side: true,
    frontend_may_infer_contributors: false,
    rejected: [],
  },
  compromise_events: [{
    compromise_event_id: "cmp_1",
    indicator_id: "sigma@1.4.0",
    authority: "DETECTION_FABRIC_ATTRIBUTION",
    derivation_basis: "DETECTION_FABRIC_DERIVATION_ON_RAW_EVENT",
    description: "rules: win_susp_registry_run_key",
    contributors_state: "CONTRIBUTORS_PROVEN_BY_AUTHORITY",
    contributing_event_refs: [
      { observation_id: OBS_A,
        contribution_basis: "DETECTION_DERIVATION_SUBJECT_OBSERVATION",
        stated_by: "DETECTION_FABRIC_ATTRIBUTION",
        resolution_state: "RESOLVED_TO_OBSERVATION" },
      { observation_id: OBS_MISSING,
        contribution_basis: "DETECTION_DERIVATION_NAMED_EVIDENCE_ID",
        stated_by: "DETECTION_FABRIC_ATTRIBUTION",
        resolution_state: "UNRESOLVED_NOT_IN_PROJECTION" },
    ],
    resolved_observation_ids: [OBS_A],
    unresolved_event_refs: [{ observation_id: OBS_MISSING,
      resolution_state: "UNRESOLVED_NOT_IN_PROJECTION" }],
    tactics: ["TA0003"],
    techniques: ["T1547.001"],
    observed_at: "2026-09-22T16:20:09.743Z",
  }],
  ...over,
});

describe("the model reads the contract and never guesses", () => {
  test("no inference primitive appears in the source", () => {
    for (const forbidden of [/proximity/i, /same_pid/i, /nearest/i,
                             /Math\.abs\(/, /within\s*\d+\s*ms/i,
                             /is_detection/, /\bpid\b/, /\blabels\b/]) {
      expect(CODE).not.toMatch(forbidden);
    }
  });

  test("the graph model no longer infers a compromise from detections", () => {
    expect(GRAPH_SRC).not.toMatch(/is_detection === true/);
    expect(GRAPH_SRC).toMatch(/export const isProvenContributor/);
  });

  test("the contract's own flags are surfaced, not assumed", () => {
    const layer = indexCompromise(payload());
    expect(layer.referenceIdentity).toBe("observation_id");
    expect(layer.inferenceAllowed).toBe(false);
    expect(layer.observed).toBe(true);
  });
});

describe("absence is reported, never softened", () => {
  test.each([
    ["no payload", null],
    ["empty payload", {}],
    ["explicit empty list", { compromise_events: [] }],
  ])("%s yields NOT OBSERVED", (_label, input) => {
    const layer = indexCompromise(input);
    expect(layer.observed).toBe(false);
    expect(layer.events).toEqual([]);
    expect(layer.state).toBe(NOT_OBSERVED);
  });

  test("the server's own not-observed state is preserved verbatim", () => {
    const layer = indexCompromise({
      compromise_events: [],
      compromise_contract: { state: NOT_OBSERVED } });
    expect(layer.state).toBe(NOT_OBSERVED);
  });
});

describe("contributor emphasis follows the authority", () => {
  test("a row is a contributor only when the server said so", () => {
    expect(isProvenContributor({ contributor_of: ["cmp_1"] })).toBe(true);
    expect(contributorIdsOf({ contributor_of: ["cmp_1"] })).toEqual(["cmp_1"]);
  });

  test.each([
    ["a detection flag", { is_detection: true }],
    ["a detection record", { detection: { verdict: "MALICIOUS" } }],
    ["a DETECTION label", { labels: ["DETECTION"] }],
    ["a malicious disposition", { disposition: "MALICIOUS" }],
    ["MITRE on the observation", { mitre: ["T1547.001"] }],
    ["an empty contributor list", { contributor_of: [] }],
    ["nothing at all", {}],
    ["null", null],
  ])("%s does NOT make a contributor", (_label, node) => {
    expect(isProvenContributor(node)).toBe(false);
  });

  test("a row resolves back to the compromise and the stated basis", () => {
    const layer = indexCompromise(payload());
    const row = { observation_id: OBS_A, contributor_of: ["cmp_1"] };
    const [c] = compromisesOfRow(layer, row);
    expect(c.indicator_id).toBe("sigma@1.4.0");
    expect(contributionBasisOf(c, OBS_A)).toBe(
      "DETECTION_DERIVATION_SUBJECT_OBSERVATION");
    expect(contributionBasisOf(c, OBS_TWIN)).toBeNull();
  });
});

describe("the identity join only matches a node's own references", () => {
  const graph = {
    process_nodes: [{
      node_id: "p1",
      evidence_ref: [{ kind: "OBSERVATION", id: OBS_A },
                     { kind: "RAW_EVENT", id: "raw_1" }],
    }, {
      node_id: "p2",
      evidence_ref: [{ kind: "OBSERVATION", id: OBS_TWIN }],
    }],
    activity_nodes: [{
      node_id: "a1",
      evidence_ref: [{ kind: "OBSERVATION", id: OBS_A }],
    }, {
      node_id: "a2", evidence_ref: [],
    }],
  };

  test("exactly the referenced nodes are stamped", () => {
    const out = attachContributors(graph, indexCompromise(payload()));
    expect(out.process_nodes[0].contributor_of).toEqual(["cmp_1"]);
    expect(out.process_nodes[0].contributor_state)
      .toBe("PROVEN_BY_AUTHORITY");
    expect(out.process_nodes[1].contributor_of).toBeUndefined();
    expect(out.activity_nodes[0].contributor_of).toEqual(["cmp_1"]);
    expect(out.activity_nodes[1].contributor_of).toBeUndefined();
  });

  test("a RAW_EVENT reference with a matching id is not a contributor", () => {
    const layer = indexCompromise(payload({
      compromise_events: [{
        ...payload().compromise_events[0],
        resolved_observation_ids: ["raw_1"],
      }] }));
    const out = attachContributors(graph, layer);
    expect(out.process_nodes[0].contributor_of).toBeUndefined();
  });

  test("an unresolved reference stamps nothing", () => {
    const layer = indexCompromise(payload({
      compromise_events: [{
        ...payload().compromise_events[0],
        resolved_observation_ids: [],
        contributors_state: CONTRIBUTORS_NOT_PROVEN,
      }] }));
    const out = attachContributors(graph, layer);
    expect(out.process_nodes.every((n) => !n.contributor_of)).toBe(true);
    expect(out.activity_nodes.every((n) => !n.contributor_of)).toBe(true);
  });

  test("no compromise leaves the graph exactly as it was", () => {
    const out = attachContributors(graph, indexCompromise(null));
    expect(out).toBe(graph);
  });
});

describe("viewport and MITRE presentation", () => {
  const layer = indexCompromise(payload());
  const t = Date.parse("2026-09-22T16:20:09.743Z");

  test("a compromise is placed by its OWN recorded instant", () => {
    expect(compromisesInWindow(layer, t - 1000, t + 1000)).toHaveLength(1);
    expect(compromisesInWindow(layer, t + 1, t + 1000)).toHaveLength(0);
  });

  test("a compromise with no recorded time is never placed", () => {
    const noTime = indexCompromise(payload({
      compromise_events: [{ ...payload().compromise_events[0],
        observed_at: null }] }));
    expect(compromisesInWindow(noTime, 0, 9e15)).toHaveLength(0);
  });

  test("MITRE is presented only when it was carried", () => {
    expect(mitreOf(layer.events[0])).toEqual({
      tactics: ["TA0003"], techniques: ["T1547.001"], state: "ATTRIBUTED" });
    expect(mitreOf({}).state).toBe("NO_MITRE_ATTRIBUTION_CARRIED");
  });
});

/**
 * OWNER-REQUIRED REGRESSION · the content-identity collision defect.
 *
 * On the real Windows corpus 2,250 of 3,299 genuinely distinct records
 * share one `event.iid`, because identical content hashes identically.
 * Two such twins must NEVER share contributor emphasis: only the
 * observation the authority actually named may be emphasised.
 */
describe("content-identical twins do not share contributor emphasis", () => {
  const CONTENT_IID = "evt_identical_content";
  const twinGraph = () => ({
    process_nodes: [],
    activity_nodes: [
      { node_id: "act_named", family: "REGISTRY", iid: CONTENT_IID,
        event_iid: CONTENT_IID,
        evidence_ref: [{ kind: "OBSERVATION", id: OBS_A }] },
      { node_id: "act_twin", family: "REGISTRY", iid: CONTENT_IID,
        event_iid: CONTENT_IID,
        evidence_ref: [{ kind: "OBSERVATION", id: OBS_TWIN }] },
    ],
  });

  const layerNaming = (observationId) => indexCompromise(payload({
    compromise_events: [{
      ...payload().compromise_events[0],
      contributing_event_refs: [{
        observation_id: observationId,
        contribution_basis: "DETECTION_DERIVATION_SUBJECT_OBSERVATION",
        stated_by: "DETECTION_FABRIC_ATTRIBUTION",
        resolution_state: "RESOLVED_TO_OBSERVATION" }],
      resolved_observation_ids: [observationId],
      unresolved_event_refs: [],
    }] }));

  test("the two twins really do share the content identity", () => {
    const [named, twin] = twinGraph().activity_nodes;
    expect(named.event_iid).toBe(twin.event_iid);
    expect(named.evidence_ref[0].id).not.toBe(twin.evidence_ref[0].id);
  });

  test("only the NAMED observation is emphasised", () => {
    const out = attachContributors(twinGraph(), layerNaming(OBS_A));
    const [named, twin] = out.activity_nodes;
    expect(isProvenContributor(named)).toBe(true);
    expect(named.contributor_of).toEqual(["cmp_1"]);
    expect(isProvenContributor(twin)).toBe(false);
    expect(twin.contributor_of).toBeUndefined();
  });

  test("naming the OTHER twin moves the emphasis, and only it", () => {
    const out = attachContributors(twinGraph(), layerNaming(OBS_TWIN));
    const [named, twin] = out.activity_nodes;
    expect(isProvenContributor(named)).toBe(false);
    expect(isProvenContributor(twin)).toBe(true);
    expect(twin.contributor_of).toEqual(["cmp_1"]);
  });

  test("emphasis is never spread by the shared content identity", () => {
    const out = attachContributors(twinGraph(), layerNaming(OBS_A));
    const emphasised = out.activity_nodes.filter(isProvenContributor);
    expect(emphasised).toHaveLength(1);
    expect(emphasised[0].node_id).toBe("act_named");
  });
});
