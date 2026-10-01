/**
 * E3 · the detail pane must tell three DIFFERENT stories apart:
 *
 *   1. a rule matched      -> the FINDING is the authoritative record
 *   2. evaluated, no match -> said explicitly, and never as "benign"
 *   3. never evaluated     -> said explicitly, as a detection GAP
 *
 * Before this, an observation the engine had matched via the finding
 * plane rendered "Not evaluated", and an observation nothing had looked
 * at rendered identically to one that was cleanly evaluated.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { isRed } from "../../ampModel";

const read = (f) =>
  readFileSync(new URL(`../../${f}`, import.meta.url), "utf8");

const DETAILS = read("AmpEventDetails.jsx");

describe("A · a matched finding is the authoritative record", () => {
  it("renders the finding block when there is no raw derivation", () => {
    expect(DETAILS).toContain("(!event.detection && findings.length) ?");
    expect(DETAILS).toContain("amp-detection-findings");
  });

  it("shows the producing rule, its version, severity and ATT&CK", () => {
    for (const id of ["amp-d-finding-rule-", "amp-d-finding-severity-",
                      "amp-d-finding-attck-", "amp-d-finding-engine-",
                      "amp-d-finding-evaluated-", "amp-d-finding-id-"]) {
      expect(DETAILS).toContain(id);
    }
  });

  it("states the basis of the finding and of its ATT&CK", () => {
    expect(DETAILS).toContain("f.detection_source");
    expect(DETAILS).toContain("f.attck_basis");
  });

  it("reads findings from the event or the evaluation ledger", () => {
    expect(DETAILS).toContain("event.findings || ev.findings || []");
  });
});

describe("B · evaluated-with-no-match is its own answer", () => {
  it("is driven by the assessment state, not by silence", () => {
    expect(DETAILS).toContain(
      'event.assessment_state === "EVALUATED_NO_DETECTION"');
    expect(DETAILS).toContain('ev.state === "EVALUATED_NO_FINDING"');
  });

  it("says Evaluated · no rule matched, and names who evaluated it", () => {
    expect(DETAILS).toContain("Evaluated · no rule matched.");
    expect(DETAILS).toContain("amp-detection-evaluated-by");
    expect(DETAILS).toContain("ev.analyzer_id");
    expect(DETAILS).toContain("ev.evaluated_at");
  });

  it("carries the server's stated meaning rather than inventing one", () => {
    expect(DETAILS).toContain("event.evaluation_meaning");
    expect(DETAILS).toContain("amp-detection-evaluated-meaning");
  });

  it("exposes the state for assertions", () => {
    expect(DETAILS).toContain("data-assessment-state={event.assessment_state");
  });
});

describe("C · never-evaluated is a GAP, not a clean verdict", () => {
  it("says Not evaluated and calls it a detection gap", () => {
    expect(DETAILS).toContain("Not evaluated.");
    expect(DETAILS).toContain("detection gap, not an ");
  });

  it("never describes an unexamined observation as benign or clean", () => {
    const window = DETAILS.slice(DETAILS.indexOf("amp-detection-none"),
                                 DETAILS.indexOf("amp-detected-by"));
    expect(window.toLowerCase()).not.toContain("benign");
    expect(window.toLowerCase()).not.toContain("no threat");
    expect(window.toLowerCase()).not.toContain("is clean");
  });

  it("distinguishes the two cases in Detected By as well", () => {
    expect(DETAILS).toContain(
      "No detection engine has evaluated this observation yet.");
  });
});

describe("D · red is still only an authoritative claim", () => {
  it("EVALUATED_NO_DETECTION is never painted as malicious", () => {
    expect(isRed({ assessment_state: "EVALUATED_NO_DETECTION",
                   is_detection: true })).toBe(false);
    expect(isRed({ assessment_state: "NOT_EVALUATED",
                   is_detection: true })).toBe(false);
  });

  it("an assessed detection or a MALICIOUS disposition is red", () => {
    expect(isRed({ assessment_state: "ASSESSED_BY_DETECTION_FABRIC",
                   is_detection: true })).toBe(true);
    expect(isRed({ disposition: "MALICIOUS" })).toBe(true);
  });
});

describe("E · ATT&CK is only shown as a claim when a rule declared it", () => {
  it("the box is neutral unless something is attributed", () => {
    expect(DETAILS).toContain('data-mitre-attributed={attributed');
    expect(DETAILS).toContain("attributed ? C.malicious : C.paperAlt");
  });
});
