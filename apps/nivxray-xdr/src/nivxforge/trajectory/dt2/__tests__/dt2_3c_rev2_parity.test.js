/**
 * DT2-3c REV 2 · owner corrections against the LIVE Cisco Secure
 * Endpoint console captures (which now outrank the User Guide figure).
 *
 * 1. the full-height yellow IOC time column is REMOVED from strict
 *    Cisco parity mode — it was a NivXForge design decision, uncited;
 * 2. a compromise is a SEPARATE EVENT on its OWN band, so it stays
 *    distinguishable from its contributing observations even when it
 *    shares their instant. No timestamp is altered to achieve that;
 * 3. the surface is DARK, because the live Cisco console is dark;
 * 4. `?from=&to=` focuses the viewport, never the evidence.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { C, setTheme } from "../../ampModel";

const read = (f) =>
  readFileSync(new URL(`../../${f}`, import.meta.url), "utf8");

const CANVAS = read("RelationshipCanvas.jsx");
const PAGE = read("EdrDeviceTrajectoryPage.jsx");
const MODEL = read("ampModel.js");

describe("A · the full-height yellow IOC column is gone", () => {
  it("draws no rect spanning the graph height for a compromise", () => {
    expect(CANVAS).not.toMatch(/height=\{height\s*-\s*AXIS\}/);
  });

  it("no longer reads the yellow band tokens at all", () => {
    expect(CANVAS).not.toContain("C.iocBand");
    expect(CANVAS).not.toContain("C.iocRow");
  });

  it("does not draw a full-height dashed compromise rule", () => {
    expect(CANVAS).not.toMatch(/y1=\{AXIS\}\s+y2=\{height\}/);
  });
});

describe("B · the compromise is a separate event on its own band", () => {
  it("reserves a dedicated compromise band", () => {
    expect(CANVAS).toContain("const CMP_H");
    expect(CANVAS).toContain("dt2-compromise-band");
    expect(CANVAS).toContain("dt2-section-compromise");
  });

  it("only reserves the band when an authoritative compromise exists", () => {
    expect(CANVAS).toContain("const cmpH = iocs.length ? CMP_H : 0");
    expect(CANVAS).toContain("{cmpH ? (");
  });

  it("pushes System / Files & Network BELOW the compromise band", () => {
    expect(CANVAS).toContain("const sysTop = AXIS + cmpH;");
    expect(CANVAS).toContain("const fnTop = sysTop + SYS_H;");
    expect(CANVAS).toContain("const rowTop = fnTop + FN_H;");
  });

  it("marks the compromise glyph with its own x and y", () => {
    expect(CANVAS).toContain("data-ioc-x=");
    expect(CANVAS).toContain("data-ioc-y=");
  });

  it("keeps the contributor emphasis blue and evidence-gated", () => {
    expect(CANVAS).toContain("isProvenContributor");
    expect(CANVAS).toContain("dt2-contributor-halo-");
    expect(CANVAS).toContain("C.contributor");
  });
});

describe("C · the live Cisco console is dark", () => {
  it("defaults the trajectory palette to dark", () => {
    expect(MODEL).toContain("export const C = { ...DARK };");
  });

  it("the page pins the dark surface", () => {
    expect(PAGE).toContain('setTheme("dark")');
    expect(PAGE).not.toContain('setTheme("light")');
  });

  it("still offers the light palette for the classic AMP console", () => {
    expect(setTheme("light").theme).toBe("light");
    expect(setTheme("dark").theme).toBe("dark");
    expect(C.theme).toBe("dark");
  });
});

describe("D · time focusing moves the viewport, not the evidence", () => {
  it("reads ?from=&to= once, at mount, before the first paint", () => {
    expect(PAGE).toContain("const linkedWindow = useRef(undefined)");
    expect(PAGE).toContain('Date.parse(params.get("from"))');
    expect(PAGE).toContain('Date.parse(params.get("to"))');
    expect(PAGE).toContain("useState(linkedWindow.current)");
  });

  it("seeds the selected day from the linked window", () => {
    expect(PAGE).toContain(
      "linkedWindow.current ? startOfDayUTC(linkedWindow.current.t0) : null");
  });

  it("does not let auto-focus override an explicit linked window", () => {
    expect(PAGE).toMatch(/if \(linkedWindow\.current\) \{[\s\S]*?return;/);
  });

  it("rejects an incomplete or inverted range", () => {
    expect(PAGE).toContain("Number.isFinite(f) && Number.isFinite(t) && t > f");
  });
});
