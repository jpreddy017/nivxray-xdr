// The IOC section's empty state must not misstate the basis of what is shown.
import { describe, expect, it as test } from "vitest";
import { TI_NO_MATCH, buildSections } from "../fields.js";

const ctx = { model: { items: [] }, facts: null, computer: {}, approvals: [], typeDesc: () => "" };

// glyph "reg" deliberately avoids the file and network branches: this test is
// about the IOC section only.
const item = (e3_ti) => ({
  kind: { glyph: "reg" },
  actorIid: "proc_1",
  targetIid: "proc_1",
  actor: { label: "powershell.exe" },
  target: { label: "HKLM\\Run", path: "HKLM\\Run" },
  ev: { event_type: "registry_set", pid: "1234", timestamp: "2026-09-30T18:17:34Z", e3_doc: {}, ...(e3_ti ? { e3_ti } : {}) },
});

const ioc = (it) => buildSections(it, ctx).find((s) => s.id === "ioc");

describe("IOC / threat intel empty state", () => {
  test("states only that nothing is recorded", () => {
    const rows = ioc(item(null)).rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].k).toBe("Indicator match");
    expect(rows[0].v).toBe(TI_NO_MATCH);
  });

  test("never names a synthetic or fixture source on real evidence", () => {
    expect(ioc(item(null)).rows[0].v).not.toMatch(/synthetic|fixture|mock|sample/i);
  });

  test("does not imply the observation is benign or clean", () => {
    // NB: "no threat" is deliberately not in this pattern — it would match the
    // legitimate phrase "No threat-intelligence match". The risk being guarded
    // is a VERDICT claim, so match verdict words only.
    expect(ioc(item(null)).rows[0].v).not.toMatch(/\b(benign|clean|safe|harmless|not malicious|no risk)\b/i);
  });

  test("does not claim a lookup ran and returned nothing", () => {
    // "no match recorded" is a statement about the record, not about a query
    // this page cannot prove happened.
    expect(ioc(item(null)).rows[0].v).not.toMatch(/looked up|queried|checked|scanned|lookup (?:ran|returned)/i);
  });

  test("a real TI match is still rendered instead of the empty state", () => {
    const rows = ioc(item([{ type: "ip", value: "10.0.0.9", status: "MATCH", verdict: "MALICIOUS",
                             matched_field: "dst_ip", source: "threatfox" }])).rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].k).toBe("ip 10.0.0.9");
    expect(rows[0].v).toContain("MATCH");
    expect(rows[0].v).not.toBe(TI_NO_MATCH);
  });
});
