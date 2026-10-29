// P0 · Device Trajectory authentication rendering.
//
// The G4-A2 Windows VM reported 345 `logon_success` observations in a 24h
// window. They rendered as unlabelled squares because `KIND` carried no
// authentication kind, so `kindOf()` fell back to glyph "other" and
// `targetOf()` produced no row of its own.
//
// Fixtures below are copied from the live G4 contract
// (`GET /api/edr/endpoints/ep_024ce6515803f7165a11/trajectory`), including the
// fields that are genuinely absent on that sensor: `ppid`, `parent_process`
// and `command_line` are null and MUST stay null.
import { describe, expect, it as test } from "vitest";

import { buildSections } from "../fields.js";
import { ACTIVITY_FILTERS, EVENT_LABEL, KIND, LEGEND } from "../labels.js";
import { accountOf, buildModel, DEFAULT_ON, passes, presentKinds } from "../model.js";

//: Exactly the set the backend canonicalises as authentication
//: (`_AUTH_KINDS`, backend/edr_plane/trajectory_window.py:72).
const BACKEND_AUTH_KINDS = ["logon_success", "logon_failure", "logon", "logoff",
                            "credential_validation"];

const logon = (account, ms, over = {}) => ({
  event_iid: `obs_${account}_${ms}#a`,
  observation_id: `obs_${account}_${ms}`,
  timestamp: new Date(ms).toISOString(),
  timestamp_instant_ms: ms,
  event_type: "logon_success",
  lane_group: "AUTHENTICATION",
  lane_id: `auth::${account}`,
  lane_index: 29,
  process: "winlogon.exe",
  image: "C:\\Windows\\System32\\winlogon.exe",
  pid: "0x354",
  user: account,
  entity: "winlogon.exe",
  display_label: "winlogon.exe · logon success",
  disposition: "UNKNOWN_NOT_ASSESSED",
  //: genuinely not reported by sensor 0.3.0-windows
  ppid: null, parent_process: "", parent_process_iid: null, command_line: null,
  ...over,
});

const exec = (name, ms) => ({
  event_iid: `obs_${name}#x`, observation_id: `obs_${name}`,
  timestamp: new Date(ms).toISOString(), timestamp_instant_ms: ms,
  event_type: "process_create", lane_group: "PROCESS", lane_id: `proc::${name}`,
  process: name, image: `C:\\Windows\\System32\\${name}`, pid: "0x220",
  process_iid: `proc_${name}`, parent_process_iid: null, ppid: null, command_line: null,
});

const fileWrite = (path, ms) => ({
  event_iid: `obs_f${ms}#f`, observation_id: `obs_f${ms}`,
  timestamp: new Date(ms).toISOString(), timestamp_instant_ms: ms,
  event_type: "file_create", lane_group: "FILE", file: path,
  process_iid: "proc_smss.exe", image: "C:\\Windows\\System32\\smss.exe",
});

const T0 = Date.parse("2026-10-28T08:28:50.321Z");
const build = (events) => buildModel(events, [], "windows");
const authItems = (m) => m.items.filter((it) => it.kind.glyph.startsWith("auth"));

describe("authentication kinds are mapped", () => {
  test("every backend authentication kind has a label map entry", () => {
    for (const k of BACKEND_AUTH_KINDS) expect(KIND[k], k).toBeTruthy();
  });

  test("no authentication kind falls back to the generic glyph or raw name", () => {
    for (const k of BACKEND_AUTH_KINDS) {
      expect(KIND[k].glyph, k).not.toBe("other");
      expect(KIND[k].label, k).not.toBe(k);
      expect(KIND[k].label, k).toMatch(/^[A-Z]/);
      expect(KIND[k].filter, k).not.toBe("other");
    }
  });

  test("labels are past tense, like every other event label", () => {
    expect(KIND.logon_success.label).toBe(EVENT_LABEL.logon);
    expect(KIND.logon_failure.label).toBe(EVENT_LABEL.logon_failed);
    expect(KIND.logoff.label).toBe(EVENT_LABEL.logoff);
    expect([KIND.logon_success.label, KIND.logon_failure.label, KIND.logoff.label])
      .toEqual(["Signed In", "Sign-In Failed", "Signed Out"]);
  });

  test("success, failure and logoff are visually distinct", () => {
    const glyphs = [KIND.logon_success.glyph, KIND.logon_failure.glyph, KIND.logoff.glyph];
    expect(new Set(glyphs).size).toBe(3);
  });

  test("the legend explains the new glyphs", () => {
    const keys = LEGEND.map(([g]) => g);
    expect(keys).toEqual(expect.arrayContaining(["auth", "auth_failed", "auth_off"]));
  });

  test("authentication is NOT marked system, so rows cannot collapse", () => {
    for (const k of BACKEND_AUTH_KINDS) expect(KIND[k].system, k).toBeFalsy();
  });
});

describe("rows are evidence-backed and per account", () => {
  test("each reported account gets its own readable row", () => {
    const m = build([logon("UMFD-1", T0), logon("UMFD-0", T0 + 1000), logon("DWM-1", T0 + 2000)]);
    const rows = m.rows.filter((r) => r.key.startsWith("auth:"));
    expect(rows.map((r) => r.label).sort()).toEqual(["DWM-1", "UMFD-0", "UMFD-1"]);
    expect(new Set(rows.map((r) => r.key)).size).toBe(3);
  });

  test("unrelated users are never merged into one indistinguishable row", () => {
    const m = build([logon("alice", T0), logon("bob", T0 + 1000)]);
    const keys = m.rows.filter((r) => r.key.startsWith("auth:")).map((r) => r.key);
    expect(keys).toHaveLength(2);
    expect(keys[0]).not.toBe(keys[1]);
  });

  test("repeated logons for one account collapse onto that account's row", () => {
    const m = build([logon("UMFD-1", T0), logon("UMFD-1", T0 + 1000), logon("UMFD-1", T0 + 2000)]);
    const rows = m.rows.filter((r) => r.key.startsWith("auth:"));
    expect(rows).toHaveLength(1);
    expect(rows[0].count).toBe(3);
  });

  test("the lane identity is used when the sensor reports no user", () => {
    const m = build([logon("UMFD-1", T0, { user: "-" })]);
    expect(m.rows.find((r) => r.key.startsWith("auth:")).label).toBe("UMFD-1");
  });

  test("an unreported account says so rather than inventing one", () => {
    const m = build([logon("x", T0, { user: null, lane_id: null, lane_label: null })]);
    const row = m.rows.find((r) => r.key.startsWith("auth:"));
    expect(row.label).toBe("account not reported by sensor");
  });

  test("accountOf reads only reported fields", () => {
    expect(accountOf({ user: "alice" })).toBe("alice");
    expect(accountOf({ user: "-", lane_id: "auth::bob" })).toBe("bob");
    expect(accountOf({})).toBe(null);
  });

  test("the 345-observation scale stays selectable, not one blob", () => {
    const accounts = ["SYSTEM", "UMFD-0", "UMFD-1", "DWM-1", "NIVX-G4-WIN11$"];
    const events = Array.from({ length: 345 }, (_, i) =>
      logon(accounts[i % accounts.length], T0 + i * 1000));
    const m = build(events);
    expect(authItems(m)).toHaveLength(345);
    expect(m.rows.filter((r) => r.key.startsWith("auth:"))).toHaveLength(5);
    for (const it of authItems(m)) expect(it.target).toBeTruthy();
  });
});

describe("filters", () => {
  test("authentication filters exist and are on by default", () => {
    const keys = ACTIVITY_FILTERS.map(([k]) => k);
    expect(keys).toEqual(expect.arrayContaining(["logon", "logon_failed", "logoff"]));
    for (const k of ["logon", "logon_failed", "logoff"]) expect(DEFAULT_ON).toContain(k);
  });

  test("default filters show authentication events", () => {
    const m = build([logon("UMFD-1", T0)]);
    expect(passes(authItems(m)[0], new Set(DEFAULT_ON))).toBe(true);
  });

  test("unchecking the logon filter hides them — previously impossible", () => {
    const m = build([logon("UMFD-1", T0)]);
    const off = new Set(DEFAULT_ON.filter((k) => k !== "logon"));
    expect(passes(authItems(m)[0], off)).toBe(false);
  });

  test("hiding logons leaves process events visible", () => {
    const m = build([logon("UMFD-1", T0), exec("smss.exe", T0 + 1000)]);
    const off = new Set(DEFAULT_ON.filter((k) => k !== "logon"));
    const proc = m.items.find((it) => it.kind.glyph === "exec");
    expect(passes(proc, off)).toBe(true);
  });

  test("presentKinds reports authentication so the panel can enable it", () => {
    expect(presentKinds(build([logon("UMFD-1", T0)]).items).has("logon")).toBe(true);
  });

  test("file-type filters never hide an identity row", () => {
    const m = build([logon("UMFD-1", T0)]);
    expect(authItems(m)[0].ftype).toBe(null);
  });
});

describe("Activity Details shows the real event", () => {
  const ctx = { model: { items: [] }, facts: null, computer: {}, approvals: [], typeDesc: () => "" };
  const sectionsFor = (ev) => {
    const m = build([ev]);
    const it = authItems(m)[0];
    return buildSections(it, { ...ctx, model: m });
  };
  const auth = (ev) => sectionsFor(ev).find((s) => s.id === "auth");
  const val = (s, k) => s.rows.find((r) => r.k === k)?.v;

  test("an Authentication section is produced", () => {
    expect(auth(logon("UMFD-1", T0))).toBeTruthy();
  });

  test("it carries the reported account, outcome, process and time", () => {
    const s = auth(logon("UMFD-1", T0));
    expect(val(s, "Account")).toBe("UMFD-1");
    expect(val(s, "Outcome")).toBe("Signed In");
    expect(val(s, "Logon process")).toBe("winlogon.exe");
    expect(val(s, "Process image")).toBe("C:\\Windows\\System32\\winlogon.exe");
    expect(val(s, "PID")).toBe("0x354");
    expect(val(s, "Event time (UTC)")).toBe(new Date(T0).toISOString());
    expect(val(s, "Observation")).toBe(`obs_UMFD-1_${T0}`);
    expect(val(s, "Identity lane")).toBe("auth::UMFD-1");
  });

  test("a failed sign-in reads as failed", () => {
    const s = auth(logon("alice", T0, { event_type: "logon_failure" }));
    expect(val(s, "Outcome")).toBe("Sign-In Failed");
  });

  test("absent logon type and source address carry a reason, not a value", () => {
    const s = auth(logon("UMFD-1", T0));
    expect(val(s, "Logon type")).toBeUndefined();
    expect(s.missing.map((r) => r.k)).toEqual(expect.arrayContaining(["Logon type", "Source host / address"]));
    for (const r of s.missing) expect(r.reason).toBeTruthy();
  });

  test("reported logon type and source address are shown", () => {
    const s = auth(logon("alice", T0, { e3_doc: { raw: { winlog: { logon_type: 3, source_address: "10.0.0.9" } } } }));
    expect(val(s, "Logon type")).toBe("3");
    expect(val(s, "Source host / address")).toBe("10.0.0.9");
  });

  test("no process lineage, PID/PPID or command line is invented", () => {
    const secs = sectionsFor(logon("UMFD-1", T0));
    expect(secs.find((s) => s.id === "parent")).toBeUndefined();
    const proc = secs.find((s) => s.id === "process");
    expect(val(proc, "Command line")).toBeUndefined();
    const flat = JSON.stringify(secs);
    expect(flat).not.toMatch(/ppid/i);
    expect(flat).not.toMatch(/0x220/);
  });
});

describe("previously supported events are unchanged", () => {
  test("process_create keeps its row key, glyph, label and filter", () => {
    const m = build([exec("smss.exe", T0)]);
    const it = m.items[0];
    expect(it.kind.glyph).toBe("exec");
    expect(it.kind.label).toBe("Executed");
    expect(it.kind.filter).toBe("execute");
    expect(it.target.key).toBe("exe:c:\\windows\\system32\\smss.exe");
    expect(it.target.label).toBe("smss.exe");
    expect(it.target.type).toBe("PE");
  });

  test("file events keep their row key, glyph and section", () => {
    const m = build([fileWrite("C:\\Users\\a\\Desktop\\note.txt", T0)]);
    const it = m.items[0];
    expect(it.kind.glyph).toBe("create");
    expect(it.target.key).toBe("file:c:\\users\\a\\desktop\\note.txt");
    expect(it.target.section).toBe("Files & Network");
    expect(it.target.type).toBe("TXT");
  });

  test("a mixed window keeps every kind on its own row", () => {
    const m = build([exec("smss.exe", T0), logon("UMFD-1", T0 + 1000),
                     fileWrite("C:\\tmp\\x.txt", T0 + 2000)]);
    const keys = m.rows.map((r) => r.key);
    expect(keys).toEqual(expect.arrayContaining([
      "exe:c:\\windows\\system32\\smss.exe", "auth:umfd-1", "file:c:\\tmp\\x.txt"]));
    expect(m.items.map((it) => it.kind.glyph)).toEqual(["exec", "auth", "create"]);
  });

  test("an unmapped kind still degrades safely to the generic marker", () => {
    const m = build([{ ...exec("x.exe", T0), event_type: "something_new" }]);
    expect(m.items[0].kind.glyph).toBe("other");
  });
});
