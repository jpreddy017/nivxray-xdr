import test from "node:test";
import assert from "node:assert/strict";
import { buildSections, networkSummary, R } from "../../apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/fields.js";

const row = (k, v = {}) => ({ key: k, label: k, path: v.path, type: v.type || "PE", section: "System" });
const mk = (col, ev, extra = {}) => ({ col, ev: { timestamp: "2026-10-02T06:00:00Z", timestamp_instant_ms: 1e12 + col, ...ev },
  kind: extra.kind || { glyph: "exec", label: "Execute", verb: "Executed" }, flags: {}, causal: "PROVEN", ...extra });
const ctx = (items) => ({ model: { items }, facts: null, computer: { hostname: "H" }, approvals: [], typeDesc: (t) => t?.type });
const missing = (secs, id) => secs.find((s) => s.id === id)?.missing || [];
const value = (secs, id, k) => secs.find((s) => s.id === id)?.rows.find((r) => r.k === k)?.v;

test("execution without hashes lists SHA-1/MD5 as S-6 and signer as S-1, never blank", () => {
  const it = mk(1, { event_type: "process_create", image: "C:\\a.exe" }, { target: row("exe:a", { path: "C:\\a.exe" }), targetIid: "p1" });
  const s = buildSections(it, ctx([it]));
  assert.deepEqual(missing(s, "file").find((m) => m.k === "SHA-1").reason, R.HASHALG);
  assert.equal(missing(s, "file").find((m) => m.k === "Signer / publisher").reason, R.SIGN);
  assert.equal(missing(s, "process").find((m) => m.k === "End time").reason, R.END);
  assert.ok(s.every((x) => x.rows.every((r) => r.v !== "")));
});

test("disposition without TI evidence is Unknown with provider-not-configured source, never Clean", () => {
  const it = mk(1, { event_type: "file_create", file: "C:\\x.txt" }, { kind: { glyph: "create", label: "Create", verb: "Created" }, target: row("f", { path: "C:\\x.txt", type: "TXT" }) });
  const s = buildSections(it, ctx([it]));
  assert.equal(value(s, "disposition", "Disposition"), "Unknown");
  assert.equal(value(s, "disposition", "Source"), R.TI);
  assert.ok(!JSON.stringify(s).includes("Clean"));
});

test("action taken appears only with enforcement evidence", () => {
  const base = { event_type: "file_create", file: "C:\\e.com", e3_detection: { name: "X", severity: "MEDIUM", mitre: [] } };
  const k = { kind: { glyph: "create", label: "Create", verb: "Created" }, target: row("f", { path: "C:\\e.com" }) };
  const none = buildSections(mk(1, base, k), ctx([]));
  assert.equal(value(none, "action", "Outcome"), "No enforcement/response evidence recorded.");
  const q = buildSections(mk(1, { ...base, e3_enforcement: { outcome: "QUARANTINED", detail: "moved", at: "t", source: "fx" } }, k), ctx([]));
  assert.match(value(q, "action", "Outcome"), /^quarantined/);
});

test("MITRE links to attack.mitre.org with sub-technique path; absence carries a reason", () => {
  const it = mk(1, { event_type: "process_create", e3_detection: { name: "D", mitre: [{ tactic: "Execution", technique: "T1059.001", name: "PowerShell" }], mitre_source: "rule metadata" } },
    { target: row("exe:p"), targetIid: "p" });
  const m = buildSections(it, ctx([it])).find((s) => s.id === "mitre");
  assert.equal(m.rows[0].link, "https://attack.mitre.org/techniques/T1059/001/");
  const n = buildSections(mk(2, { event_type: "process_create", mitre_basis: "NOT_ATTRIBUTED" }, { target: row("exe:q"), targetIid: "q" }), ctx([])).find((s) => s.id === "mitre");
  assert.match(n.missing[0].reason, /no rule mapped/);
});

test("network: bytes/duration are S-3, direction/local endpoint are derivable-from-raw, host correlated from DNS", () => {
  const dns = mk(1, { event_type: "dns_query", file: "a.example", e3_doc: { raw: { dns: { query_name: "a.example", answers: ["1.2.3.4"] } } } }, { kind: { glyph: "dns" } });
  const net = mk(2, { event_type: "network_connect", file: "1.2.3.4", e3_doc: { artefacts: { network: [{ dst_ip: "1.2.3.4", dst_port: 443, protocol: "tcp" }] } } },
    { kind: { glyph: "net", label: "Network connection", verb: "Connected" }, target: row("net:1.2.3.4", { type: "Network" }), actorIid: "p" });
  const s = buildSections(net, ctx([dns, net]));
  assert.equal(missing(s, "network").find((m) => m.k === "Bytes in / out").reason, R.BYTES);
  assert.equal(missing(s, "network").find((m) => m.k === "Direction").reason, R.PRJ);
  assert.equal(value(s, "network", "Remote host / domain"), "a.example (correlated DNS)");
  assert.equal(value(s, "network", "TLD"), ".example");
  const sum = networkSummary({ items: [dns, net] });
  assert.equal(sum.total, 1); assert.equal(sum.rows[0].tld, ".example");
});

test("USB and system sections render only when such an event exists, absent values carry reasons", () => {
  const usb = mk(1, { event_type: "usb_connect", device_class: "Mass storage", device_vendor: "Acme", device_product: "Stick", device_serial: "S1" },
    { kind: { glyph: "usb", label: "External device", verb: "Connected" }, target: row("usb:S1", { type: "USB" }) });
  const s = buildSections(usb, ctx([usb]));
  assert.equal(value(s, "usb", "Serial"), "S1");
  assert.match(missing(s, "usb").find((m) => m.k === "Allowed / blocked").reason, /no enforcement evidence/);
  const sys = mk(2, { event_type: "policy_update", previous_value: "v1", new_value: "v2" }, { kind: { glyph: "other", label: "Policy update", system: true }, target: row("sys:p", { type: "System" }) });
  assert.equal(value(buildSections(sys, ctx([])), "system", "New"), "v2");
  const exe = mk(3, { event_type: "process_create" }, { target: row("exe:z"), targetIid: "z" });
  assert.ok(!buildSections(exe, ctx([])).some((x) => x.id === "usb" || x.id === "system"));
});
