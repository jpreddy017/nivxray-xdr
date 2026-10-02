// Event-compressed trajectory model over the page's /edr/endpoints/{id}/trajectory rows. Evidence-only.
import { attackText, KILL_CHAIN, tacticsOf } from "./attack";
import { ACTIVITY_FILTERS, KIND, outcomeSentence, SYSTEM_FILTERS } from "./labels";

export { KIND };

const base = (p) => (p ? String(p).replace(/\\/g, "/").split("/").pop() : "");
export const short = (h) => (h && h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h || "");
const EXT = { exe: "PE", dll: "PE", sys: "PE", pyd: "PE", com: "PE", scr: "PE", js: "Script", ps1: "Script", vbs: "Script", py: "Script",
  sh: "Script", bat: "Script", cmd: "Script", msi: "MSI/CAB", cab: "MSI/CAB", zip: "ZIP", gz: "GZ", pdf: "PDF", txt: "TXT", log: "TXT",
  docx: "OOXML", xlsx: "OOXML", pptx: "OOXML", docm: "OOXML", doc: "OLE2", xls: "OLE2", pkg: "Unknown" };
export const TYPE_DESC = { PE: "PE", ELF: "ELF", MachO: "Mach-O", Script: "Script", GZ: "GZ archive", ZIP: "ZIP archive", "MSI/CAB": "MS Cabinet",
  OOXML: "MS Office (OOXML)", OLE2: "MS Office (OLE2)", PDF: "PDF", TXT: "Text (ASCII)", Unknown: "Unknown" };
export function fileType(path, platform) {
  if (!path) return "Unknown";
  const m = /\.([a-z0-9]+)_?$/i.exec(base(path));
  if (m) return EXT[m[1].toLowerCase()] || "Unknown";
  if (String(path).startsWith("/")) return platform === "macos" ? "MachO" : platform === "linux" ? "ELF" : "Unknown";
  return "Unknown";
}
const TYPE_FILTER = { PE: "t_PE", ELF: "t_ELF", MachO: "t_MachO", OOXML: "t_Office", OLE2: "t_Office", PDF: "t_PDF", ZIP: "t_Archive",
  GZ: "t_Archive", "MSI/CAB": "t_MSI", Script: "t_Script" };

export function dispositionShape(ev) {
  const a = ev.e3_assessment;
  if (a?.state === "MALICIOUS" && a.evidence?.length) return "hexagon";
  if (a?.state === "CLEAN" && a.evidence?.length) return "circle";
  return "square";
}
const DISP = { hexagon: "d_malicious", circle: "d_benign", square: "d_unknown" };

const kindOf = (e) => KIND[e.event_type] || { verb: e.event_type, glyph: "other", label: e.event_type, filter: "other" };

function targetOf(e, pf) {
  const t = e.event_type, k = KIND[t]?.glyph;
  const fileRow = (p, sha) => ({ key: `file:${String(p || sha || e.event_iid).toLowerCase()}`, label: p ? base(p) : short(sha), path: p,
    hash: sha, type: fileType(p, pf), section: "Files & Network" });
  if (t === "process_create") return { key: `exe:${String(e.image || e.file_sha256 || e.event_iid).toLowerCase()}`,
    label: e.image ? base(e.image) : short(e.file_sha256), path: e.image, hash: e.file_sha256, type: fileType(e.image, pf), section: "System" };
  if (["create", "modify", "delete", "move"].includes(k)) return fileRow(e.file, e.file_sha256 || e.file_artefacts?.[0]?.sha256);
  if (k === "net") return { key: `net:${e.file || e.network}`, label: e.file || e.network, type: "Network", section: "Files & Network" };
  if (k === "dns") return { key: `dns:${e.entity || e.network || e.file}`, label: e.file || e.lane_label || e.entity || "dns", type: "DNS", section: "Files & Network" };
  if (k === "usb") return { key: `usb:${e.device_serial || e.device_product || e.event_iid}`, label: e.device_product || "External device", type: "USB", section: "Files & Network" };
  if (KIND[t]?.system) return { key: `sys:${t}`, label: KIND[t].label, type: "System", section: "System" };
  if (k === "reg") return { key: `reg:${e.file}`, label: String(e.file || "").split("\\").slice(-2).join("\\"), path: e.file, type: "Registry", section: "Files & Network" };
  return null;
}

const GAP = 3_600_000;
export function buildModel(events, lanes, platform) {
  const laneBy = new Map(lanes.map((l) => [l.lane_index, l]));
  const imageOfIid = new Map(), parentOf = new Map(), children = new Map();
  for (const e of events) {
    if (e.process_iid && e.image) imageOfIid.set(e.process_iid, e.image);
    if (e.event_type === "process_create" && e.process_iid && e.parent_process_iid) {
      parentOf.set(e.process_iid, e.parent_process_iid);
      if (!children.has(e.parent_process_iid)) children.set(e.parent_process_iid, new Set());
      children.get(e.parent_process_iid).add(e.process_iid);
    }
  }
  const seen = new Set();
  const sorted = [...events].filter((e) => !seen.has(e.event_iid) && seen.add(e.event_iid))
    .sort((a, b) => (a.timestamp_instant_ms - b.timestamp_instant_ms) || String(a.event_iid).localeCompare(b.event_iid));
  const rows = new Map();
  const row = (t) => {
    if (!rows.has(t.key)) rows.set(t.key, { ...t, instances: new Map(), count: 0, detection: false });
    return rows.get(t.key);
  };
  const items = [], ticks = [];
  let col = 0, prev = null;
  for (const e of sorted) {
    const ms = e.timestamp_instant_ms;
    if (prev != null && ms - prev >= GAP) { ticks.push({ col, ms: Math.ceil(prev / GAP) * GAP }); col += 1; }
    prev = ms;
    const ev = { ...e, lane_label: e.lane_label || laneBy.get(e.lane_index)?.label };
    const isExec = e.event_type === "process_create";
    const actorIid = isExec ? e.parent_process_iid : e.process_iid;
    const actorImage = isExec ? (imageOfIid.get(e.parent_process_iid) || e.parent_image) : (e.image || imageOfIid.get(e.process_iid));
    const actor = actorImage ? row({ key: `exe:${actorImage.toLowerCase()}`, label: base(actorImage), path: actorImage,
      type: fileType(actorImage, platform), section: "System" }) : null;
    const tgt = targetOf(ev, platform);
    const target = tgt ? row(tgt) : actor;
    if (target) { target.count += 1; target.detection = target.detection || !!e.e3_detection; }
    const targetIid = isExec ? e.process_iid : null;
    const mark = (r, iid) => {
      if (!r || !iid) return;
      const inst = r.instances.get(iid) || { iid, pid: e.pid, from: col, to: col };
      inst.to = col; r.instances.set(iid, inst);
    };
    if (isExec) mark(target, targetIid); else mark(actor, actorIid);
    const causal = !actor ? "UNRESOLVED" : !isExec ? "PROVEN" : (e.parent_process_guid || e.parent_process_iid) ? "PROVEN" : "CORRELATED";
    const ftype = tgt && !["Network", "DNS", "Registry", "USB", "System"].includes(tgt.type) ? tgt.type : null;
    items.push({ col, ev, kind: kindOf(e), actor, target, actorIid, targetIid, causal, shape: dispositionShape(e), actorImage, ftype,
      flags: { warn: !!e.e3_detection, cmd: !!e.command_line, audit: e.audit_only === true } });
    col += 1;
  }
  const order = (s) => [...rows.values()].filter((r) => r.section === s).sort((a, b) => b.count - a.count || String(a.label).localeCompare(b.label));
  return { items, ticks, ncol: col, rows: [...order("System"), ...order("Files & Network")], parentOf, children, total: sorted.length };
}

export function lineage(model, it) {
  const root = it.targetIid || it.actorIid;
  if (!root) return null;
  const set = new Set([root]);
  for (let p = model.parentOf.get(root); p && !set.has(p); p = model.parentOf.get(p)) set.add(p);
  const stack = [root];
  while (stack.length) for (const c of model.children.get(stack.pop()) || []) if (!set.has(c)) { set.add(c); stack.push(c); }
  return set;
}

export function matches(it, q) {
  if (!q) return true;
  const n = q.toLowerCase(), e = it.ev;
  return [e.image, e.file, e.network, e.entity, e.command_line, e.user, e.parent_image, e.file_sha256, e.lane_label,
    e.e3_detection?.name, e.observation_id, e.event_iid, attackText(it)].some((v) => v && String(v).toLowerCase().includes(n));
}

export function passes(it, f) {
  const tac = tacticsOf(it);
  if (tac.length && !tac.some((t) => f.has(`ta_${t}`))) return false;
  if (!f.has(it.kind.filter) && it.kind.filter !== "other") return false;
  if (!f.has(DISP[it.shape])) return false;
  if (it.ftype && !f.has(TYPE_FILTER[it.ftype] || "t_Other")) return false;
  return (it.flags.warn && f.has("f_warning")) || (it.flags.cmd && f.has("f_cmd")) || (!it.flags.warn && !it.flags.cmd && f.has("f_none"));
}

export const fmt = (ms, local) => {
  const d = new Date(ms);
  return local ? d.toLocaleString() : `${d.toISOString().replace("T", " ").slice(0, 19)} UTC`;
};
const cap = (s) => (s ? s[0] + s.slice(1).toLowerCase() : s);
export { cap };

// Narrative tokens: string | {tok, full} | {hash} | {unk} | {det, sev}
export function narrative(it) {
  const e = it.ev, nc = "not collected", t = it.target, d = e.e3_detection;
  const tok = (text, full) => ({ tok: text, full: full || text });
  const who = it.actorImage ? [tok(base(it.actorImage), it.actorImage), ` [${TYPE_DESC[fileType(it.actorImage)] || "Unknown"}]`] : [{ unk: "Unknown" }];
  const hash = (h) => (h ? [" (", { hash: h }, ")"] : [" "]);
  const L = [];
  const user = e.user ? ` executing as ${e.user}` : "";
  if (d) {
    const actorWho = it.actorImage ? [{ name: base(it.actorImage), full: it.actorImage }, ...hash(it.actor?.hash), `[${TYPE_DESC[fileType(it.actorImage)] || "Unknown"}] `] : [{ unk: "Unknown" }, " "];
    L.push(["Detected ", { name: t?.label || nc, full: t?.path }, ...hash(t?.hash), `[${TYPE_DESC[t?.type] || t?.type || "Unknown"}] as `, { det: d.name, sev: d.severity }, "."]);
    L.push([`${it.kind.verb} by `, ...actorWho, e.user ? `executing as ${e.user}.` : "(user not reported)."]);
    L.push([outcomeSentence(e.e3_enforcement)]);
    L.push(["Process disposition ", e.e3_assessment?.state ? cap(e.e3_assessment.state) : { unk: "Unknown" }, "."]);
  } else if (e.event_type === "process_create") {
    L.push([tok(t?.label || nc, e.image), ...hash(e.file_sha256), `[${TYPE_DESC[t?.type] || "Unknown"}] was Executed by `, ...who, "."]);
    L.push([{ unk: "Unknown" }, " disposition."], [{ unk: "Unknown" }, " parent disposition."]);
  } else if (it.kind.glyph === "net") {
    L.push([...who, " connected to ", tok(e.network || nc), `${user}.`]);
  } else if (it.kind.glyph === "dns") {
    L.push([...who, " queried ", tok(t?.label || nc), `${user}.`]);
  } else if (it.kind.glyph === "reg") {
    L.push([...who, " set registry value ", tok(t?.label || nc, e.file), `${user}.`]);
  } else {
    L.push([tok(t?.label || nc, t?.path), ...hash(t?.hash), `[${TYPE_DESC[t?.type] || "Unknown"}] was ${it.kind.verb} by `, ...who, `${user}.`]);
    L.push([{ unk: "Unknown" }, " disposition."]);
  }
  const prod = e.product_name || e.file_product, ver = e.product_version || e.file_version;
  if (t?.hash || t?.path) L.push(["Product: ", prod ? { name: prod, full: prod } : { unk: "not reported by sensor" }, " · Version: ", ver ? { name: ver, full: ver } : { unk: "not reported by sensor" }, "."]);
  if (t?.path) L.push(["File full path: ", tok(t.path)]);
  if (e.command_line) L.push(["Command line: ", tok(e.command_line)]);
  for (const s of e.e3_status_history || []) L.push([`Added later at ${s.recorded_at}: ${s.from} → ${s.to} (${s.provenance?.source}); original observation unchanged.`]);
  return L;
}

export const FILTER_GROUPS = [
  ["All activity", ACTIVITY_FILTERS],
  ["All system", SYSTEM_FILTERS],
  ["All dispositions", [["d_benign", "Benign (circle)"], ["d_malicious", "Malicious (hexagon)"], ["d_unknown", "Unknown (square)"]]],
  ["All flags", [["f_warning", "Warning"], ["f_audit", "Audit only", 1], ["f_cmd", "Command line"], ["f_none", "No flag"]]],
  ["All file types", [["t_PE", "Executable [PE]"], ["t_ELF", "ELF"], ["t_MachO", "Mach-O"], ["t_Office", "MS Office"], ["t_PDF", "PDF"],
    ["t_Archive", "Zip/GZ archive"], ["t_MSI", "MS Cabinet/MSI"], ["t_Script", "Script"], ["t_Other", "Other"]]],
  // Hides only events whose mappings are all in unchecked tactics; unmapped events are never hidden (no mapping ≠ no attack).
  ["All ATT&CK tactics", KILL_CHAIN.map((t) => [`ta_${t.key}`, t.label])],
];
export const DEFAULT_ON = FILTER_GROUPS.flatMap(([, its]) => its.filter((x) => !x[2]).map((x) => x[0]));
export const presentKinds = (items) => new Set(items.map((it) => it.kind.filter));
