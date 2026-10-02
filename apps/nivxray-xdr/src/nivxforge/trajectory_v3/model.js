// Event-compressed trajectory model (AMP-parity) over the real page's /edr/endpoints/{id}/trajectory rows.
export const COL_W = 24;
const base = (p) => (p ? String(p).replace(/\\/g, "/").split("/").pop() : "");
export const short = (h) => (h && h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h || "");

const EXT = { exe: "PE", dll: "PE", sys: "PE", pyd: "PE", com: "PE", scr: "PE", js: "Script", ps1: "Script", vbs: "Script",
  py: "Script", sh: "Script", bat: "Script", cmd: "Script", msi: "MSI", cab: "MSI", zip: "Archive", gz: "GZ", "7z": "Archive",
  pdf: "PDF", docm: "Document", docx: "Document", xlsx: "Document", doc: "Document", tmp: "Unknown", pf: "Prefetch", bin: "Unknown" };
export function fileType(path) {
  const m = /\.([a-z0-9]+)_?$/i.exec(base(path));
  if (!m) return "Unknown";
  return EXT[m[1].toLowerCase()] || m[1].toUpperCase();
}

export const DISPOSITION = { BENIGN: "circle", MALICIOUS: "hexagon", UNKNOWN: "square" };
// Shape is disposition: circle only with known-good evidence, hexagon only with evidence-backed MALICIOUS.
export function dispositionShape(ev) {
  const a = ev.e3_assessment;
  if (a?.state === "MALICIOUS" && a.evidence?.length) return "hexagon";
  if (a?.state === "CLEAN" && a.evidence?.length) return "circle";
  return "square";
}

export const KIND = {
  process_create: { verb: "Executed", glyph: "exec", label: "Process executed", filter: "execute" },
  file_create: { verb: "Created", glyph: "create", label: "File created", filter: "create" },
  network_connect: { verb: "Connected", glyph: "net", label: "Network connection", filter: "network" },
  dns_query: { verb: "Queried", glyph: "dns", label: "DNS", filter: "dns" },
  registry_value_set: { verb: "Set", glyph: "reg", label: "Registry", filter: "registry" },
};
const kindOf = (e) => KIND[e.event_type] || { verb: e.event_type, glyph: "other", label: e.event_type, filter: "other" };

function targetOf(e) {
  const t = e.event_type;
  if (t === "process_create") return { key: `exe:${(e.image || "").toLowerCase()}`, label: base(e.image), path: e.image, type: fileType(e.image), section: "System" };
  if (t === "file_create") return { key: `file:${(e.file || "").toLowerCase()}`, label: base(e.file), path: e.file, type: fileType(e.file), section: "Files & Network" };
  if (t === "network_connect") return { key: `net:${e.network}`, label: e.network, type: "Network", section: "Files & Network" };
  if (t === "dns_query") return { key: `dns:${e.entity || e.network || e.file}`, label: e.lane_label || e.entity || "dns", type: "DNS", section: "Files & Network" };
  if (t === "registry_value_set") return { key: `reg:${e.file}`, label: String(e.file || "").split("\\").slice(-2).join("\\"), path: e.file, type: "Registry", section: "Files & Network" };
  return null;
}

export function buildModel(events, lanes) {
  const laneBy = new Map(lanes.map((l) => [l.lane_index, l]));
  const imageOfIid = new Map();
  for (const e of events) if (e.process_iid && e.image) imageOfIid.set(e.process_iid, e.image);
  const sorted = [...events].sort((a, b) => (a.timestamp_instant_ms - b.timestamp_instant_ms) || String(a.event_iid).localeCompare(b.event_iid));
  const rows = new Map();
  const row = (key, label, type, section, path) => {
    if (!rows.has(key)) rows.set(key, { key, label, type, section, path, instances: new Map(), count: 0, detection: false });
    return rows.get(key);
  };
  const items = sorted.map((e, col) => {
    const lane = laneBy.get(e.lane_index) || {};
    const ev = { ...e, lane_label: lane.label };
    const tgt = targetOf(ev);
    const isExec = e.event_type === "process_create";
    const actorImage = isExec ? (e.parent_image || imageOfIid.get(e.parent_process_iid)) : (e.image || imageOfIid.get(e.process_iid));
    const actor = actorImage ? row(`exe:${actorImage.toLowerCase()}`, base(actorImage), fileType(actorImage), "System", actorImage) : null;
    const target = tgt ? row(tgt.key, tgt.label, tgt.type, tgt.section, tgt.path) : actor;
    if (target) { target.count += 1; target.detection = target.detection || !!e.e3_detection; }
    const iid = isExec ? e.process_iid : (e.process_iid || null);
    const procRow = isExec ? target : actor;
    if (procRow && iid) {
      const inst = procRow.instances.get(iid) || { iid, pid: e.pid, from: col, to: col };
      inst.to = col; inst.from = Math.min(inst.from, col);
      procRow.instances.set(iid, inst);
    }
    const causal = !isExec ? "PROVEN" : e.parent_process_guid ? "PROVEN" : actor ? "CORRELATED" : "UNRESOLVED";
    return { col, ev, kind: kindOf(e), actor, target, causal, shape: dispositionShape(e), actorImage };
  });
  const order = (s) => [...rows.values()].filter((r) => r.section === s).sort((a, b) => b.count - a.count || a.label.localeCompare(b.label));
  return { items, rows: [...order("System"), ...order("Files & Network")], total: events.length };
}

export function matches(it, q) {
  if (!q) return true;
  const n = q.toLowerCase();
  const e = it.ev;
  return [e.image, e.file, e.network, e.command_line, e.user, e.parent_image, e.e3_detection?.name, e.observation_id]
    .some((v) => v && String(v).toLowerCase().includes(n));
}

const fmt = (ms, local) => {
  const d = new Date(ms);
  return local ? d.toLocaleString() : `${d.toISOString().replace("T", " ").slice(0, 19)} UTC`;
};
export { fmt };

// Deterministic narrative from evidence fields only; anything absent reads "not collected".
export function narrative(it) {
  const e = it.ev, nc = "not collected";
  const actor = it.actorImage ? base(it.actorImage) : "Unknown";
  const lines = [];
  const tok = (text, full) => ({ tok: text, full: full || text });
  if (e.e3_detection) {
    const d = e.e3_detection;
    lines.push([ "Detected ", tok(it.target?.label || nc, it.target?.path), ` [${it.target?.type || "Unknown"}] as `, { det: d.name, sev: d.severity }, "." ]);
  }
  if (e.event_type === "process_create") {
    lines.push([tok(base(e.image), e.image), ` [${fileType(e.image)}] was Executed by `, actor === "Unknown" ? { unk: "Unknown" } : tok(actor, it.actorImage), ` [${it.actorImage ? fileType(it.actorImage) : "Unknown"}].`]);
    lines.push([`SHA-256: ${e.file_sha256 || nc}.`]);
    lines.push([{ unk: "Unknown" }, " disposition."], [{ unk: "Unknown" }, " parent disposition."]);
    lines.push(["File full path: ", tok(e.image || nc)], ["Command line: ", tok(e.command_line || nc)]);
  } else if (e.event_type === "file_create") {
    lines.push([tok(base(e.file), e.file), ` [${fileType(e.file)}] was Created by `, tok(actor, it.actorImage), ` executing as ${e.user || nc}.`]);
    lines.push([{ unk: "Unknown" }, " disposition."], ["File full path: ", tok(e.file || nc)]);
  } else if (e.event_type === "network_connect") {
    lines.push([tok(actor, it.actorImage), " connected to ", tok(e.network || nc), ` executing as ${e.user || nc}.`]);
  } else if (e.event_type === "dns_query") {
    lines.push([tok(actor, it.actorImage), " queried ", tok(it.target?.label || nc), "."]);
  } else if (e.event_type === "registry_value_set") {
    lines.push([tok(actor, it.actorImage), " set registry value ", tok(e.file || nc), "."]);
  }
  if (e.e3_detection) lines.push([e.e3_detection.response ? `Response evidence: ${e.e3_detection.response}.` : "No quarantine/response evidence recorded."],
    ["Detected is not Malicious: disposition stays Unknown without an evidence-backed assessment."]);
  for (const s of e.e3_status_history || []) lines.push([`Added later at ${s.recorded_at}: disposition ${s.from} → ${s.to} by ${s.provenance?.source}; original observation unchanged.`]);
  return lines;
}

export const FILTER_GROUPS = [
  ["All activity", [["create", "Create"], ["copy", "Copy", 1], ["move", "Move", 1], ["execute", "Execute"], ["exec_blocked", "Execute blocked", 1],
    ["open", "Open", 1], ["network", "Network connection"], ["exploit", "Exploit prevention", 1], ["restore", "Restore", 1],
    ["scan_det", "Scan detection", 1], ["usb", "External devices", 1], ["dns", "DNS"], ["registry", "Registry"], ["modify", "File modify", 1],
    ["delete", "File delete", 1], ["match", "Behavioral detection (MATCH)"], ["approval", "Response request (approval)", 1]]],
  ["All system", [["compromise", "Compromise", 1], ["reboot", "Reboot", 1], ["scan", "Scan", 1], ["defs", "Definitions update", 1],
    ["policy", "Policy update", 1], ["sensor_update", "Sensor update", 1], ["scan_sched", "Scan schedule", 1], ["uninstall", "Uninstall", 1],
    ["isolation", "Isolation status", 1], ["snapshot", "System snapshot", 1], ["hunt", "Threat-hunting incident", 1], ["telemetry", "Behavioral telemetry", 1]]],
  ["All dispositions", [["d_benign", "Benign (circle)"], ["d_malicious", "Malicious (hexagon)"], ["d_unknown", "Unknown (square)"]]],
  ["All flags", [["f_warning", "Warning"], ["f_audit", "Audit only", 1], ["f_cmd", "Command line"], ["f_none", "No flag"]]],
  ["All file types", [["t_PE", "Executable [PE]"], ["t_ELF", "ELF", 1], ["t_MACHO", "Mach-O", 1], ["t_Document", "MS Office"], ["t_PDF", "PDF"],
    ["t_Archive", "Zip/GZ archive"], ["t_MSI", "MS Cabinet/MSI"], ["t_Script", "Script"], ["t_Other", "Other"]]],
];
