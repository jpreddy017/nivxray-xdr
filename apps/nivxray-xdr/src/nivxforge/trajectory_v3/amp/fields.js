import { enforcementLabel } from "./labels.js";
// Activity Details artifact sections (AMP-class). Pure: (item, ctx) -> sections. Evidence-only; absent fields carry a reason.
export const R = {
  FHASH: "not collected by sensor (S-3: Sysmon ID11 file events carry no hash)",
  END: "not collected by sensor (S-7: Sysmon config does not emit EventID 5 process end)",
  SIGN: "not collected by sensor (S-8: Sysmon ID1 carries no signer/signature)",
  BYTES: "not collected by sensor (S-9: Sysmon ID3 has no bytes/duration)",
  SIZE: "not collected by sensor (S-10: Sysmon ID11 has no file size)",
  HASHALG: "not collected by sensor (S-11: hash config is SHA-256 only)",
  ENGINE: "not collected by sensor (S-12: no such engine emits on this sensor)",
  SRC: "not provided by source",
  PRJ: "not provided by source (E1 normalizer drops it; derivable from raw)",
  TI: "provider not configured (E1 TI live switch-on pending)",
  WIN: "not provided by source (creating event outside the loaded window)",
};
const base = (p) => (p ? String(p).replace(/\\/g, "/").split("/").pop() : "");
const tld = (h) => (h && /[a-z]/i.test(h) ? `.${String(h).split(".").pop()}` : null);
export const mitreUrl = (t) => `https://attack.mitre.org/techniques/${String(t).trim().toUpperCase().replace(".", "/")}/`;
const TACTICS = { reconnaissance: "TA0043", "resource development": "TA0042", "initial access": "TA0001", execution: "TA0002", persistence: "TA0003",
  "privilege escalation": "TA0004", "defense evasion": "TA0005", "credential access": "TA0006", discovery: "TA0007", "lateral movement": "TA0008",
  collection: "TA0009", "command and control": "TA0011", exfiltration: "TA0010", impact: "TA0040" };
export const tacticUrl = (t) => { const id = /^TA\d{4}$/i.test(t || "") ? t.toUpperCase() : TACTICS[String(t || "").toLowerCase()]; return id ? `https://attack.mitre.org/tactics/${id}/` : null; };
const has = (v) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length);

// IOC empty state. Says ONLY what is true: nothing is recorded against this
// observation. It must not imply the observation is benign or clean, and it
// must not imply a TI lookup ran and came back negative — neither is known
// here. The previous wording named a "synthetic TI fixture", which on real
// production evidence misstated the basis of the display.
export const TI_NO_MATCH = "No threat-intelligence match recorded for this observation.";

function Sec(id, title) {
  const s = { id, title, rows: [], missing: [] };
  s.add = (k, v, o = {}) => { if (has(v)) s.rows.push({ k, v: String(v), ...o }); else if (o.reason) s.missing.push({ k, reason: o.reason }); return s; };
  return s;
}

const raw = (it) => it?.ev?.e3_doc?.raw || {};
const art = (it, k) => (it?.ev?.e3_doc?.artefacts?.[k] || [])[0] || {};
export const imageSha = (it) => raw(it).process_image_hashes?.sha256 || null;

export function procOf(model, iid) {
  return iid ? model.items.find((x) => x.ev.event_type === "process_create" && x.targetIid === iid) || null : null;
}

export function correlatedHost(model, ip) {
  const d = model.items.find((x) => x.kind.glyph === "dns" && (raw(x).dns?.answers || []).includes(ip));
  return d ? (raw(d).dns?.query_name || d.ev.file) : null;
}

export function buildSections(it, ctx) {
  const { model, facts, computer, approvals } = ctx, e = it.ev, d = e.e3_detection, g = it.kind.glyph, out = [];
  const isExec = e.event_type === "process_create";
  const procIid = isExec ? it.targetIid : it.actorIid, procItem = isExec ? it : procOf(model, procIid);
  if (["exec", "create", "modify", "delete", "move"].includes(g)) {
    const f = art(it, "file"), sha = isExec ? imageSha(it) : (f.sha256 || e.file_sha256);
    const s = Sec("file", "File");
    s.add("File name", it.target?.label, { reason: R.SRC, search: true });
    s.add("SHA-256", sha, { reason: isExec ? R.SRC : R.FHASH, hash: true, search: true });
    s.add("SHA-1", f.hashes?.sha1, { reason: R.HASHALG }).add("MD5", f.hashes?.md5, { reason: R.HASHALG });
    s.add("File size", f.size, { reason: R.SIZE });
    s.add("File type", ctx.typeDesc(it.target), {});
    s.add("Full path", it.target?.path, { reason: R.SRC, wrap: true });
    s.add("Signer / publisher", null, { reason: R.SIGN }).add("Signature status", null, { reason: R.SIGN });
    s.add("First seen on this device", facts?.first_seen_on_device, { reason: facts ? R.SRC : undefined });
    s.add("Prevalence", facts && `${facts.prevalence_devices} device(s) in retained evidence`, {});
    const creator = model.items.find((x) => ["create", "modify"].includes(x.kind.glyph) && x.target?.path && x.target.path === it.target?.path);
    s.add("Created / dropped by", creator?.actor ? `${creator.actor.label} · ${String(creator.actorIid || "").slice(-8)}` : null,
      { reason: R.WIN, jump: creator });
    out.push(s);
    const ds = Sec("disposition", "File disposition"), dp = e.e3_disposition;
    ds.add("Disposition", dp ? dp.state : "Unknown", {}).add("Source", dp ? dp.source : R.TI, {}).add("Assessed at", dp?.at, {});
    if (dp) ds.add("Provenance", JSON.stringify(dp.provenance), { wrap: true });
    for (const h of dp?.history || []) ds.add(`Change ${h.at}`, `${h.from || "∅"} → ${h.to} · ${h.source}${h.note ? ` · ${h.note}` : ""}`, { wrap: true });
    out.push(ds);
  }
  const p = Sec("process", "Process"), pr = raw(procItem || it);
  p.add("Process name", isExec ? it.target?.label : it.actor?.label, { reason: R.SRC, search: true });
  p.add("PID", isExec ? e.pid : e.pid, { reason: R.SRC }).add("Process instance", procIid, { reason: R.SRC, copy: true });
  p.add("Start time", procItem ? (raw(procItem).process_start_time || procItem.ev.timestamp) : null, { reason: R.WIN });
  p.add("End time", null, { reason: R.END });
  p.add("User", (procItem || it).ev.user, { reason: R.SRC }).add("Integrity level", pr.integrity_level, { reason: procItem ? R.SRC : R.WIN });
  p.add("Session", null, { reason: R.PRJ }).add("Command line", (procItem || it).ev.command_line, { reason: procItem ? R.SRC : R.WIN, wrap: true });
  p.add("Current directory", pr.current_directory, { reason: procItem ? R.SRC : R.WIN }).add("Image path", isExec ? e.image : it.actorImage, { reason: R.SRC, wrap: true });
  p.add("Image SHA-256", procItem && imageSha(procItem), { reason: procItem ? R.SRC : R.WIN, hash: true, search: true });
  p.add("Image disposition", procItem?.ev.e3_disposition?.state || "Unknown", {});
  out.push(p);
  if (isExec) {
    const par = procOf(model, it.actorIid), pp = Sec("parent", "Parent process");
    pp.add("Name", it.actor?.label, { reason: R.SRC, jump: par }).add("PID", e.ppid, { reason: R.SRC }).add("Instance", it.actorIid, { reason: R.SRC, copy: true });
    pp.add("Image path", raw(it).parent_image_path || e.parent_image, { reason: R.SRC, wrap: true });
    pp.add("SHA-256", par && imageSha(par), { reason: R.WIN, hash: true, search: true }).add("Disposition", par?.ev.e3_disposition?.state || "Unknown", {});
    pp.add("Causal state", it.causal === "PROVEN" ? "Proven" : it.causal === "CORRELATED" ? "Correlated" : "Parent not observed", {});
    out.push(pp);
  }
  if (procIid) {
    const c = Sec("children", "Child processes & activity"), mine = model.items.filter((x) => x.actorIid === procIid);
    const kids = mine.filter((x) => x.ev.event_type === "process_create"), files = mine.filter((x) => x.kind.glyph === "create"), nets = mine.filter((x) => x.kind.glyph === "net");
    c.add("Child processes", String(kids.length), {});
    kids.slice(0, 12).forEach((x) => c.add(`• ${x.target?.label}`, `pid ${x.ev.pid || "?"} · ${x.ev.timestamp?.slice(11, 19)} · ${x.causal}`, { jump: x }));
    c.add("Files created", String(files.length), {});
    files.slice(0, 8).forEach((x) => c.add(`• ${x.target?.label}`, x.ev.timestamp?.slice(11, 19), { jump: x }));
    const dests = [...new Set(nets.map((x) => x.target?.label))];
    c.add("Network destinations", String(dests.length), {});
    dests.slice(0, 8).forEach((h) => { const x = nets.find((n) => n.target?.label === h); c.add(`• ${h}`, `${nets.filter((n) => n.target?.label === h).length} connection(s)`, { jump: x }); });
    out.push(c);
  }
  if (d) {
    const s = Sec("detection", "Detection");
    s.add("Detection name", d.name, { search: true }).add("Detected by", d.engine ? `${d.engine}${d.engine_component ? ` (${d.engine_component})` : ""}` : null, { reason: R.SRC });
    s.add("Rule ID", d.rule_id, { reason: R.SRC }).add("Rule version", d.rule_version, { reason: R.SRC }).add("Confidence", d.confidence, { reason: R.SRC });
    (d.evidence_refs || []).forEach((o) => { const x = model.items.find((y) => y.ev.observation_id === o); s.add("Matched evidence", o, { jump: x, copy: true }); });
    s.add("Behavioral Analytics (edr_ml, TESTING)", null, { reason: "not emitted for this event" });
    ["Exploit Prevention", "System Process Protection", "Malicious Activity Protection"].forEach((k) => s.add(k, null, { reason: R.ENGINE }));
    out.push(s);
  }
  // E1's own attribution (row.mitre / findings.attck), catalogue-decorated server-side as ev.e3_attack. Rendered by MitreBox.
  const m = Sec("mitre", "MITRE ATT&CK"), att = e.e3_attack, tl = (t) => ctx.attack?.tacticLabel?.[t] || t;
  (att?.techniques || []).forEach((a) => m.add(a.tactics.map(tl).join(" · ") || "Technique", `${a.technique} ${a.display}`,
    { link: a.url || mitreUrl(a.technique), klink: tacticUrl(tl(a.tactics[0])), hover: a.description, heat: a.technique }));
  if (att) m.add("Attribution", att.type, {}).add("ATT&CK version", `Enterprise v${att.catalogue_version}`, {});
  else m.add("Technique", null, { reason: "not provided by source (E1 attributed no technique to this observation)" });
  out.push(m);
  const mitre = att?.techniques || [];
  const a = Sec("action", "Action taken / outcome"), en = e.e3_enforcement;
  a.add("Outcome", enforcementLabel(en), {});
  if (en && en.outcome !== "QUARANTINED") a.add("Reason", en.reason, { reason: en.outcome === "QUARANTINE_FAILED" ? "reason not reported by sensor" : "reason not reported" });
  if (en?.detail) a.add("Detail", en.detail, {});
  if (en) a.add("Recorded", `${en.at} · ${en.source}`, {});
  (approvals || []).forEach((r) => a.add("Approval request", `${r.action} · Approval Requested (APPROVAL_REQUESTED, not executed)`, {}));
  out.push(a);
  const ti = Sec("ioc", "IOC / threat intel");
  (e.e3_ti || []).forEach((t) => ti.add(`${t.type} ${t.value}`, `${t.status}${t.verdict ? ` · ${t.verdict}` : ""} · matched ${t.matched_field} · ${t.source} · first ${t.first_seen || "—"} · last ${t.last_seen || "—"}`, { wrap: true }));
  if (!e.e3_ti?.length) ti.add("Indicator match", TI_NO_MATCH, {});
  out.push(ti);
  if (g === "net") {
    const n = Sec("network", "Network"), na = art(it, "network"), ip = na.dst_ip || e.file, host = na.dns || correlatedHost(model, ip);
    n.add("Direction", null, { reason: R.PRJ }).add("Protocol", na.protocol, { reason: R.SRC }).add("Local IP:port", null, { reason: R.PRJ });
    n.add("Remote IP:port", ip && `${ip}${na.dst_port ? `:${na.dst_port}` : ""}`, { reason: R.SRC, search: true });
    n.add("Remote host / domain", host && `${host}${na.dns ? "" : " (correlated DNS)"}`, { reason: R.SRC }).add("TLD", tld(host), { reason: R.SRC });
    n.add("URL", na.url, { reason: R.SRC }).add("Start / end / duration", null, { reason: R.BYTES }).add("Bytes in / out", null, { reason: R.BYTES });
    n.add("Connections from this process to this destination", String(model.items.filter((x) => x.kind.glyph === "net" && x.actorIid === it.actorIid && x.target?.key === it.target?.key).length), {});
    n.add("Reputation", (e.e3_ti || []).find((t) => t.value === ip || t.value === host)?.verdict || "Unknown", {});
    out.push(n);
  }
  if (g === "dns") {
    const s = Sec("dns", "DNS"), dn = raw(it).dns || {};
    s.add("Query name", dn.query_name || e.file, { reason: R.SRC, search: true }).add("Record type", null, { reason: R.SRC });
    s.add("Answers", (dn.answers || []).join(", "), { reason: R.SRC }).add("TLD", tld(dn.query_name || e.file), { reason: R.SRC }).add("Queried by", it.actor?.label, { reason: R.SRC });
    out.push(s);
  }
  if (g === "reg") {
    const s = Sec("registry", "Registry"), rg = art(it, "registry");
    s.add("Key path", rg.key || e.file, { reason: R.SRC, wrap: true }).add("Value name", rg.value, { reason: R.SRC }).add("Operation", "SetValue", {});
    s.add("Data", rg.data, { reason: R.SRC, wrap: true, truncate: 120 });
    out.push(s);
  }
  if (g === "usb") {
    const s = Sec("usb", "Device control / USB");
    s.add("Device class", e.device_class, { reason: R.SRC }).add("Vendor / product", [e.device_vendor, e.device_product].filter(Boolean).join(" / "), { reason: R.SRC });
    s.add("Serial", e.device_serial, { reason: R.SRC }).add("Connect / disconnect", e.event_type === "usb_connect" ? "Connect" : "Disconnect", {});
    s.add("Allowed / blocked", e.e3_enforcement?.outcome || e.device_policy_outcome, { reason: "not provided by source (no enforcement evidence)" });
    out.push(s);
  }
  if (it.kind.system) {
    const s = Sec("system", "System / sensor event");
    s.add("Event", it.kind.label, {}).add("Previous", e.previous_value, { reason: R.SRC }).add("New", e.new_value, { reason: R.SRC });
    s.add("Policy / version", e.policy_name || e.sensor_version, { reason: R.SRC }).add("Status", e.status, { reason: R.SRC }).add("Source", e.provenance?.source, { reason: R.SRC });
    out.push(s);
  }
  const dc = Sec("device", "Device context"), v = (x) => (x && typeof x === "object" ? x.state : x);
  dc.add("Hostname", computer?.hostname, { reason: R.SRC }).add("OS", v(computer?.operating_system), { reason: R.SRC });
  dc.add("Sensor version", v(computer?.connector_version), { reason: R.SRC }).add("Policy / mode", null, { reason: R.SRC }).add("Tenant", computer?.tenant || computer?.tenant_id, { reason: R.SRC });
  out.push(dc);
  const open = new Set(d ? out.map((s) => s.id) : ["file", "disposition", "process", "network", "dns", "registry", "usb", "system"]);
  if (mitre.length) open.add("mitre");
  if (en || approvals?.length) open.add("action");
  out.forEach((s) => { s.open = open.has(s.id); });
  return out;
}

export function networkSummary(model) {
  const nets = model.items.filter((x) => x.kind.glyph === "net"), by = new Map();
  for (const x of nets) {
    const na = art(x, "network"), ip = na.dst_ip || x.ev.file, host = na.dns || correlatedHost(model, ip) || "(no domain)";
    const t = tld(host) || "(no TLD)", k = `${t}|${host}|${ip}`, ms = x.ev.timestamp_instant_ms;
    const r = by.get(k) || { tld: t, host, ip, n: 0, first: ms, last: ms };
    r.n += 1; r.first = Math.min(r.first, ms); r.last = Math.max(r.last, ms); by.set(k, r);
  }
  const rows = [...by.values()].sort((a, b) => a.tld.localeCompare(b.tld) || a.host.localeCompare(b.host) || b.n - a.n);
  return { total: nets.length, unique: rows.length, rows };
}
