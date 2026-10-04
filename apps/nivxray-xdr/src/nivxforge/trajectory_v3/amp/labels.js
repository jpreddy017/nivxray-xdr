// ONE shared, past-tense event label map for DT V3: chips, Activity rows, tooltips, legend, Filters, narrative, actions.
// Pure module (no imports) so node unit tests can lint it. Imperative menu commands ("Quarantine file") are not event labels.
export const EVENT_LABEL = {
  create: "Created", copy: "Copied", move: "Moved", rename: "Renamed", modify: "Modified", delete: "Deleted", open: "Opened",
  execute: "Executed", exec_blocked: "Execution Blocked", network: "Connected (network connection)", dns: "DNS Queried",
  registry: "Registry Modified", scan: "Scanned", scan_det: "Scan Detected", restore: "Restored", quarantined: "Quarantined",
  not_quarantined: "Not Quarantined", quarantine_failed: "Quarantine Failed", detected: "Detected", exploit: "Exploit Prevented",
  usb: "Device Connected / Device Disconnected", usb_connect: "Device Connected", usb_disconnect: "Device Disconnected",
  policy: "Policy Updated", sensor_update: "Sensor Updated", reboot: "Rebooted", uninstall: "Uninstalled",
  isolation: "Isolated / Isolation Released", isolated: "Isolated", isolation_released: "Isolation Released",
  approval: "Approval Requested", match: "Detected (behavioral MATCH)", defs: "Definitions Updated", scan_sched: "Scan Scheduled",
  compromise: "Compromise Detected", snapshot: "Snapshot Taken", hunt: "Threat-Hunting Incident Opened", telemetry: "Sensor Service Status Reported",
};

export const KIND = {
  process_create: { verb: "Executed", glyph: "exec", label: EVENT_LABEL.execute, filter: "execute" },
  process_blocked: { verb: "Blocked from executing", glyph: "exec_blocked", label: EVENT_LABEL.exec_blocked, filter: "exec_blocked" },
  file_create: { verb: "Created", glyph: "create", label: EVENT_LABEL.create, filter: "create" },
  file_write: { verb: "Created", glyph: "create", label: EVENT_LABEL.create, filter: "create" },
  file_modify: { verb: "Modified", glyph: "modify", label: EVENT_LABEL.modify, filter: "modify" },
  file_delete: { verb: "Deleted", glyph: "delete", label: EVENT_LABEL.delete, filter: "delete" },
  file_rename: { verb: "Moved", glyph: "move", label: EVENT_LABEL.move, filter: "move" },
  network_connect: { verb: "Connected", glyph: "net", label: "Connected", filter: "network" },
  dns_query: { verb: "Queried", glyph: "dns", label: EVENT_LABEL.dns, filter: "dns" },
  registry_value_set: { verb: "Set", glyph: "reg", label: EVENT_LABEL.registry, filter: "registry" },
  usb_connect: { verb: "Connected", glyph: "usb", label: EVENT_LABEL.usb_connect, filter: "usb" },
  usb_disconnect: { verb: "Disconnected", glyph: "usb", label: EVENT_LABEL.usb_disconnect, filter: "usb" },
  policy_update: { verb: "Policy updated", glyph: "other", label: EVENT_LABEL.policy, filter: "policy", system: true },
  sensor_update: { verb: "Sensor updated", glyph: "other", label: EVENT_LABEL.sensor_update, filter: "sensor_update", system: true },
  isolation_status: { verb: "Isolation changed", glyph: "other", label: EVENT_LABEL.isolation, filter: "isolation", system: true },
  scan: { verb: "Scanned", glyph: "scan", label: EVENT_LABEL.scan, filter: "scan", system: true },
  reboot: { verb: "Rebooted", glyph: "restore", label: EVENT_LABEL.reboot, filter: "reboot", system: true },
  sensor_service_status: { verb: "Reported service status", glyph: "other", label: EVENT_LABEL.telemetry, filter: "telemetry", system: true },
};

const L = (k, nc) => (nc ? [k, EVENT_LABEL[k], 1] : [k, EVENT_LABEL[k]]);
export const ACTIVITY_FILTERS = [L("create"), L("copy", 1), L("move"), L("execute"), L("exec_blocked", 1), L("open", 1), L("network"),
  L("exploit", 1), L("restore", 1), L("scan_det", 1), L("usb", 1), L("dns"), L("registry"), L("modify"), L("delete"), L("match"), L("approval", 1)];
export const SYSTEM_FILTERS = [L("compromise", 1), L("reboot", 1), L("scan", 1), L("defs", 1), L("policy", 1), L("sensor_update", 1),
  L("scan_sched", 1), L("uninstall", 1), L("isolation", 1), L("snapshot", 1), L("hunt", 1), L("telemetry", 1)];
const NC = " (not collected)";
export const LEGEND = [["create", EVENT_LABEL.create], ["copy", EVENT_LABEL.copy], ["move", EVENT_LABEL.move], ["exec", EVENT_LABEL.execute],
  ["exec_blocked", EVENT_LABEL.exec_blocked + NC], ["open", EVENT_LABEL.open + NC], ["net", EVENT_LABEL.network], ["exploit", EVENT_LABEL.exploit + NC],
  ["restore", EVENT_LABEL.restore + NC], ["scan", EVENT_LABEL.scan_det + NC], ["usb", EVENT_LABEL.usb + NC], ["dns", EVENT_LABEL.dns],
  ["reg", EVENT_LABEL.registry], ["modify", EVENT_LABEL.modify], ["delete", EVENT_LABEL.delete]];

// Enforcement outcome label. The reason comes ONLY from enforcement evidence (`reason`); never invented.
export function enforcementLabel(en) {
  if (!en) return "No enforcement/response evidence recorded.";
  if (en.outcome === "QUARANTINED") return EVENT_LABEL.quarantined;
  if (en.outcome === "QUARANTINE_FAILED") return `${EVENT_LABEL.quarantine_failed} — ${en.reason || "reason not reported by sensor"}`;
  if (en.outcome === "NOT_QUARANTINED") return `${EVENT_LABEL.not_quarantined} — ${en.reason || "reason not reported"}`;
  return String(en.outcome).replace(/_/g, " ").toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
}

// Narrative outcome sentence (AMP pattern), ONLY from enforcement evidence and its reason code.
export function outcomeSentence(en) {
  if (!en) return "No quarantine/response evidence recorded.";
  if (en.outcome === "QUARANTINED") return "The file was quarantined.";
  if (en.outcome === "NOT_QUARANTINED") {
    return en.reason_code === "FILE_NOT_PRESENT" ? "The file was not quarantined. It was moved, deleted or already quarantined."
      : `The file was not quarantined — ${en.reason || "reason not reported"}.`;
  }
  if (en.outcome === "QUARANTINE_FAILED") return `Quarantine failed — ${en.reason || "reason not reported by sensor"}.`;
  return `${enforcementLabel(en)}.`;
}

export const BANNED_PRESENT = ["Execute", "Create", "Move", "Delete", "Scan", "Quarantine", "Copy", "Open", "Restore", "Modify", "Rename",
  "Reboot", "Uninstall", "Isolate", "Connect", "Query"];
// True when a rendered event label uses a present-tense verb as a standalone word ("Execute", "Execute blocked", "File delete").
const ALLOWED = /\b(Quarantine Failed|Scan Detected|Scan Scheduled)\b/g;
export const hasPresentTense = (label) => {
  const s = String(label).replace(ALLOWED, "");
  return BANNED_PRESENT.some((v) => new RegExp(`(^|\\s)${v}(\\s|$)`, "i").test(s));
};
