// e3.dt.v1 view-models for the AMP-parity Device Trajectory (pure, no React, no network).

export const PAL = {
  bg: "#0A0E13", panel: "#10161E", panelAlt: "#141C26", grid: "#1C2632", gridStrong: "#2A3644",
  text: "#D7DEE7", muted: "#8392A3", faint: "#56657A", accent: "#4CC3D9",
  red: "#E5484D", amber: "#E7A93B", grey: "#8A94A3", neutral: "#C9D3DE", green: "#3DBA7A",
  gap: "#3A2E1A",
};

// Color semantics: red = evidence-backed MALICIOUS only; amber = detection/IOC MATCH; grey = UNKNOWN-like;
// neutral = NO_DETECTION; green = CLEAN with known-good evidence only.
const S = (key, color, label) => ({ key, color, label });
export const SEMANTIC = {
  MALICIOUS: S("MALICIOUS", PAL.red, "Malicious (evidence-backed assessment)"),
  MATCH: S("MATCH", PAL.amber, "Detection / IOC match (not a verdict)"),
  UNKNOWN: S("UNKNOWN", PAL.grey, "Unknown (not clean)"),
  NO_DETECTION: S("NO_DETECTION", PAL.neutral, "No detection (not clean)"),
  CLEAN: S("CLEAN", PAL.green, "Clean (known-good evidence)"),
};
const GREY_STATES = new Set(["UNKNOWN", "NO_HIT", "PROVIDER_ERROR", "RATE_LIMITED", "OUTAGE", "UNASSESSED", "NOT_LOOKED_UP"]);

export function semanticOf(state, evidence = []) {
  const has = Array.isArray(evidence) && evidence.length > 0;
  if (state === "MALICIOUS") return has ? SEMANTIC.MALICIOUS : S("UNKNOWN", PAL.grey, "Malicious claimed without evidence (shown as unknown)");
  if (state === "CLEAN") return has ? SEMANTIC.CLEAN : S("UNKNOWN", PAL.grey, "Clean claimed without known-good evidence (shown as unknown)");
  if (state === "MATCH" || state === "DETECTED") return SEMANTIC.MATCH;
  if (state === "NO_DETECTION") return SEMANTIC.NO_DETECTION;
  if (GREY_STATES.has(state)) return S(state, PAL.grey, `${state.replace(/_/g, " ").toLowerCase()} (not clean)`);
  return SEMANTIC.UNKNOWN;
}

export const markerColor = (m) => (m.detection || m.max_severity === "MATCH" ? PAL.amber : PAL.neutral);

export const CONNECTOR = {
  PROVEN_CAUSAL: { dash: null, mark: null, label: "Proven causal (creation record names the parent instance)" },
  CORRELATED: { dash: "6 4", mark: null, label: "Correlated (pid + time only, not proven)" },
  UNRESOLVED: { dash: "1.5 4", mark: "?", label: "Unresolved (parent not identified)" },
};
export const connectorStyle = (state) => CONNECTOR[state] || CONNECTOR.UNRESOLVED;

export function connectorSource(lane) {
  if (lane.causal_state === "CORRELATED" && lane.candidate_parent) return lane.candidate_parent;
  return lane.parent_lane || null;
}

export const KINDS = {
  PROCESS_START: { label: "Process start", family: "process" },
  PROCESS_END: { label: "Process end", family: "process" },
  FILE_CREATE: { label: "File create", family: "file" },
  FILE_WRITE: { label: "File write / modify", family: "file", gap: "S-2" },
  FILE_MOVE: { label: "File move / rename", family: "file", gap: "S-2" },
  FILE_DELETE: { label: "File delete", family: "file", gap: "S-2" },
  FILE_EXECUTE: { label: "File execute", family: "file", note: "Indirect: shown as the process start of that image" },
  NETWORK_CONNECT: { label: "Network connect", family: "network" },
  DNS_QUERY: { label: "DNS query", family: "network" },
};
export const SENSOR_GAPS = {
  "S-1": "No true-creator field: parent spoofing cannot be verified from Sysmon 1",
  "S-2": "File write/modify, delete and rename are not collected by the current sensor",
  "S-3": "File events carry no hash (Sysmon 11)",
  "S-4": "No boot/session id: PID reuse across reboots relies on start time",
  "S-5": "No image-load / remote-thread / process-access telemetry",
  "S-6": "Security 4688-only process: no GUID and no start time (PID only)",
  "S-7": "Process end is only seen if the sensor config emits it",
};

// Unique-event counts: an event is primary on its process lane (or its file / unattributed lane when it has no
// process); file lanes touched by a process are secondary projections and are not counted twice.
const isPrimary = (lane, meta) => !(meta && meta.lane_type === "FILE" && (meta.touched_by || []).length);

export function filterSummary(vpLanes, laneMeta, kinds) {
  const active = kinds && kinds.size > 0;
  let total = 0, shown = 0;
  for (const l of vpLanes || []) {
    if (!isPrimary(l, laneMeta[l.lane_id])) continue;
    total += l.count;
    if (!active) { shown += l.count; continue; }
    if (l.mode === "BUCKETS") for (const b of l.buckets) for (const [k, n] of Object.entries(b.kinds)) shown += kinds.has(k) ? n : 0;
    else shown += l.markers.filter((m) => kinds.has(m.kind)).length;
  }
  return { active, shown, total, text: active ? `Showing ${shown} of ${total} events` : `${total} events` };
}

export function isolateRows(lanes, laneIds) {
  if (!laneIds) return null;
  const keep = new Set(laneIds);
  for (const l of lanes) if (l.lane_type === "FILE" && (l.touched_by || []).some((k) => keep.has(k))) keep.add(l.lane_id);
  return keep;
}

export const MIN_GROUP_PX = 7;
export const xOf = (t, t0, t1, w) => ((t - t0) / Math.max(1, t1 - t0)) * w;

// Markers closer than MIN_GROUP_PX collapse into one counted group; zooming in spreads them past the threshold.
export function groupMarkers(lane, t0, t1, width, kinds, minPx = MIN_GROUP_PX) {
  const pass = (k) => !kinds || kinds.size === 0 || kinds.has(k);
  if (lane.mode === "BUCKETS") {
    const out = [];
    for (const b of lane.buckets) {
      const count = Object.entries(b.kinds).reduce((s, [k, n]) => s + (pass(k) ? n : 0), 0);
      if (!count) continue;
      const x = xOf((b.from_ms + b.to_ms) / 2, t0, t1, width);
      const last = out[out.length - 1];
      if (last && x - last.x0 < minPx * 4) {
        last.count += count; last.t_end = b.to_ms; last.xl = x; last.x = (last.x0 + x) / 2;
        for (const [k, n] of Object.entries(b.kinds)) last.kinds[k] = (last.kinds[k] || 0) + n;
        continue;
      }
      out.push({ group: true, bucket: true, count, t_ms: b.from_ms, t_end: b.to_ms, x, x0: x, xl: x, kinds: { ...b.kinds }, ids: [] });
    }
    return out;
  }
  const out = [];
  for (const m of lane.markers.filter((x) => pass(x.kind))) {
    const x = xOf(m.t_ms, t0, t1, width);
    const last = out[out.length - 1];
    if (last && x - last.xl < minPx) {
      last.count += 1; last.ids.push(m.event_id); last.t_end = m.t_ms; last.late = last.late || m.late;
      last.kinds[m.kind] = (last.kinds[m.kind] || 0) + 1; last.group = true; last.xl = x; last.x = (last.x0 + x) / 2;
      continue;
    }
    out.push({ group: false, count: 1, x, x0: x, xl: x, t_ms: m.t_ms, t_end: m.t_ms, kind: m.kind, late: m.late, event_id: m.event_id,
               severity: m.severity, ids: [m.event_id], kinds: { [m.kind]: 1 } });
  }
  return out;
}

export function approvalText(req) {
  if (!req) return "";
  if (req.state === "APPROVAL_REQUESTED" && !req.executed) return "Approval requested — not executed. Execution is owned by E1.";
  return `State ${req.state} is owned by E1 and is not displayed as an outcome by E3.`;
}

const pad = (n) => String(n).padStart(2, "0");
export function fmtInstant(raw, mode = "UTC", tz) {
  if (raw == null || !Number.isFinite(raw)) return "—";
  const ms = Math.round(raw);
  const d = new Date(ms);
  const frac = ms % 1000 ? `.${String(ms % 1000).padStart(3, "0")}` : "";
  if (mode === "UTC") {
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}${frac} UTC`;
  }
  const zone = tz || Intl.DateTimeFormat().resolvedOptions().timeZone;
  const p = Object.fromEntries(new Intl.DateTimeFormat("en-US", { timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23", timeZoneName: "short" })
    .formatToParts(d).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}${frac} ${p.timeZoneName}`;
}
export const fmtShort = (ms, mode, tz) => fmtInstant(ms, mode, tz).slice(11, 16);

export function fmtLateness(ms) {
  if (ms == null) return "unknown";
  const s = Math.round(ms / 1000);
  if (s < 120) return `${s}s`;
  if (s < 7200) return `${Math.round(s / 60)}m`;
  return `${(s / 3600).toFixed(1)}h`;
}

const TICKS = [1e3, 5e3, 15e3, 6e4, 3e5, 9e5, 36e5, 108e5, 216e5, 432e5, 864e5];
export function ticks(t0, t1, target = 8) {
  const step = TICKS.find((s) => (t1 - t0) / s <= target) || TICKS[TICKS.length - 1];
  const out = [];
  for (let t = Math.ceil(t0 / step) * step; t <= t1; t += step) out.push(t);
  return { step, ticks: out };
}

// Negative explainability: what the evidence cannot tell the analyst about this event/row.
export function cannotTell({ event, lane, fileStatus }) {
  const out = [];
  const add = (id, text) => out.push({ id, text });
  const kind = event?.kind || "";
  const isProc = lane && (lane.lane_type === "PROCESS" || lane.lane_type === "UNRESOLVED_PARENT");
  if (lane?.lane_type === "UNRESOLVED_PARENT") add("parent-not-observed", "The parent process was never observed; it is a placeholder, not evidence.");
  if (isProc && lane.causal_state === "UNRESOLVED") add("parent-unresolved", "The parent of this process is unresolved: no parent identifier in the creation record.");
  if (isProc && lane.causal_state === "CORRELATED") add("parent-correlated", "The parent link is CORRELATED by pid and time only; it is not proven.");
  if (isProc && lane.parent_spoof?.suspected) add("spoof-unverified", "Parent-spoof flag is raised from a creator field but is UNVERIFIED (S-1).");
  else if (isProc) add("S-1", SENSOR_GAPS["S-1"]);
  if (lane?.identity_state === "PID_ONLY_NOT_AUTHORITATIVE" || event?.process_identity === "PID_ONLY_NOT_AUTHORITATIVE") add("S-6", SENSOR_GAPS["S-6"]);
  if (event && event.boot_id == null && isProc) add("S-4", SENSOR_GAPS["S-4"]);
  if (isProc && lane.continues_after && lane.span?.to_ms == null) add("S-7", SENSOR_GAPS["S-7"]);
  if (isProc) add("S-5", SENSOR_GAPS["S-5"]);
  if (kind.startsWith("FILE_") || lane?.lane_type === "FILE") {
    if (!event?.file?.sha256 && !lane?.sha256) add("S-3", SENSOR_GAPS["S-3"]);
    add("S-2", SENSOR_GAPS["S-2"]);
  }
  if (lane?.lane_type === "UNATTRIBUTED_NETWORK" || (kind.startsWith("NETWORK") && !event?.process_key)) add("no-attribution", "No process is attributed to this network activity.");
  for (const r of fileStatus?.reputation || []) if (r.state !== "CLEAN") add(`rep-${r.provider}`, `Reputation ${r.state} from ${r.provider}: ${r.detail || "not clean"}.`);
  return out;
}

// Retrospective status entries placed on rows whose evidence carries the subject hash (process image or file row).
export function retroMarkers(statusEvents, lanes) {
  const out = [];
  for (const s of statusEvents || []) {
    const t = Date.parse(s.recorded_at);
    for (const l of lanes) if (l.sha256 && l.sha256 === s.subject) out.push({ lane_id: l.lane_id, t_ms: t, status: s });
  }
  return out;
}

export function approvalMarkers(approvals, lanes, t0) {
  const ids = new Set(lanes.map((l) => l.lane_id));
  return (approvals || []).filter((a) => ids.has(a.target?.lane_id))
    .map((a) => ({ lane_id: a.target.lane_id, t_ms: a.target.t_ms ?? t0, request: a }));
}

export function basename(p) {
  return p ? String(p).replace(/\\/g, "/").split("/").pop() : "";
}
