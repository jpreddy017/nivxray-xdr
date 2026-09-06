/**
 * Device Trajectory · shared model for the Cisco Secure Endpoint
 * (AMP) observable clone.
 *
 * Everything here is presentation of PERSISTED evidence. Nothing
 * invents a disposition, a lifeline or a relationship the projection
 * did not report.
 *
 * Reproduced from the Cisco reference screens: computer card and
 * Navigator side by side above a full-width trajectory; vertical axis
 * of processes then files & network; horizontal axis of time with
 * rotated tick labels; green lifelines with grey lineage connectors;
 * outline activity icons; red compromise markers with an amber time
 * band; right-hand Events panel that expands into the event's details
 * including Detected By.
 *
 * DIFFERENCES (declared, never hidden):
 *  · icon artwork is original — Cisco's glyph assets are proprietary;
 *  · exact pixel metrics, zoom step ratios and colour hex values are
 *    not published, so functional equivalents are used;
 *  · file-type tags ([PE], [OLE2] …) come from Cisco's file
 *    identification, which NivXForge does not collect; the tag is
 *    derived from the observed path extension or the row's group;
 *  · wheel-zoom is deliberately NOT bound: the Cisco reference
 *    establishes navigation via the Navigator bands and the trajectory
 *    itself, so the wheel scrolls the activity axis.
 */

export const ROW_H = 15;
export const GUTTER = 280;
export const AXIS_H = 32;

export const MS = { s: 1000, m: 60000, h: 3600000, d: 86400000 };
export const DAY_MS = MS.d;
export const DAY_BINS = 240;

/** Cisco's console is a light surface; the NivXForge chrome around it
 *  stays dark. */
export const C = {
  // Cisco AMP classic light console tokens (design_guidelines.json)
  shell: "#0F172A",
  paper: "#FFFFFF",
  paperAlt: "#F8FAFC",
  chrome: "#F8FAFC",
  gutterBg: "#F1F5F9",
  grid: "#E2E8F0",
  gridStrong: "#CBD5E1",
  ink: "#0F172A",
  inkDim: "#475569",
  inkFaint: "#64748B",
  lifeline: "#16A34A",
  lifelineDim: "#22C55E",
  connector: "#94A3B8",
  glyph: "#475569",
  malicious: "#DC2626",
  maliciousHalo: "#FEF2F2",
  suspicious: "#D97706",
  detection: "#DC2626",
  band: "rgba(251, 191, 36, 0.18)",
  telemetry: "#2563EB",
  spark: "#2563EB",
  sparkFill: "rgba(59, 130, 246, 0.15)",
  selection: "#3B82F6",
  selectionRow: "#EFF6FF",
  selectionStrong: "#2563EB",
  handle: "#1D4ED8",
  navWindow: "rgba(37, 99, 235, 0.12)",
  file: "#475569",
  network: "#475569",
  link: "#2563EB",
};

export const DISPOSITION = {
  MALICIOUS: { label: "Malicious", color: C.malicious },
  SUSPICIOUS: { label: "Suspicious", color: C.suspicious },
  UNKNOWN_NOT_ASSESSED: { label: "Unknown · not assessed",
                          color: C.inkFaint },
};

export const GROUP_COLOR = {
  PROCESS: C.glyph, FILE: C.file, NETWORK: C.network, OTHER: C.inkFaint,
};

/** Cisco groups the vertical axis: system processes first, then files
 *  and network artefacts. */
export const GROUP_SECTION = {
  PROCESS: "System", FILE: "Files & Network", NETWORK: "Files & Network",
  OTHER: "Unattributed",
};

export const dispositionOf = (e) =>
  DISPOSITION[e?.disposition] || DISPOSITION.UNKNOWN_NOT_ASSESSED;

/** Red treatment is reserved for evidence that earns it. */
export const isRed = (e) =>
  e?.disposition === "MALICIOUS" || e?.is_detection === true;

export const eventColor = (e) => {
  if (isRed(e)) return C.malicious;
  if (e?.disposition === "SUSPICIOUS" || e?.attributed) return C.suspicious;
  return C.glyph;
};

export const iso = (ms) => new Date(ms).toISOString();
export const dayKeyOf = (ms) => new Date(ms).toISOString().slice(0, 10);
export const startOfDayUTC = (ms) => {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
};

export const fmtSpan = (ms) => {
  if (ms < 1000) return `${Math.max(1, Math.round(ms))} ms`;
  if (ms < 90 * MS.s) return `${(ms / MS.s).toFixed(1)} s`;
  if (ms < 90 * MS.m) return `${(ms / MS.m).toFixed(1)} min`;
  if (ms < 48 * MS.h) return `${(ms / MS.h).toFixed(1)} h`;
  return `${(ms / MS.d).toFixed(1)} d`;
};

const p2 = (n) => String(n).padStart(2, "0");

export const fmtHM = (ms) => {
  const d = new Date(ms);
  return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
};

export const fmtHMS = (ms) => {
  const d = new Date(ms);
  return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}:${p2(d.getUTCSeconds())}`;
};

export const MONTHS = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN",
                       "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];

export const fmtDate = (ms) => {
  const d = new Date(ms);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
};

const STEPS = [
  MS.s, 5 * MS.s, 15 * MS.s, 30 * MS.s,
  MS.m, 2 * MS.m, 5 * MS.m, 15 * MS.m, 30 * MS.m,
  MS.h, 3 * MS.h, 6 * MS.h, 12 * MS.h,
  MS.d, 2 * MS.d, 7 * MS.d, 14 * MS.d, 30 * MS.d,
];

export function ticksFor(t0, t1, width, target = 12) {
  const span = Math.max(1, t1 - t0);
  const want = span / Math.max(2, target);
  const step = STEPS.find((s) => s >= want) || STEPS[STEPS.length - 1];
  const first = Math.ceil(t0 / step) * step;
  const out = [];
  for (let t = first; t <= t1 && out.length < 80; t += step) {
    const d = new Date(t);
    const dayBreak = step < MS.d && d.getUTCHours() === 0
      && d.getUTCMinutes() === 0;
    out.push({ t, x: ((t - t0) / span) * width,
               label: step >= MS.d ? fmtDate(t)
                 : step >= MS.m ? fmtHM(t) : fmtHMS(t),
               major: step >= MS.d || dayBreak });
  }
  return { ticks: out, step };
}

export const TYPE_LABEL = {
  process_create: "Process created",
  process_exit: "Process exited",
  file_create: "File created",
  file_write: "File written",
  file_delete: "File deleted",
  file_modify: "File modified",
  image_load: "Image loaded",
  network_connect: "Network connection",
  network_listen: "Network listen",
  dns_query: "DNS query",
  detection: "Detection",
  registry_value_set: "Registry value set",
  service_install: "Service installed",
  memory_alloc: "Memory allocation",
  kernel_event: "Kernel event",
  cloud_iam_action: "Cloud IAM action",
};

export const typeLabel = (t) =>
  TYPE_LABEL[t] || String(t || "observation").replace(/_/g, " ");

/** Cisco tags each row with the artefact's identified type. NivXForge
 *  does not run file identification, so the tag is derived from the
 *  observed path extension and falls back to the row's group — a
 *  derivation, never an identification. */
const EXT_TAG = {
  sh: "Shell", bash: "Shell", py: "Python", pl: "Perl", rb: "Ruby",
  js: "JS", so: "SharedObj", ko: "KernelMod", elf: "ELF", exe: "PE",
  dll: "PE", ps1: "Powershell", jar: "JAR", zip: "ZIP", gz: "GZ",
  tar: "TAR", conf: "Conf", json: "JSON", log: "Log", key: "Key",
  pem: "Key", csv: "CSV", txt: "Text",
};

export function rowTag(lane) {
  if (!lane) return "";
  const path = lane.image || lane.label || "";
  const m = String(path).match(/\.([A-Za-z0-9]{1,10})$/);
  if (m) {
    const tag = EXT_TAG[m[1].toLowerCase()];
    if (tag) return tag;
  }
  if (lane.group === "PROCESS") return "Proc";
  if (lane.group === "FILE") return "File";
  if (lane.group === "NETWORK") return "Net";
  return "Unattributed";
}
