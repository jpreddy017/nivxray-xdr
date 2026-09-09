/**
 * Cisco XDR observable semantics · the published colour/score system.
 *
 * Source: docs.xdr.security.cisco.com/Content/navigation.htm §"Color and
 * Icon Key" (verified 2026-06). These are Cisco's PUBLISHED semantics —
 * disposition set, priority score bands and risk score bands — not a
 * reproduction of Cisco artwork. NivXRay XDR adopts the semantics and
 * renders them with its own marks.
 *
 * Owner directive: NivXRay XDR must present the same operating semantics
 * as Cisco XDR. Every screen reads these helpers so a band is defined in
 * ONE place and cannot drift per page.
 *
 * HONESTY RULE (unchanged and non-negotiable):
 *   • `clean` is NEVER inferred. A NivXRay verdict that was not asserted
 *     clean by an authoritative engine resolves to `unknown`.
 *   • A priority or risk score that was not computed returns
 *     `band: null` and `label: "Not scored"` — never a 0 that reads like
 *     a real low-risk finding.
 */

// ── Dispositions · Cisco: clean · malicious · suspicious · common · unknown ──
// Verified from docs.xdr.security.cisco.com/Content/pivot-menu.htm §Verdicts.
// Disposition PRIORITY, highest → lowest: Clean, Malicious, Suspicious,
// Common, Unknown. (Clean is the HIGHEST priority, not the lowest — this is
// counter-intuitive and is why it is encoded once, here.)
export const DISPOSITION_PRIORITY =
  ["clean", "malicious", "suspicious", "common", "unknown"];

export const DISPOSITIONS = {
  clean:      { key: "clean",      label: "Clean",      tone: "blue",
                priority: 0, cssVar: "--nx-disposition-clean" },
  malicious:  { key: "malicious",  label: "Malicious",  tone: "red",
                priority: 1, cssVar: "--nx-disposition-malicious" },
  suspicious: { key: "suspicious", label: "Suspicious", tone: "orange",
                priority: 2, cssVar: "--nx-disposition-suspicious" },
  common:     { key: "common",     label: "Common",     tone: "grey",
                priority: 3, cssVar: "--nx-disposition-common" },
  unknown:    { key: "unknown",    label: "Unknown",    tone: "grey",
                priority: 4, cssVar: "--nx-disposition-unknown" },
};

/**
 * Map any NivXRay verdict/label onto the Cisco disposition set.
 * Anything not explicitly asserted resolves to `unknown` — we do not
 * manufacture a `clean` disposition from the absence of a finding.
 */
export function disposition(value) {
  const v = String(value || "").trim().toLowerCase();
  if (!v) return DISPOSITIONS.unknown;
  if (v.includes("malicious")) return DISPOSITIONS.malicious;
  if (v.includes("suspicious")) return DISPOSITIONS.suspicious;
  if (v === "common" || v.includes("common")) return DISPOSITIONS.common;
  if (v === "clean" || v === "benign" || v.includes("clean"))
    return DISPOSITIONS.clean;
  return DISPOSITIONS.unknown;
}

/**
 * Cisco's verdict rule, implemented once (pivot-menu.htm §Verdicts):
 *   1. drop every EXPIRED judgment (end_time in the past)
 *   2. of the remaining, take the HIGHEST-PRIORITY disposition
 *   3. tie-break on the OLDEST start_time
 * Returns `null` when nothing qualifies — never a manufactured verdict.
 * `judgments`: [{ disposition, start_time, end_time, ...}]
 */
export function verdictOf(judgments, now = Date.now()) {
  const live = (judgments || []).filter((j) => {
    if (!j) return false;
    if (!j.end_time) return true;
    const t = Date.parse(j.end_time);
    return Number.isFinite(t) ? t > now : true;
  });
  if (live.length === 0) return null;
  const ranked = [...live].sort((a, b) => {
    const pa = disposition(a.disposition).priority;
    const pb = disposition(b.disposition).priority;
    if (pa !== pb) return pa - pb;
    const sa = Date.parse(a.start_time || "") || Infinity;
    const sb = Date.parse(b.start_time || "") || Infinity;
    return sa - sb;
  });
  const top = ranked[0];
  return { ...top, meta: disposition(top.disposition) };
}

/** Cisco "Copy defanged value": 216.238.85.220 → 216.238.85[.]220, http → hxxp. */
export function defang(value) {
  let s = String(value ?? "");
  if (!s) return s;
  s = s.replace(/^http/i, (m) => (m[0] === "H" ? "HXXP" : "hxxp"));
  const i = Math.max(s.lastIndexOf("."), s.lastIndexOf(":"));
  if (i > -1) s = `${s.slice(0, i)}[${s[i]}]${s.slice(i + 1)}`;
  return s;
}

// ── Priority score · Cisco bands ────────────────────────────────────
// ≥800 red · 600–799 orange · 400–599 yellow · ≤399 blue · none grey
const PRIORITY_BANDS = [
  { min: 800, band: "critical", label: "Critical", tone: "red"    },
  { min: 600, band: "high",     label: "High",     tone: "orange" },
  { min: 400, band: "medium",   label: "Medium",   tone: "yellow" },
  { min: 0,   band: "low",      label: "Low",      tone: "blue"   },
];

// ── Risk score · Cisco bands (0–100) ───────────────────────────────
// 80–100 Critical · 60–79 High · 40–59 Medium · 0–39 Low · N/A grey
const RISK_BANDS = [
  { min: 80, band: "critical", label: "Critical", tone: "red"    },
  { min: 60, band: "high",     label: "High",     tone: "orange" },
  { min: 40, band: "medium",   label: "Medium",   tone: "yellow" },
  { min: 0,  band: "low",      label: "Low",      tone: "blue"   },
];

const NOT_SCORED = { band: null, label: "Not scored", tone: "grey",
                     score: null, scored: false };

function resolve(bands, score) {
  if (score === null || score === undefined || score === "") return NOT_SCORED;
  const n = Number(score);
  if (!Number.isFinite(n)) return NOT_SCORED;
  const hit = bands.find((b) => n >= b.min) || bands[bands.length - 1];
  return { ...hit, score: n, scored: true };
}

/** Cisco priority band for a 0–1000 priority score. */
export const priorityBand = (score) => resolve(PRIORITY_BANDS, score);

/** Cisco risk band for a 0–100 risk score. */
export const riskBand = (score) => resolve(RISK_BANDS, score);

/** The published band table, for rendering a legend without retyping it. */
export const BANDS = { priority: PRIORITY_BANDS, risk: RISK_BANDS };
