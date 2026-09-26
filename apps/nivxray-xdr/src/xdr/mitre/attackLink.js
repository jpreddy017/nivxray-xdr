/**
 * Shared MITRE ATT&CK link resolver.
 *
 * Owner rules:
 *   1. Every consumer routes through `attackHrefFor()` so the whole
 *      cockpit resolves technique deep-links the same way.
 *   2. Resolution order:
 *        a. Canonical `T####` / `T####.###` in ANY candidate field
 *           → direct https://attack.mitre.org/techniques/T####/###/
 *              URL.
 *        b. Recognised technique NAME → direct URL.  The name
 *           catalogue is generated at build time from the MITRE
 *           ATT&CK Enterprise STIX bundle (see
 *           `/app/backend/mitre_catalogue/build_name_index.py`), so
 *           every parent and sub-technique currently published on
 *           attack.mitre.org resolves automatically.  Refreshing
 *           to a future ATT&CK version means re-running the build
 *           step — no hand-edits.
 *        c. A tiny non-canonical alias table below covers common
 *           backend leakages that MITRE never publishes as
 *           canonical names (`"CMD"`, `"POWERSHELL (HIDDEN)"`,
 *           `"COMMAND OBFUSCATION: BASE64/ENCODED COMMAND"`, …).
 *   3. Unresolvable → `null`.  Callers MUST render an honest
 *      "no attack id" pill; no Google search fallback exists here.
 */
import {
  CATALOGUE_VERSION,
  ATTACK_NAME_INDEX as GENERATED_INDEX,
} from "./attackNameIndex.generated.js";

const ATTACK_ID_RE = /\b(T\d{4})(?:\.(\d{3}))?\b/i;

/* Non-canonical aliases seen leaking from real detection stacks.
   Every value points at a real published ATT&CK technique — the
   catalogue itself is untouched by this alias table. */
const ALIAS_INDEX = {
  "CMD":                                                       "T1059/003",
  "POWERSHELL (HIDDEN)":                                       "T1059/001",
  "COMMAND OBFUSCATION: BASE64/ENCODED COMMAND":               "T1027/010",
  "STANDALONE LONG BASE64 BLOB (>=200 CHARS) — LIKELY ENCODED PAYLOAD":
                                                               "T1027/010",
  "SIGNED BINARY PROXY EXECUTION: RUNDLL32":                   "T1218/011",
  "SANDBOX EVASION: TIME BASED EVASION":                       "T1497/003",
  "WINDOWS MANAGEMENT INSTRUMENTATION EVENT SUBSCRIPTION":     "T1546/003",
  "REMOTE DESKTOP PROTOCOL":                                   "T1021/001",
  "OS CREDENTIAL DUMPING":                                     "T1003",
  "SYSTEM BINARY PROXY EXECUTION":                             "T1218",
  "VIRTUALIZATION/SANDBOX EVASION":                            "T1497",
};

export const ATTACK_NAME_INDEX = { ...ALIAS_INDEX, ...GENERATED_INDEX };
export const ATTACK_CATALOGUE_VERSION = CATALOGUE_VERSION;


function _normalise(s) {
  return String(s || "").replace(/\s+/g, " ").trim().toUpperCase();
}


export function extractAttackId(node) {
  if (!node) return null;
  const candidates = [node.attack_id, node.technique_id, node.tid,
                              node.object_id, node.id, node.title,
                              node.object_name, node.name, node.label,
                              node.technique_name, node.external_id];
  // Pass 1 — real ATT&CK id anywhere.
  for (const cand of candidates) {
    const m = ATTACK_ID_RE.exec(String(cand || ""));
    if (m) {
      const base = m[1].toUpperCase();
      return m[2] ? `${base}/${m[2]}` : base;
    }
  }
  // Pass 2 — catalogue-published name (whole / head:tail /
  // longest word-boundary prefix).  Only ever matches an EXACT
  // catalogue name — never a fuzzy substring.
  for (const cand of candidates) {
    const hit = _resolveName(cand);
    if (hit) return hit;
  }
  return null;
}


function _resolveName(raw) {
  const key = _normalise(raw);
  if (!key) return null;
  if (ATTACK_NAME_INDEX[key]) return ATTACK_NAME_INDEX[key];
  // head:tail
  if (key.includes(":")) {
    const colon = key.indexOf(":");
    const head = key.slice(0, colon).trim();
    const tail = key.slice(colon + 1).trim();
    if (head && ATTACK_NAME_INDEX[head]) return ATTACK_NAME_INDEX[head];
    if (tail && ATTACK_NAME_INDEX[tail]) return ATTACK_NAME_INDEX[tail];
  }
  // longest word-boundary prefix
  const words = key.split(" ");
  for (let i = words.length; i >= 1; i--) {
    const cand = words.slice(0, i).join(" ").replace(/[\s\-—:]+$/, "");
    if (cand.length >= 3 && ATTACK_NAME_INDEX[cand]) {
      return ATTACK_NAME_INDEX[cand];
    }
  }
  return null;
}


export function extractAttackName(node) {
  if (!node) return null;
  for (const cand of [node.object_name, node.name, node.label,
                                 node.technique_name, node.title, node.id]) {
    const s = String(cand || "").trim();
    if (s && s.toUpperCase() !== "NOT_APPLICABLE"
             && !ATTACK_ID_RE.test(s)) {
      return s;
    }
  }
  return null;
}


export function attackHrefFor(node) {
  const id = extractAttackId(node);
  if (id) return `https://attack.mitre.org/techniques/${id}/`;
  // No canonical id and no recognised name → honest null.
  return null;
}


export function attackLinkTitle(node) {
  if (extractAttackId(node)) return "Open technique on attack.mitre.org";
  return "No ATT&CK identifier resolvable for this row";
}
