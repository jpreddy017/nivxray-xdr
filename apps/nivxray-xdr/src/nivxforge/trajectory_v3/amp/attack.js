// ATT&CK helpers for DT V3. Tactic order, catalogue version and attribution text come from the SAME generated module
// the ATT&CK HeatMap uses (built from MITRE's official STIX release). Technique data is E1's own attribution
// (row.mitre / findings) decorated server-side: `ev.e3_attack`.
import { ATTACK_ATTRIBUTION, ATTACK_TACTICS, CATALOGUE_MODIFIED, CATALOGUE_VERSION } from "@/xdr/lib/mitre/attackNameIndex.generated";

export const ATTACK_CATALOGUE_VERSION = CATALOGUE_VERSION;
export { ATTACK_ATTRIBUTION, ATTACK_TACTICS, CATALOGUE_MODIFIED };
export const KILL_CHAIN = ATTACK_TACTICS;
export const TACTIC_LABEL = Object.fromEntries(ATTACK_TACTICS.map((t) => [t.key, t.label]));
export const TACTIC_ID = Object.fromEntries(ATTACK_TACTICS.map((t) => [t.key, t.id]));
export const SEMANTICS = "Mapped by rule metadata. A MITRE mapping is not a verdict.";
export const DETECTION_TYPES = ["Rule-mapped", "Intel-derived"];

export const attributionOf = (it) => it?.ev?.e3_attack || null;
export const attackOf = (it) => attributionOf(it)?.techniques || [];
export const isDetectionMapped = (it) => DETECTION_TYPES.includes(attributionOf(it)?.type);
// Tactic filter + marker badge act on detection mappings only; heuristic ingest tags never hide or badge an event.
export const tacticsOf = (it) => (isDetectionMapped(it) ? attributionOf(it).tactics || [] : []);
export const attackText = (it) => attackOf(it).flatMap((a) => [a.technique, a.name, a.parent_name, a.parent_id]).filter(Boolean).join(" ");
export const techMatches = (mapped, q) => { const u = String(q || "").toUpperCase(); return mapped === u || mapped.startsWith(`${u}.`); };
export const hasTechnique = (it, tid) => attackOf(it).some((a) => techMatches(a.technique, tid));

export const heatmapHref = ({ technique, device, t0, t1 }) => {
  const p = new URLSearchParams({ q: technique, technique, from: "device-trajectory" });
  if (device) p.set("device", device);
  if (t0) p.set("t0", String(t0));
  if (t1) p.set("t1", String(t1));
  return `/xdr/intelligence/mitre?${p}`;
};
// Chip colour follows detection severity, never "red because mapped".
export const sevTone = (sev, C) => ({ CRITICAL: C.red, HIGH: C.red, MEDIUM: C.amber, LOW: C.accent }[String(sev || "").toUpperCase()] || C.label);
