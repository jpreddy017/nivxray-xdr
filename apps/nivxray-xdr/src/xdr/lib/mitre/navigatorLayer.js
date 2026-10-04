// MITRE ATT&CK Navigator layer export (layer format 4.5, Navigator 5.x). Pure; shared by the DT ATT&CK strip
// (and any HeatMap export). Version fields follow the vendored catalogue version.
export const LAYER_FORMAT = "4.5";
export const NAVIGATOR_VERSION = "5.1.0";

export function buildLayer({ name, description, version, techniques, domain = "enterprise-attack", metadata = [] }) {
  const max = Math.max(1, ...techniques.map((t) => t.score || 0));
  return {
    name, versions: { attack: String(version).split(".")[0], navigator: NAVIGATOR_VERSION, layer: LAYER_FORMAT }, domain, description,
    filters: { platforms: ["Windows", "Linux", "macOS"] }, sorting: 3,
    layout: { layout: "side", aggregateFunction: "average", showID: true, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: "annotated" },
    hideDisabled: false,
    techniques: techniques.map((t) => ({ techniqueID: t.techniqueID, tactic: t.tactic, score: t.score, color: "", comment: t.comment || "", enabled: true,
      metadata: t.metadata || [], links: t.links || [], showSubtechniques: false })),
    gradient: { colors: ["#ffffffff", "#66b1ffff", "#ff6666ff"], minValue: 0, maxValue: max },
    legendItems: [], metadata: [{ name: "catalogue", value: `ATT&CK Enterprise v${version}` }, ...metadata], links: [],
    showTacticRowBackground: false, tacticRowBackground: "#dddddd", selectTechniquesAcrossTactics: true, selectSubtechniquesWithParent: false, selectVisibleTechniques: false,
  };
}

// Strip summary (GET …/trajectory/attack) -> one layer entry per (technique, tactic), scored by count.
export function layerFromStrip(strip, { device, t0, t1 }) {
  const techniques = strip.tactics.flatMap((tac) => tac.techniques.map((x) => ({
    techniqueID: x.technique, tactic: tac.shortname, score: x.count,
    comment: `${x.count} observed on ${device} · ${(x.types || []).join(", ")} · ${(x.rules || []).join(", ") || "no rule id"} · observed technique is not a confirmed attack`,
    metadata: [{ name: "first_seen", value: new Date(x.first_ms).toISOString() }, { name: "last_seen", value: new Date(x.last_ms).toISOString() }],
    links: [{ label: "attack.mitre.org", url: x.url }],
  })));
  return buildLayer({ name: `NivXForge DT · ${device}`, version: strip.catalogue_version, techniques,
    description: `${strip.label}. ${new Date(t0).toISOString()} – ${new Date(t1).toISOString()}. ${strip.semantics}`,
    metadata: [{ name: "device", value: String(device) }, { name: "source", value: strip.source || "E1 trajectory attribution" }] });
}

export function validateLayer(l) {
  const err = [];
  const need = { name: "string", versions: "object", domain: "string", techniques: "object", gradient: "object", layout: "object" };
  Object.entries(need).forEach(([k, t]) => { if (typeof l?.[k] !== t) err.push(`${k} must be ${t}`); });
  if (l?.versions && (!/^\d+$/.test(l.versions.attack) || l.versions.layer !== LAYER_FORMAT || !/^\d+\.\d+\.\d+$/.test(l.versions.navigator))) err.push("versions invalid");
  if (l?.domain !== "enterprise-attack") err.push("domain must be enterprise-attack");
  (l?.techniques || []).forEach((t, i) => {
    if (!/^T\d{4}(\.\d{3})?$/.test(t.techniqueID || "")) err.push(`techniques[${i}].techniqueID invalid`);
    if (!/^[a-z-]+$/.test(t.tactic || "")) err.push(`techniques[${i}].tactic must be a tactic shortname`);
    if (typeof t.score !== "number") err.push(`techniques[${i}].score must be a number`);
  });
  if (l?.gradient && !(Array.isArray(l.gradient.colors) && l.gradient.colors.length >= 2)) err.push("gradient.colors needs ≥2 colours");
  return err;
}
