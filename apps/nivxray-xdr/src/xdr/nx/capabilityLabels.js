/**
 * ONE analyst-facing vocabulary for investigation capabilities.
 *
 * Owner rule: the analyst reads a capability NAME, the engine keeps its
 * ID. Backend identifiers are never renamed, never translated on the
 * wire and always reachable under Technical details — this module only
 * decides what a human is shown.
 *
 * Every investigation surface (Findings · Activity · Graph · Entity
 * details · Report) imports from here so no page invents its own
 * translation.
 */

export const CAPABILITY_LABELS = {
  detection_intel:        "Detection Intelligence",
  process_ancestry:       "Process Ancestry",
  commandline_decode:     "Command Intelligence",
  lolbas_lookup:          "LOLBAS Analysis",
  mitre_expansion:        "ATT&CK Analysis",
  ioc_pivot:              "Indicator Intelligence",
  historical_correlation: "Correlation",
  correlation:            "Correlation",
  network_pivot:          "Network Intelligence",
  identity_pivot:         "Identity Intelligence",
  dns_pivot:              "DNS Intelligence",
  file_reputation:        "File Reputation",
};

/** Analyst label for a backend capability id. An unmapped id is shown
 *  readably but NEVER invented: the raw id stays available via
 *  `capabilityIsMapped` so the UI can mark it as unmapped. */
export function capabilityLabel(id) {
  if (id == null || id === "") return null;
  const key = String(id).trim();
  if (CAPABILITY_LABELS[key]) return CAPABILITY_LABELS[key];
  return key.replace(/[_:.]+/g, " ").replace(/\s+/g, " ").trim();
}

export function capabilityIsMapped(id) {
  return Boolean(id && CAPABILITY_LABELS[String(id).trim()]);
}

/** Engine identity string, verbatim — for Technical details only. */
export function capabilityEngineId(id) {
  return id == null || id === "" ? null : String(id);
}
