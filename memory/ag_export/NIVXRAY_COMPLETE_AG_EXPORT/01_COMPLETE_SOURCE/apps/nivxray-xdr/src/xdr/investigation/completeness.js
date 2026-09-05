/**
 * Investigation Completeness — deterministic gap checker.
 *
 * "NivXRay must know whether the investigation is actually complete."
 *
 * Every facet is scored { present: bool, source: string } from real
 * incident payload.  NEVER fabricated — a missing facet is honestly
 * reported as missing and blocks the "Investigation Complete" state.
 *
 * The list of facets matches the owner-listed structure:
 *   identity · endpoint · process · file · network · dns ·
 *   persistence · threat_intel · mitre · lateral_movement ·
 *   blast_radius · response · evidence · root_cause · user_validation.
 */

export const COMPLETENESS_FACETS = [
  { key: "identity",         label: "Identity" },
  { key: "endpoint",         label: "Endpoint" },
  { key: "process",          label: "Process" },
  { key: "file",             label: "File" },
  { key: "network",          label: "Network" },
  { key: "dns",              label: "DNS" },
  { key: "persistence",      label: "Persistence" },
  { key: "threat_intel",     label: "Threat Intelligence" },
  { key: "mitre",            label: "MITRE mapping" },
  { key: "lateral_movement", label: "Lateral movement" },
  { key: "blast_radius",     label: "Blast radius" },
  { key: "response",         label: "Response status" },
  { key: "evidence",         label: "Evidence" },
  { key: "root_cause",       label: "Root cause" },
  { key: "user_validation",  label: "User validation" },
];


function _has(coll) { return Array.isArray(coll) ? coll.length > 0 : !!coll; }


/**
 * @param {object} ctx
 *   - incident       (required) — canonical incident payload
 *   - executions     (Response Engine executions for this incident)
 *   - verdict        (Verdict Stage-2 payload if fetched)
 *   - summary        (`/api/incidents/:id/summary` payload if fetched)
 * @returns {
 *   facets: [{ key, label, present, partial, source }],
 *   score:  number (0..1),
 *   complete: boolean,
 *   missing:  string[]
 * }
 */
export function computeCompleteness(ctx) {
  const { incident, executions = [], verdict, summary } = ctx || {};
  const ev  = incident?.evidence || [];
  const has = (k) => ev.some((e) => e[k] != null && e[k] !== "");

  const facetMap = {
    identity: () => _has(incident?.users) || has("user"),
    endpoint: () => _has(incident?.hosts) || has("host"),
    process:  () => has("process") || has("pid") || has("command_line")
                     || has("commandline") || _has(incident?.processes),
    file:     () => has("file") || has("sha256") || has("md5") || has("path"),
    network:  () => has("ip") || has("connection")
                     || _has(incident?.network_connections),
    dns:      () => has("domain") || has("dns"),
    persistence: () => (incident?.persistence != null)
                       || has("persistence")
                       || (Array.isArray(summary?.persistence)
                             && summary.persistence.length > 0),
    threat_intel: () => Boolean(
        incident?.threat_intel
     || has("malware_family")
     || (verdict?.evidence || []).some((e) => e.rule_id?.includes("ti_"))
    ),
    mitre: () => (verdict?.techniques || []).length > 0
                 || ev.some((e) => e.technique_id),
    lateral_movement: () =>
        (verdict?.techniques || []).some((t) => t.startsWith("T1021"))
     || has("lateral_movement"),
    blast_radius: () =>
        (incident?.hosts?.length || 0) > 1
     || (incident?.users?.length || 0) > 1,
    response: () => executions.length > 0,
    evidence: () => ev.length > 0,
    root_cause: () => Boolean(
        summary?.root_cause
     || incident?.root_cause
     || (verdict?.summary || "").toLowerCase().includes("root")
    ),
    user_validation: () => Boolean(
        incident?.analyst_validated
     || incident?.validated_by
     || executions.some((x) => x.state === "SUCCEEDED"
                                    && x.invoker_kind === "analyst")
    ),
  };

  const partial = {
    // A facet can be PARTIAL when the SSOT knows about it but only
    // has a single reference.  This is a deterministic heuristic; no
    // ML.  Never treats a partial as complete.
    persistence: () => (has("persistence") && !(summary?.persistence?.length)),
    root_cause:  () => Boolean(summary?.root_cause_partial),
    user_validation: () => Boolean(incident?.validation_pending),
  };

  const out = COMPLETENESS_FACETS.map((f) => {
    let present = false, isPartial = false;
    try { present = !!facetMap[f.key]?.(); } catch { present = false; }
    try { isPartial = present && !!(partial[f.key]?.()); } catch { isPartial = false; }
    return {
      key: f.key, label: f.label,
      present, partial: isPartial,
      source: present
        ? (verdict ? "verdict/stage2" : summary ? "incident/summary"
                                                                : "incident/evidence")
        : "missing",
    };
  });

  const total = out.length;
  const scored = out.reduce((n, f) => n + (f.present ? (f.partial ? 0.5 : 1) : 0), 0);
  const score = total === 0 ? 0 : (scored / total);
  const missing = out.filter((f) => !f.present).map((f) => f.key);

  return {
    facets:   out,
    score:    Number(score.toFixed(3)),
    complete: score >= 1.0,
    missing,
    partial:  out.filter((f) => f.partial).map((f) => f.key),
  };
}
