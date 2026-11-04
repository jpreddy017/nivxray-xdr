/**
 * NivXRay XDR — Extension Contract
 * ─────────────────────────────────
 *
 * The universal manifest every plug-and-play capability MUST declare
 * before it can be installed into NivXRay XDR.  This is the single
 * architectural piece that turns Admin from a hand-coded feature set
 * into an extensible platform.
 *
 *   Install → Configure → Test → Enable → Disable → Upgrade → Remove
 *
 * Extension types (canonical, closed set):
 *
 *   CONNECTOR    — pulls telemetry from a third-party source
 *   COLLECTOR    — first-party collector runtime (linux/win/k8s/cloud)
 *   PROTOCOL     — syslog / cef / leef / kafka / s3 / eventhub / …
 *   PARSER       — canonical event parser for a source type
 *   NORMALIZER   — schema mapping to canonical evidence
 *   DETECTOR     — Sigma / YARA / correlation rule producer
 *   CORRELATOR   — ICE-style rules or plug-in
 *   ENRICHMENT   — IOC / identity / asset enrichment provider
 *   TI_PROVIDER  — threat-intel feed (STIX/TAXII, MISP, VT, …)
 *   ACTION       — response action (endpoint / identity / network / …)
 *   PLAYBOOK_PACK — bundled playbooks
 *   CONTENT_PACK  — connectors + parsers + rules + playbooks + tests
 *   AGENT         — endpoint agent
 *   PATTERN_ENGINE — regex/glob/exact/cidr/yara/sigma/threshold/sequence
 *
 * The manifest is deliberately declarative — NO executable code is
 * uploaded.  An extension is a REGISTRATION.  Actual behaviour is
 * implemented by first-party adapters in-tree that match the
 * declared `provider` + `type` tuple.  This preserves NivXRay's
 * evidence-first / deterministic invariants.
 */

export const EXTENSION_TYPES = [
  "CONNECTOR", "COLLECTOR", "PROTOCOL", "PARSER", "NORMALIZER",
  "DETECTOR",  "CORRELATOR", "ENRICHMENT", "TI_PROVIDER",
  "ACTION",    "PLAYBOOK_PACK", "CONTENT_PACK", "AGENT",
  "PATTERN_ENGINE",
];

export const LIFECYCLE_STATES = [
  "AVAILABLE",   // in catalog, not yet installed
  "INSTALLING",
  "INSTALLED",   // installed, not configured
  "CONFIGURED",  // configured, not tested
  "TESTED",      // test connection passed
  "ENABLED",     // active
  "DISABLED",    // installed but off
  "DRAINING",    // being removed; queued work still finishing
  "REMOVING",
  "DEPRECATED",  // installed but end-of-life
  "FAILED",      // install/config/test failed
];

export const LIFECYCLE_TRANSITIONS = {
  AVAILABLE:  ["INSTALLING"],
  INSTALLING: ["INSTALLED", "FAILED"],
  INSTALLED:  ["CONFIGURED", "REMOVING", "DEPRECATED"],
  CONFIGURED: ["TESTED", "INSTALLED", "REMOVING"],
  TESTED:     ["ENABLED", "CONFIGURED", "REMOVING"],
  ENABLED:    ["DISABLED", "DRAINING", "DEPRECATED"],
  DISABLED:   ["ENABLED", "REMOVING", "DEPRECATED"],
  DRAINING:   ["REMOVING"],
  REMOVING:   ["AVAILABLE"],
  DEPRECATED: ["REMOVING"],
  FAILED:     ["INSTALLING", "REMOVING"],
};

// ── Manifest schema keys (all required unless noted) ────────────
export const MANIFEST_REQUIRED_KEYS = [
  "capability_id",       // slug — "collector.crowdstrike.falcon"
  "name",                // "CrowdStrike Falcon EDR Collector"
  "type",                // one of EXTENSION_TYPES
  "provider",            // "crowdstrike" | "microsoft" | "nivxray" | …
  "version",             // semver
  "vendor",              // "CrowdStrike Holdings, Inc."
  "authentication",      // ["api_key"] | ["oauth2"] | ["bearer"] | …
  "permissions",         // ["read:alerts", "read:devices", …]
  "supported_operations",// ["pull_alerts", "isolate_device", …]
  "input_schema",        // canonical shape the extension consumes
  "output_schema",       // canonical shape it produces
  "health_check",        // { kind, endpoint?, method?, interval_seconds }
  "lifecycle",           // one of LIFECYCLE_STATES
  "adapter_status",      // "AVAILABLE" | "STUB" | "NOT_IMPLEMENTED"
];

export const MANIFEST_OPTIONAL_KEYS = [
  "description", "logo", "docs_url", "transport",
  "dependencies",        // ["capability_id", …] for CONTENT_PACK etc
  "rollback",            // { supported: bool, evidence_required: bool }
  "risk",                // "low" | "medium" | "high" | "critical"
  "execution_mode",      // "sync" | "async" | "batch"
  "approval_required",   // bool
  "destructive",         // bool
  "installed_at", "installed_by", "config_ref",
];


/** Validate a manifest.  Returns { valid, missing[], invalid[] }.
 *  Deterministic.  Never accepts unknown types or invalid lifecycle. */
export function validateManifest(m) {
  const missing = [];
  const invalid = [];
  if (!m || typeof m !== "object") {
    return { valid: false, missing: MANIFEST_REQUIRED_KEYS, invalid: [] };
  }
  for (const k of MANIFEST_REQUIRED_KEYS) {
    if (!(k in m)) missing.push(k);
  }
  if (m.type && !EXTENSION_TYPES.includes(m.type))
    invalid.push(`type:${m.type}`);
  if (m.lifecycle && !LIFECYCLE_STATES.includes(m.lifecycle))
    invalid.push(`lifecycle:${m.lifecycle}`);
  if (m.adapter_status
       && !["AVAILABLE", "STUB", "NOT_IMPLEMENTED"].includes(m.adapter_status))
    invalid.push(`adapter_status:${m.adapter_status}`);
  return {
    valid: missing.length === 0 && invalid.length === 0,
    missing, invalid,
  };
}


/** Verify a lifecycle transition is permitted.  Returns
 *  { ok, reason }.  Deterministic; NEVER auto-transitions. */
export function canTransition(from, to) {
  const allowed = LIFECYCLE_TRANSITIONS[from] || [];
  if (allowed.includes(to)) return { ok: true };
  return {
    ok: false,
    reason: `Illegal transition ${from} → ${to}. `
              + `Allowed: ${allowed.join(", ") || "(none)"}`,
  };
}


/** Dependency check.  Given a manifest and the current installed
 *  registry, returns the list of missing prerequisites (never
 *  fabricates a fake dependency).  Used to gate install + remove.
 */
export function missingDependencies(m, installedIndex) {
  const deps = m?.dependencies || [];
  const missing = [];
  for (const dep of deps) {
    const found = installedIndex[dep];
    if (!found || !["ENABLED", "TESTED", "CONFIGURED", "INSTALLED"]
                             .includes(found.lifecycle))
      missing.push(dep);
  }
  return missing;
}


/** Given an installed registry + a capability to remove, return the
 *  list of ENABLED extensions that depend on it.  If non-empty, the
 *  UI must warn "Cannot remove — used by …" and require Force Remove. */
export function dependents(capabilityId, installedIndex) {
  const out = [];
  for (const [id, m] of Object.entries(installedIndex || {})) {
    if ((m.dependencies || []).includes(capabilityId))
      out.push({ id, name: m.name, lifecycle: m.lifecycle });
  }
  return out;
}
