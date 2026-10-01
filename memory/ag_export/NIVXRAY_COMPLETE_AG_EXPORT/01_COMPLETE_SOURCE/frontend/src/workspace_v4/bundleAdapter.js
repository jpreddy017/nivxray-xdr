/**
 * Bridge adapter (PR-4) · WorkspacePage → L4 Analyst Workspace.
 *
 * Maps an Auto-Investigate / Decode result on WorkspacePage into the
 * ``EvidenceBundle`` shape ``POST /api/investigation`` expects.
 *
 * This is **plumbing, not new business logic** (per the ARB PR-4 bridge
 * scope): every field below is a direct projection from data the L0/L1
 * pipeline already produced. No inference, no scoring, no new decoders.
 *
 * When the analyst reaches PR-5 the Evidence lens will lean on the same
 * ``anchor`` shape we already emit here, so keeping this thin is
 * intentional.
 */

/** deterministic 8-char hex tag (client-side) for the case_id prefix.
 *  We reuse the backend ``final_artifact_hash_sha256`` when available so
 *  re-clicking the bridge on the same artefact reuses the same case
 *  (the backend enforces 409 on collision — we handle it by navigating
 *  to the pre-existing case instead of creating a duplicate).
 */
function shortHash(str) {
  // Simple stable 32-bit FNV-1a — sufficient for a UI case-id prefix.
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16).padStart(8, "0");
}

/** deriveCaseId · deterministic id so re-clicks are idempotent. */
export function deriveCaseId(input, artifactHash) {
  const seed = (artifactHash && String(artifactHash).slice(0, 16))
    || shortHash(input || "unknown");
  return `wsp-${seed}`.slice(0, 40);
}

/** Map decode-smart trace entries → EvidenceBundle.transformations. */
function toTransformations(trace) {
  if (!Array.isArray(trace)) return [];
  return trace
    .map((t, i) => {
      const op = t.op || t.step || t.engine || "unknown";
      return {
        iteration: i,
        pass_name: t.pass_name || "decoder",
        transformation: op,
        changed: t.changed !== false,     // default true unless explicitly false
        before_hash: t.before_hash || "",
        after_hash: t.after_hash || "",
      };
    });
}

/** Map investigation.iocs → EvidenceBundle.iocs. Best-effort typing. */
function toIocs(iocs) {
  if (!Array.isArray(iocs)) return [];
  return iocs.map((i, idx) => ({
    ioc_id: i.ioc_id || `ioc-${String(idx).padStart(3, "0")}`,
    ioc_type: i.ioc_type || i.type || "unknown",
    value: i.value || i.ioc || "",
    source_iteration: Number.isInteger(i.source_iteration) ? i.source_iteration : idx,
    source_span: Array.isArray(i.source_span) ? i.source_span : [0, 0],
    context: i.context || "",
  }));
}

/** Map investigation.capabilities → EvidenceBundle.capabilities. */
function toCapabilities(caps) {
  if (!Array.isArray(caps)) return [];
  return caps.map((c) => ({
    capability_id: c.capability_id || c.id || "CAP.UNKNOWN",
    display_name: c.display_name || c.name || c.capability_id || "Unknown capability",
    confidence: c.confidence || "medium",
    source_iterations: Array.isArray(c.source_iterations) ? c.source_iterations : [],
  }));
}

/** Map investigation.mitre → EvidenceBundle.mitre. */
function toMitre(mitre) {
  if (!Array.isArray(mitre)) return [];
  return mitre.map((m) => ({
    technique_id: m.technique_id || m.id || "",
    technique_name: m.technique_name || m.name || "",
    tactic: m.tactic || "",
    via_capability: m.via_capability || "",
    source_iterations: Array.isArray(m.source_iterations) ? m.source_iterations : [],
  }));
}

/**
 * buildInvestigationBundle · single source-of-truth adapter.
 *
 * Inputs (all optional except ``input``):
 *   - input            · raw analyst payload
 *   - decodeResp       · payload returned by /api/decode/smart
 *   - verdictCard      · Analysis Verdict panel state (verdict / risk / family / technique)
 *   - investigation    · investigation panel state (iocs / capabilities / mitre / sample)
 *   - output           · canonical output text currently in the OUTPUT panel
 */
export function buildInvestigationBundle({
  input,
  decodeResp,
  verdictCard,
  investigation,
  output,
}) {
  const d = decodeResp || {};
  const inv = investigation || d.investigation || {};
  const vc = verdictCard || d.verdict_card || {};
  const trace = d.trace || [];

  const artifactHash =
    d.final_artifact_hash_sha256 ||
    d.artifact_hash ||
    vc.artifact_hash ||
    "";

  const case_id = deriveCaseId(input, artifactHash);

  const canonicalState = !!(
    d.canonical_state ??
    d.reached_shellcode ??
    vc.canonical_state ??
    false
  );
  const readyForBehavioral = !!(
    d.ready_for_behavioral_analysis ??
    canonicalState
  );

  return {
    case_id,
    certificate: {
      canonical_state: canonicalState,
      ready_for_behavioral_analysis: readyForBehavioral,
      iterations_executed: Array.isArray(trace) ? trace.length : 0,
      final_artifact_hash_sha256: artifactHash,
      interpreter: d.detected_type || vc.interpreter || "",
    },
    canonical_output: (output || d.output || "").slice(0, 200000),
    transformations: toTransformations(trace),
    iocs: toIocs(inv.iocs || d.iocs || []),
    capabilities: toCapabilities(inv.capabilities || d.capabilities || []),
    mitre: toMitre(inv.mitre || d.mitre || []),
    sample: {
      family: (inv.sample && inv.sample.family) || vc.family || "",
      technique: (inv.sample && inv.sample.technique) || vc.technique || "",
      variant: (inv.sample && inv.sample.variant) || "",
      sample_id: (inv.sample && inv.sample.sample_id) || case_id,
    },
  };
}

export default buildInvestigationBundle;
