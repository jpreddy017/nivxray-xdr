/**
 * evidenceDescriptors — Phase A.5 · item 3.5.
 *
 * Standardised builders for the descriptor shape consumed by
 * <EvidenceModal>. One shared factory per analyst-surface source
 * keeps every entry-point (Investigation Detail · Investigation
 * Replay · Compare Cases · Timeline · MITRE · Provenance) speaking
 * the same evidence language.
 *
 * Descriptor contract (all fields optional; modal renders what's
 * present):
 *   {
 *     source, title, rule_id, rule_description,
 *     contribution, weight, hit_count,
 *     artifact:      { type, sha256, size, name },
 *     analyzer,
 *     recovered_child: { type, sha256, depth },
 *     mitre:         [id, ...],
 *     evidence_refs: [ {...}, ...],
 *     timeline_ref:  { kind, code, ts },
 *     related:       [ { kind, sha256, label }, ...],
 *     raw:           <any JSON>
 *   }
 */

// ── Investigation Detail — Attack Chain node ───────────────────────
export function fromChainStep(step) {
  const isCase = step.kind === "case";
  return {
    source: isCase ? "Investigation · Attack Chain (Case)"
                   : "Investigation · Attack Chain (Artifact)",
    title:  step.case_name || step.label || step.input_preview || step.node_id,
    rule_description: step.snippet || step.input_preview || null,
    artifact: step.artifact_type
      ? { type: step.artifact_type, sha256: step.sha256, name: step.case_name }
      : null,
    mitre: step.techniques || [],
    related: (step.children || []).map(c => ({
      kind:   c.artifact_type,
      sha256: c.sha256,
      label:  c.case_name || c.label,
    })),
    raw: step,
  };
}

// ── Investigation Detail — Unified Timeline event ─────────────────
export function fromTimelineEvent(ev) {
  const isCase = ev.kind === "case_analyzed";
  return {
    source: "Investigation · Unified Timeline",
    title:  ev.label || ev.case_id || ev.relationship || "Timeline event",
    rule_description: isCase
      ? `${ev.artifact_type || "case"} · ${ev.verdict || ""}`
      : (ev.relationship || "linked"),
    artifact: ev.artifact_type
      ? { type: ev.artifact_type, name: ev.label }
      : null,
    timeline_ref: { kind: ev.kind, code: ev.source || ev.relationship, ts: ev.ts },
    raw: ev,
  };
}

// ── Investigation Detail — MITRE chip on summary card ─────────────
export function fromMitreEntry(m) {
  return {
    source: "Investigation · MITRE ATT&CK",
    title:  m.id,
    rule_id: m.id,
    rule_description: m.technique || m.name,
    mitre:  [m.id],
    hit_count: (m.sources || []).length,
    related: (m.sources || []).map(cid => ({
      kind: "case", label: cid.slice(0, 16) + "…", sha256: cid,
    })),
    raw: m,
  };
}

// ── Compare Cases — Confidence Provenance rule fire ───────────────
export function fromProvenanceRuleFire(rule, side) {
  return {
    source: `Compare · Case ${side} · Confidence Provenance`,
    title:  rule.id,
    rule_id: rule.id,
    rule_description: rule.description,
    contribution: rule.contribution,
    weight: rule.weight,
    hit_count: rule.hit_count,
    evidence_refs: rule.evidence_refs || [],
    raw: rule,
  };
}
