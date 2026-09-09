/**
 * NivXRay XDR · Recommendation Engine (deterministic core)
 * ─────────────────────────────────────────────────────────
 *
 * "Recommend what the analyst should do next, based on ACTUAL
 * evidence, and explain why."
 *
 * This engine NEVER invents scoring.  It composes:
 *
 *   · Base evidence-driven recommendations (`/api/decode/mitigations/evidence_driven`
 *     — AUTHORITATIVE recommender in NivXRay).
 *   · Rules matched on the incident (from Verdict Stage-2 + Sigma
 *     evaluator in XDR).
 *   · Playbook state (applicable / already_executed / partial /
 *     failed / waiting_approval / unavailable / requires_target).
 *   · Verdict (severity + confidence).
 *   · IOC disposition (reputation + malware family from `/api/ioc`).
 *   · MITRE technique attribution.
 *
 * Every recommendation carries a "supporting[]" list (positive
 * evidence) and "risk_modifiers[]" (things that make it dangerous)
 * so the UI can render the full explainability chain.
 *
 * Deterministic.  Identical inputs → identical output ordering.
 * No LLM.  No randomness.  No fabricated metrics.
 */

// ── Canonical recommendation kinds ──────────────────────────────
export const REC_KIND = {
  INVESTIGATE: "investigate",
  ENRICH:      "enrich",
  COLLECT:     "collect",
  RESPOND:     "respond",
  DECODE:      "decode",
  HUNT:        "hunt",
};

// ── Priority levels ─────────────────────────────────────────────
export const REC_PRIORITY = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };

function priorityLabel(p) {
  return Object.entries(REC_PRIORITY).find(([, v]) => v === p)?.[0] || "INFO";
}

// ── Rule-driven templates ───────────────────────────────────────
// Each entry: rule_id / mitre technique → list of atomic
// recommendations grounded in that rule's contract.  Templates are
// small (this is a deterministic mapping, not a knowledge base).
// The RULE ITSELF is authoritative; templates just materialise
// "what should the analyst do because THIS rule fired?".
const RULE_TEMPLATES = {
  // Sigma sample: Encoded PowerShell Execution
  "encoded_powershell": [
    { kind: "investigate", label: "Inspect parent process",
      action: "process_tree",  priority: REC_PRIORITY.HIGH },
    { kind: "decode",      label: "Decode command line via DIE",
      action: "die_decode",    priority: REC_PRIORITY.HIGH },
    { kind: "hunt",        label: "Search same command line across hosts",
      action: "hunt_commandline", priority: REC_PRIORITY.MEDIUM },
    { kind: "investigate", label: "Investigate parent Office document",
      action: "investigate_document", priority: REC_PRIORITY.MEDIUM,
      requires_parent: ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"] },
  ],
  // MITRE T1071.001 · C2 over HTTPS
  "T1071.001": [
    { kind: "investigate", label: "Inspect network connections from process",
      action: "process_tree", priority: REC_PRIORITY.HIGH },
    { kind: "enrich",      label: "Enrich destination IOCs",
      action: "ioc_enrich",   priority: REC_PRIORITY.HIGH },
    { kind: "collect",     label: "Collect endpoint memory + network capture",
      action: "collect_endpoint_evidence", priority: REC_PRIORITY.HIGH },
    { kind: "respond",     label: "Block malicious IOC at egress",
      action: "block_ioc", priority: REC_PRIORITY.CRITICAL,
      destructive: false, approval_required: true },
  ],
  // MITRE T1059.001 · PowerShell
  "T1059.001": [
    { kind: "decode",      label: "Decode PowerShell payload via IEDDE",
      action: "iedde_analyze", priority: REC_PRIORITY.HIGH },
    { kind: "investigate", label: "Show process tree",
      action: "process_tree",  priority: REC_PRIORITY.HIGH },
    { kind: "hunt",        label: "Hunt identical PS payload across fleet",
      action: "hunt_commandline", priority: REC_PRIORITY.MEDIUM },
  ],
  // MITRE T1105 · Ingress Tool Transfer
  "T1105": [
    { kind: "enrich",      label: "Enrich file hash via IOC intel",
      action: "ioc_enrich", priority: REC_PRIORITY.HIGH },
    { kind: "collect",     label: "Collect transferred file",
      action: "collect_file", priority: REC_PRIORITY.HIGH },
    { kind: "respond",     label: "Block source IP + hash",
      action: "block_ioc", priority: REC_PRIORITY.HIGH,
      approval_required: true },
  ],
};

// ── Playbook state kinds (owner-listed) ─────────────────────────
export const PB_STATE = {
  APPLICABLE:         "applicable",
  ALREADY_EXECUTED:   "already_executed",
  PARTIAL:            "partial",
  FAILED:             "failed",
  WAITING_APPROVAL:   "waiting_approval",
  UNAVAILABLE:        "unavailable",
  REQUIRES_TARGET:    "requires_target",
};

// ── Rule-match kinds (owner-listed) ─────────────────────────────
export const RULE_MATCH = {
  MATCHED:            "matched",
  PARTIALLY_MATCHED:  "partially_matched",
  SUPPRESSED:         "suppressed",
  EXCLUDED:           "excluded",
  CONFLICTING:        "conflicting",
  PREVIOUSLY_TRIGGERED: "previously_triggered",
};


/**
 * Compute recommendations from a full investigation context.
 *
 * @param {object} ctx
 *   - incident            (required)
 *   - baseRecs            (evidence-driven-mitigations payload from base, optional)
 *   - iocDispositions     (map ioc → { reputation, malware_family })
 *   - matchedRules        (array of { rule_id, match, evidence, technique })
 *   - applicablePlaybooks (array of { playbook_id, state, executed_actions, remaining_actions })
 *   - previousResponses   (array of { action, state, completed_at, target })
 * @returns { recommendations: [...] }
 *   Each recommendation has:
 *     { id, kind, label, priority, priority_label, action,
 *       supporting: [ { kind, ref, note } ],
 *       risk_modifiers: [ { kind, note } ],
 *       approval_required, destructive, source }
 */
export function computeRecommendations(ctx) {
  const {
    incident, baseRecs, iocDispositions = {},
    matchedRules = [], applicablePlaybooks = [], previousResponses = [],
  } = ctx || {};

  const out = [];
  const seen = new Set();  // idempotency by (kind, action)

  const push = (rec) => {
    const key = `${rec.kind}:${rec.action}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({
      ...rec,
      id: `rec_${out.length + 1}`,
      priority_label: priorityLabel(rec.priority),
    });
  };

  // ── 1. Rule-driven recommendations ────────────────────────────
  for (const r of matchedRules) {
    if (r.match === RULE_MATCH.SUPPRESSED || r.match === RULE_MATCH.EXCLUDED) continue;
    // Look up template by rule_id OR by technique.
    const tpl = RULE_TEMPLATES[r.rule_id] || RULE_TEMPLATES[r.technique] || [];
    for (const t of tpl) {
      // Guard: parent-process-required templates only fire if the
      // required parent is in the evidence.
      if (t.requires_parent) {
        const evParent = (r.evidence?.parent_image ||
                                     r.evidence?.parent_process || "").toLowerCase();
        if (!t.requires_parent.some((p) => evParent.includes(p))) continue;
      }
      push({
        kind: t.kind, label: t.label, action: t.action,
        priority: t.priority,
        approval_required: !!t.approval_required,
        destructive:       !!t.destructive,
        source: `rule:${r.rule_id}`,
        supporting: [
          { kind: "rule",     ref: r.rule_id,   note: `Rule matched · ${r.match}` },
          ...(r.technique ? [{ kind: "mitre", ref: r.technique }] : []),
          ...(r.evidence
                 ? Object.entries(r.evidence).slice(0, 4)
                          .map(([k, v]) => ({ kind: "field", ref: `${k}=${v}` }))
                 : []),
        ],
        risk_modifiers: [],
      });
    }
  }

  // ── 2. IOC-driven recommendations ─────────────────────────────
  for (const [iocValue, disp] of Object.entries(iocDispositions)) {
    if (!disp) continue;
    const rep = String(disp.reputation || disp.verdict || "").toLowerCase();
    if (rep.startsWith("mal") || rep.startsWith("high")) {
      push({
        kind: REC_KIND.RESPOND, label: `Block malicious IOC · ${iocValue}`,
        action: "block_ioc", priority: REC_PRIORITY.CRITICAL,
        approval_required: true, destructive: false,
        source: "ioc_intel",
        supporting: [
          { kind: "ioc",           ref: iocValue,     note: `Reputation: ${rep}` },
          ...(disp.malware_family
                 ? [{ kind: "malware_family", ref: disp.malware_family }]
                 : []),
          ...((disp.sources || []).length
                 ? [{ kind: "sources", ref: (disp.sources || []).join(", ") }]
                 : []),
        ],
        risk_modifiers: [],
      });
    } else if (rep === "unknown" || !rep) {
      push({
        kind: REC_KIND.ENRICH, label: `Enrich IOC via NivXRay · ${iocValue}`,
        action: "ioc_enrich", priority: REC_PRIORITY.MEDIUM,
        source: "ioc_intel",
        supporting: [{ kind: "ioc", ref: iocValue,
                              note: "Reputation unknown — enrichment required." }],
        risk_modifiers: [],
      });
    }
  }

  // ── 3. Base-recommender contributions ─────────────────────────
  // Consume authoritative recommendations from
  // /api/decode/mitigations/evidence_driven.  Never override or
  // downgrade — merge and de-dupe.
  const baseList =
      baseRecs?.recommendations
   || baseRecs?.mitigations
   || baseRecs?.data?.recommendations
   || [];
  for (const b of baseList) {
    push({
      kind:  _mapBaseKind(b.kind || b.category || b.mitigation_kind),
      label: b.label || b.title || b.name || b.mitigation || "Recommended action",
      action: b.action_id || b.id || b.action || "base_recommendation",
      priority: _mapBasePriority(b.priority || b.severity),
      approval_required: !!b.approval_required,
      destructive: !!b.destructive,
      source: "base_recommender/v2",
      supporting: [
        { kind: "engine",   ref: "evidence_driven_mitigations",
          note: "authoritative NivXRay recommender" },
        ...(b.evidence || []).slice(0, 3).map((e) => ({
          kind: "evidence", ref: e.ref || e.id || JSON.stringify(e).slice(0, 40),
        })),
      ],
      risk_modifiers: b.risk ? [{ kind: "risk", note: b.risk }] : [],
    });
  }

  // ── 4. Verdict-driven residual investigation ──────────────────
  const sev = String(incident?.severity || incident?.verdict || "").toLowerCase();
  if (sev.startsWith("crit") || sev.startsWith("high") || sev.startsWith("mal")) {
    push({
      kind: REC_KIND.COLLECT, label: "Collect endpoint evidence bundle",
      action: "collect_endpoint_evidence", priority: REC_PRIORITY.HIGH,
      approval_required: false, source: "verdict",
      supporting: [
        { kind: "verdict",   ref: sev.toUpperCase() },
        { kind: "confidence",ref: `${incident?.confidence ?? "?"}` },
      ],
      risk_modifiers: [],
    });
    push({
      kind: REC_KIND.HUNT, label: "Search related hosts for same behavior",
      action: "hunt_related_hosts", priority: REC_PRIORITY.MEDIUM,
      source: "verdict",
      supporting: [{ kind: "verdict", ref: sev.toUpperCase() }],
      risk_modifiers: [],
    });
  }

  // ── 5. Playbook state modifiers ────────────────────────────────
  // "Do not recommend an action that a successfully completed
  // playbook already performed."
  const completedActions = new Set();
  const inflightActions  = new Set();
  const partialPlaybooks = [];
  for (const p of applicablePlaybooks) {
    if (p.state === PB_STATE.ALREADY_EXECUTED) {
      for (const a of (p.executed_actions || [])) completedActions.add(a);
    }
    if (p.state === PB_STATE.WAITING_APPROVAL) {
      for (const a of (p.executed_actions || [])) inflightActions.add(a);
    }
    if (p.state === PB_STATE.PARTIAL) partialPlaybooks.push(p);
  }
  for (const r of previousResponses) {
    if (r.state === "SUCCEEDED") completedActions.add(r.action);
    if (r.state === "WAITING_APPROVAL" || r.state === "EXECUTING")
      inflightActions.add(r.action);
  }
  // Apply: annotate or suppress.
  const filtered = [];
  const suppressed = [];
  for (const rec of out) {
    if (completedActions.has(rec.action)) {
      // Move to a distinct "already_executed" list but keep visible.
      suppressed.push({
        ...rec, priority: REC_PRIORITY.INFO,
        priority_label: "INFO",
        state: "ALREADY_EXECUTED",
        supporting: [
          ...rec.supporting,
          { kind: "playbook", ref: "completed",
            note: "This action was already performed by a completed playbook." },
        ],
      });
      continue;
    }
    if (inflightActions.has(rec.action)) {
      filtered.push({
        ...rec,
        state: "WAITING_APPROVAL",
        supporting: [
          ...rec.supporting,
          { kind: "playbook", ref: "waiting_approval",
            note: "An identical action is already waiting for peer approval." },
        ],
      });
      continue;
    }
    filtered.push(rec);
  }

  // ── 6. Partial-playbook completion prompts ────────────────────
  for (const p of partialPlaybooks) {
    for (const a of (p.remaining_actions || [])) {
      filtered.push({
        id: `rec_partial_${filtered.length + 1}`,
        kind: REC_KIND.RESPOND,
        label: `Complete playbook step · ${a}`,
        action: a,
        priority: REC_PRIORITY.HIGH,
        priority_label: "HIGH",
        approval_required: true, source: `playbook:${p.playbook_id}`,
        supporting: [
          { kind: "playbook", ref: p.playbook_id, note: "PARTIALLY COMPLETED" },
          ...(p.executed_actions || []).map((ea) => ({
            kind: "executed", ref: ea, note: "✓" })),
        ],
        risk_modifiers: [],
      });
    }
  }

  // ── 7. Sort by priority (stable + deterministic) ──────────────
  filtered.sort((a, b) => (b.priority - a.priority) || a.label.localeCompare(b.label));
  suppressed.sort((a, b) => a.label.localeCompare(b.label));

  return { recommendations: filtered, already_executed: suppressed };
}


// Map arbitrary base "kind" strings to our canonical set.
function _mapBaseKind(k) {
  const s = String(k || "").toLowerCase();
  if (s.includes("invest"))  return REC_KIND.INVESTIGATE;
  if (s.includes("enrich"))  return REC_KIND.ENRICH;
  if (s.includes("collect")) return REC_KIND.COLLECT;
  if (s.includes("respond") || s.includes("block")
       || s.includes("isolate") || s.includes("contain"))
    return REC_KIND.RESPOND;
  if (s.includes("decode"))  return REC_KIND.DECODE;
  if (s.includes("hunt"))    return REC_KIND.HUNT;
  return REC_KIND.INVESTIGATE;
}

function _mapBasePriority(p) {
  const s = String(p || "").toLowerCase();
  if (s.includes("crit")) return REC_PRIORITY.CRITICAL;
  if (s.includes("high")) return REC_PRIORITY.HIGH;
  if (s.includes("med"))  return REC_PRIORITY.MEDIUM;
  if (s.includes("low"))  return REC_PRIORITY.LOW;
  return REC_PRIORITY.MEDIUM;
}


/**
 * Derive matched-rule context from an incident payload.
 * Consumes rule evidence embedded in incident.evidence[] +
 * RULE_TO_TECHNIQUE mapping.  Never fabricates a match.
 */
export function deriveMatchedRulesFromIncident(incident, ruleToTechnique = {}) {
  const rules = [];
  const seen = new Set();
  for (const ev of (incident?.evidence || [])) {
    const rid = ev.rule_id || ev.rule;
    if (!rid || seen.has(rid)) continue;
    seen.add(rid);
    rules.push({
      rule_id:   rid,
      match:     RULE_MATCH.MATCHED,
      evidence:  { ...(ev.fields || {}), ...(ev.matched_fields || {}),
                       command_line:  ev.command_line || ev.commandline,
                       parent_image:  ev.parent_image || ev.parent_process,
                       user:          ev.user, host: ev.host },
      technique: ev.technique_id || ruleToTechnique[rid] || null,
      weight:    ev.weight,
    });
  }
  return rules;
}


/**
 * Derive IOC dispositions from an incident + a batch lookup callback.
 * `lookup(value, kind) → { ok, data }`.  Never fabricates a reputation;
 * skips IOCs whose lookup fails.
 */
export async function deriveIocDispositions(incident, lookup) {
  const iocs = new Set();
  for (const ev of (incident?.evidence || [])) {
    for (const k of ["ip", "domain", "url", "hash", "sha256", "md5"]) {
      const v = ev[k];
      if (typeof v === "string" && v.trim().length > 0)
        iocs.add(JSON.stringify({ v: v.trim(), k }));
    }
  }
  const out = {};
  for (const j of iocs) {
    const { v, k } = JSON.parse(j);
    try {
      const r = await lookup(v, k);
      if (r?.ok && r.data) out[v] = r.data;
    } catch { /* skip — never fabricate */ }
  }
  return out;
}


/**
 * Given the Response Engine execution list for an incident, map to
 * playbook state entries.
 */
export function playbooksFromExecutions(executions = []) {
  const byPlaybook = new Map();
  for (const e of executions) {
    const pid = e.playbook_id || e.playbookId || "adhoc";
    const bucket = byPlaybook.get(pid)
        || { playbook_id: pid, executed_actions: [], remaining_actions: [],
                state: PB_STATE.APPLICABLE };
    if (e.state === "SUCCEEDED" || e.status === "SUCCEEDED")
      bucket.executed_actions.push(e.action);
    else if (e.state === "WAITING_APPROVAL")
      bucket.state = PB_STATE.WAITING_APPROVAL;
    else if (String(e.state || "").startsWith("FAILED"))
      bucket.state = PB_STATE.FAILED;
    byPlaybook.set(pid, bucket);
  }
  // Any playbook with executed_actions but no explicit state → ALREADY_EXECUTED
  for (const b of byPlaybook.values()) {
    if (b.state === PB_STATE.APPLICABLE && b.executed_actions.length > 0)
      b.state = PB_STATE.ALREADY_EXECUTED;
  }
  return Array.from(byPlaybook.values());
}
