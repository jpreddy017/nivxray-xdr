// DT-I1C client view model for Device Trajectory frames. Pure, deterministic, no I/O.
// Mirrors backend/edr_investigation (dt-i1.view.v1). A source is read from `frame.investigation.<key>`
// (the future view-model API attachment). Absent key => NOT_WIRED. Present but empty => EMPTY (never clean).
export const VIEW_VERSION = "dt-i1.view.v1";
export const NO_DETECTION = "No detection engine claimed this observation.";
export const ABSENCE = "Absence of detection is not evidence of clean.";
export const NOT_WIRED_TEXT = "No backend source is wired for this section yet.";
export const SECTION_KEYS = ["observation", "causal_context", "detection_attribution", "behavioral",
  "threat_intel", "ml", "supporting_evidence", "contradicting_evidence", "missing_evidence", "mitre",
  "retrospection", "response", "verification", "provenance", "pivots"];
export const SECTION_TITLES = {
  observation: "Observation", causal_context: "Causal context", detection_attribution: "Detection attribution",
  behavioral: "Behavioral intelligence", threat_intel: "Threat intelligence", ml: "ML / anomaly",
  supporting_evidence: "Supporting evidence", contradicting_evidence: "Contradicting evidence",
  missing_evidence: "Missing evidence", mitre: "MITRE ATT&CK", retrospection: "Retrospection",
  response: "Response requested", verification: "Verification", provenance: "Provenance", pivots: "Next pivots",
};
export const TI_STATES = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "NO_DATA", "NO_HIT", "UNAVAILABLE",
  "RATE_LIMITED", "ERROR", "STALE"];
export const TI_SCHEMA = "dt-i1e.ti.v1";
const TI_DEGRADED = ["UNAVAILABLE", "RATE_LIMITED", "ERROR", "STALE"];
export const PROOF = {
  REQUESTED: "NOTHING_HAS_HAPPENED_YET", AUTHORIZED: "AUTHORISED_NOT_YET_SENT", ACCEPTED: "ACCEPTED_NOT_EXECUTED",
  DISPATCHED: "CLAIMED_BY_ENDPOINT_NO_RESULT", EXECUTED: "SENSOR_CLAIM_ONLY_NOT_VERIFIED",
  VERIFIED: "VERIFIED_BY_POST_ACTION_EVIDENCE", FAILED: "FAILED", VERIFICATION_FAILED: "VERIFICATION_FAILED",
  CAPABILITY_UNAVAILABLE: "CAPABILITY_NOT_PRESENT", REFUSED: "REFUSED_BEFORE_DISPATCH",
};
const MACHINE = ["MALICIOUS", "SUSPICIOUS", "BENIGN", "UNKNOWN", "NOT_ASSESSED", "INSUFFICIENT_EVIDENCE"];
const TRIGGERS = ["INITIAL", "RULE_CHANGE", "INTEL_CHANGE", "MODEL_CHANGE", "REPUTATION_CHANGE", "ANALYST_CHANGE", "NEW_EVIDENCE"];

const ruleOf = (f) => (f && (f.rule_id || (f.provenance && f.provenance.rule_id))) || null;
const inv = (f) => (f && f.investigation) || {};
const has = (f, k) => Object.prototype.hasOwnProperty.call(inv(f), k);
const matches = (f) => (inv(f).behavior || []).filter((b) => b.outcome === "MATCH");

// Row/event classification. Red ("detected") requires an engine claim (rule on the frame or a behavioral MATCH).
// MITRE tags alone are UNATTRIBUTED (neutral). Nothing at all is UNKNOWN, never benign.
export function attributionOf(f) {
  if (ruleOf(f) || matches(f).length) return "detected";
  if ((f && f.mitre && f.mitre.length) > 0) return "unattributed";
  return "unknown";
}
export const ATTRIBUTION_LABEL = { detected: "DETECTED", unattributed: "MITRE · UNATTRIBUTED", unknown: "NOT ASSESSED" };

// A detection answers "did a defined condition match?"; an assessment answers "what does the evidence justify?".
export function machineAssessmentOf(f) {
  const h = historyOf(f || {});
  return h.length ? h[h.length - 1].assessment : "NOT_ASSESSED";
}
// Trajectory verdict key: "malicious" ONLY from an evidence-backed MALICIOUS machine assessment. A rule or
// behavioral MATCH is "detected" and never increments or renders as malicious.
export function trajectoryVerdict(f) {
  return machineAssessmentOf(f) === "MALICIOUS" ? "malicious" : attributionOf(f);
}
export const VERDICT_LABEL = { malicious: "ASSESSED MALICIOUS", detected: "DETECTED",
  unattributed: "MITRE · UNATTRIBUTED", unknown: "NOT ASSESSED" };
export const VERDICT_RANK = { unknown: 0, unattributed: 1, detected: 2, malicious: 3 };
export function chainCounts(stages) {
  return { stages: stages.length, detected: stages.filter((s) => s.detected).length,
           malicious: stages.filter((s) => s.malicious).length };
}
export const chainCountsText = (c) => `${c.stages} stages · ${c.detected} detected · ${c.malicious} assessed malicious`;

export function participatingFrameIds(f) {
  return [...new Set(matches(f).flatMap((b) => b.contributing_frame_ids || []))].sort();
}

export function mitreItems(f) {
  const claimed = new Set(matches(f).flatMap((b) => b.mitre || []));
  const ruleAll = !!ruleOf(f);
  return [...new Set((f && f.mitre) || [])].sort().map((t) => {
    const a = ruleAll || claimed.has(t);
    return { technique: t, attribution: a ? "ATTRIBUTED" : "UNATTRIBUTED", style: a ? "threat" : "neutral" };
  });
}

const sec = (key, items, statements = [], none = "EMPTY") =>
  ({ key, state: items.length ? "AVAILABLE" : none, items: items.slice(0, 50), statements });
const notWired = (key) => ({ key, state: "NOT_WIRED", items: [], statements: [NOT_WIRED_TEXT] });

function observables(f) {
  const out = [];
  const sha = f.sha256 || f.hash || (f.process && f.process.sha256);
  const ip = f.remote_ip || f.destination_ip;
  if (sha) out.push({ type: "sha256", value: String(sha) });
  if (ip) out.push({ type: "ip", value: String(ip) });
  return out;
}

function tiSection(f) {
  const obs = observables(f);
  if (!has(f, "ti")) return obs.length ? sec("threat_intel", obs.map((o) => ({ indicator: o.value, type: o.type,
    state: "UNKNOWN", provider: null, reason: "TI results are not served by the trajectory API" })),
    ["NO_DATA, NO_HIT and UNKNOWN are not BENIGN."]) : notWired("threat_intel");
  // Consumes dt-i1e.ti.v1 normalized results (legacy {indicator,type,state} rows still accepted).
  const rows = (inv(f).ti || []).map((r) => {
    let state = TI_STATES.includes(r.state) ? r.state : "UNKNOWN";
    if (["MALICIOUS", "SUSPICIOUS", "BENIGN"].includes(state) && !r.provider) state = "UNKNOWN";
    if (state === "BENIGN" && r.schema_version === TI_SCHEMA
        && (r.provenance || {}).basis !== "PROVIDER_ASSERTED_KNOWN_GOOD") state = "UNKNOWN";
    const row = { indicator: r.observable || r.indicator, type: r.ioc_type || r.type, provider: r.provider || null,
                  state, detail: r.failure_reason || r.detail || null };
    if (r.schema_version) Object.assign(row, { schema_version: r.schema_version, cache_state: r.cache_state,
      freshness: r.freshness, lookup_at: r.lookup_at, source_client: (r.provenance || {}).source_client });
    if (state === "STALE") row.stale_state = r.stale_state || "UNKNOWN";
    return row;
  });
  const out = rows.some((r) => TI_DEGRADED.includes(r.state));
  return sec("threat_intel", rows, ["NO_DATA, NO_HIT and UNKNOWN are not BENIGN."].concat(
    out ? ["A TI provider is unavailable, rate-limited, failing or stale; no reputation conclusion is drawn from it."] : []));
}

function historyOf(f) {
  const h = inv(f).history || [];
  const ok = h.every((e, i) => e.version === i + 1 && (i === 0 ? e.supersedes == null : e.supersedes === i)
    && TRIGGERS.includes(e.trigger) && MACHINE.includes(e.assessment));
  if (!ok) throw new Error("assessment history is not append-only");
  return h;
}

export function buildActivityView(f, causal = null) {
  if (!f) return null;
  const keys = [f.canonical_evidence_id, f.frame_iid, ...(f.evidence_ids || [])].filter(Boolean);
  const proc = f.process || {};
  const I = inv(f);
  const obs = Object.fromEntries(Object.entries({
    action: f.action, label: f.label, ts: f.ts, lane: f.lane,
    command_line: f.command_line || proc.command_line,
  }).filter(([, v]) => v));
  const parent = (f.parent && f.parent.iid) || null;
  const child = (f.entity && f.entity.iid) || proc.iid || null;
  const edge = parent && child && keys.length
    ? { type: "process->child", source: parent, target: child, state: "SUPPORTED_RELATIONSHIP",
        evidence_refs: keys.slice(0, 4), reason: "sensor-reported parent identity on this event" }
    : { type: "process->child", source: child || "unknown", target: null, state: "UNKNOWN",
        evidence_refs: [], reason: "parent linkage unavailable; no edge inferred" };
  const rule = ruleOf(f);
  const det = (rule ? [{ engine: "deterministic_rules", rule_id: rule, confidence: f.confidence ?? null,
                         evidence_refs: keys.slice(0, 4) }] : [])
    .concat(matches(f).map((b) => ({ engine: "edr_behavior", rule_id: b.rule_id, rule_version: b.rule_version,
                                     outcome: "MATCH", evidence_refs: b.evidence_refs || [] })));
  const behavior = has(f, "behavior")
    ? sec("behavioral", (I.behavior || []).map((b) => ({ rule_id: b.rule_id, rule_version: b.rule_version,
        outcome: b.outcome, explanation: b.explanation || null, contributing_frame_ids: b.contributing_frame_ids || [],
        reasons: b.reasons || [] })), (I.behavior || []).length ? [] : ["No behavioral sequence matched this event.", ABSENCE])
    : notWired("behavioral");
  const ml = has(f, "ml")
    ? sec("ml", (I.ml || []).map((m) => ({ model_id: m.model_id, model_version: m.model_version,
        lifecycle: m.lifecycle || "UNKNOWN", outcome: m.outcome, score: m.score ?? null, reasons: m.reasons || [] })),
        ["ML is a signal, never a verdict.", "TESTING models are not confirmed detections."])
    : notWired("ml");
  const ti = tiSection(f);
  const history = historyOf(f);
  const resp = has(f, "response") ? (I.response || []).map((c) => {
    const st = PROOF[c.state] ? c.state : "UNKNOWN_STATE";
    return { command_id: c.command_id, action: c.action, state: st, proof: PROOF[st] || "UNKNOWN_OUTCOME" };
  }) : null;
  const missing = [];
  if (["LEGACY_UNBRIDGED", "REFERENCED_RECORD_ABSENT"].includes(f.bridge_state))
    missing.push({ source: "evidence_bridge", detail: f.bridge_state });
  if (causal) causal.groups.unknown.forEach((e) => missing.push({ source: "causal", detail: e.reason }));
  else if (edge.state === "UNKNOWN") missing.push({ source: "causal", detail: edge.reason });
  (I.behavior || []).filter((b) => b.outcome === "INSUFFICIENT_EVIDENCE")
    .forEach((b) => missing.push({ source: "edr_behavior", detail: (b.reasons || []).join("; ") }));
  (I.ml || []).forEach((m) => (m.reasons || []).forEach((r) => missing.push({ source: "edr_ml", detail: r })));
  ti.items.filter((t) => ["UNKNOWN", "NO_DATA", "UNAVAILABLE", "RATE_LIMITED", "ERROR"].includes(t.state))
    .forEach((t) => missing.push({ source: "threat_intel", detail: `${t.type} ${t.state}${t.provider ? " · " + t.provider : ""}` }));
  (I.missing || []).forEach((m) => missing.push({ source: m.source || "expected", detail: m.detail }));
  const supporting = det.map((d) => ({ kind: "detection", ...d }))
    .concat(ml.items.filter((m) => m.outcome === "EMITTED").map((m) => ({ kind: "ml_signal", model_id: m.model_id,
      lifecycle: m.lifecycle, score: m.score })))
    .concat(ti.items.filter((t) => ["MALICIOUS", "SUSPICIOUS"].includes(t.state)).map((t) => ({ kind: "threat_intel", ...t })));
  const contradicting = ti.items.filter((t) => t.state === "BENIGN")
    .map((t) => ({ kind: "threat_intel_context", ...t, note: "context, not exoneration" }))
    .concat((I.contradicting || []).map((c) => ({ kind: "context", ...c, note: "context, not exoneration" })));
  const pivots = [
    ...(parent ? [{ pivot: "process_ancestry", target: parent }] : []),
    ...observables(f).map((o) => ({ pivot: o.type === "sha256" ? "file_trajectory" : "network_hunt", target: o.value })),
  ];
  const stmtResp = ["Accepted ≠ executed ≠ contained ≠ verified."];
  const sections = [
    { key: "observation", state: Object.keys(obs).length ? "AVAILABLE" : "UNKNOWN",
      items: Object.keys(obs).length ? [obs] : [], statements: [] },
    sec("causal_context", causal ? causal.edges : [edge], ["Temporal order alone is never shown as causality."]),
    sec("detection_attribution", det, det.length ? [] : [NO_DETECTION, ABSENCE]),
    behavior, ti, ml,
    sec("supporting_evidence", supporting),
    sec("contradicting_evidence", contradicting,
        contradicting.length ? [] : ["No contradicting evidence recorded; this is not proof of malice."]),
    sec("missing_evidence", missing),
    sec("mitre", mitreItems(f), ["Only engine-attributed techniques are styled as threats."]),
    has(f, "history") ? sec("retrospection", history.map((e) => ({ version: e.version, at: e.at, trigger: e.trigger,
      assessment: e.assessment, supersedes: e.supersedes ?? null, source: e.source || null, change: e.change || null,
      evidence_refs: e.evidence_refs || [] })), ["History is append-only; earlier versions are never rewritten."])
      : notWired("retrospection"),
    resp ? sec("response", resp, stmtResp) : notWired("response"),
    resp ? sec("verification", resp.map((r) => ({ command_id: r.command_id, verified: r.state === "VERIFIED",
      proof: r.proof })), stmtResp) : notWired("verification"),
    sec("provenance", [{ frame_iid: f.frame_iid || null, canonical_evidence_id: f.canonical_evidence_id || null,
                         bridge_state: f.bridge_state || "UNKNOWN", view_version: VIEW_VERSION,
                         data_origin: I.synthetic ? "SYNTHETIC_FIXTURE" : "TRAJECTORY_API" }]),
    sec("pivots", pivots),
  ];
  return { view_version: VIEW_VERSION, subject: f.frame_iid || "unknown",
           machine_assessment: history.length ? history[history.length - 1].assessment : "NOT_ASSESSED",
           analyst_disposition: I.analyst || null, causal, sections };
}
