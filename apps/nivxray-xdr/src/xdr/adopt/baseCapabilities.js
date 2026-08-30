/**
 * Base-capability consumers.
 *
 * Every helper here CONSUMES an existing NivXRay Tool API rather than
 * reimplementing the underlying engine.  On any failure we return an
 * "adapter_disconnected" envelope so the UI can render an honest
 * ``AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED`` banner
 * instead of faking data.
 *
 * Adopt-before-invent — see docs/NIVXRAY_XDR_TECHNOLOGY_ADOPTION_MATRIX.md.
 */
import api from "@/lib/api";

async function _call(method, url, opts = {}) {
  try {
    const r = await api.request({ method, url, ...opts });
    return { ok: true, data: r.data };
  } catch (e) {
    return {
      ok: false,
      status: e?.response?.status,
      error:  e?.response?.data?.detail || e?.response?.data?.error || e?.message,
      not_wired: e?.response?.status === 404 || e?.code === "ERR_NETWORK",
    };
  }
}

// ── Verdict Stage-2 ─────────────────────────────────────────────
export const VerdictConsumer = {
  /**
   * `POST /api/verdict/stage2` — authoritative deterministic verdict.
   * XDR NEVER re-implements this; it only surfaces it.  Body shape
   * mirrors the base contract: at minimum ``{ incident_id }``.
   */
  fetch: (body) => _call("POST", "/api/verdict/stage2", { data: body }),
};

// ── IOC Intelligence ────────────────────────────────────────────
export const IocConsumer = {
  /**
   * `GET /api/ioc/lookup` — reputation / relationships / sightings.
   * Never re-implements TI logic.  Query params match the base
   * endpoint: ``{ value, kind }``.
   */
  lookup: ({ value, kind }) => _call("GET", "/api/ioc/lookup",
                                                   { params: { value, kind } }),
};

// ── Decode chain (`/api/analyze`) ───────────────────────────────
export const AnalyzeConsumer = {
  /**
   * `POST /api/analyze` — deterministic multi-stage decoder chain +
   * command-line analyzer.  Used by the Sigma test/replay screen so
   * an encoded PowerShell command is decoded by the AUTHORITATIVE
   * NivXRay decoder, not a copy-pasted ad-hoc one.
   */
  analyzeCommand: (command_line, opts = {}) =>
    _call("POST", "/api/analyze",
             { data: { input: command_line, kind: "commandline", ...opts } }),
};

// ── Investigation report ────────────────────────────────────────
export const ReportConsumer = {
  /**
   * `GET /api/incidents/{id}/summary` — authoritative investigation
   * summary written by NivXRay's report writer.  XDR surfaces this
   * verbatim; there is no second XDR-side report engine.
   */
  summary: (incidentId) =>
    _call("GET", `/api/incidents/${encodeURIComponent(incidentId)}/summary`),
};

// ── Correlation engine ──────────────────────────────────────────
export const CorrelationConsumer = {
  /** `GET /api/correlations/{cid}/graph` — authoritative causal chain. */
  graph:  (cid) => _call("GET", `/api/correlations/${encodeURIComponent(cid)}/graph`),
  chain:  (cid) => _call("GET", `/api/correlations/${encodeURIComponent(cid)}/chain`),
  /** `GET /api/correlations?incident_id=...` — list correlations for an incident. */
  forIncident: (incidentId) =>
    _call("GET", "/api/correlations", { params: { incident_id: incidentId } }),
};

// ── Process tree (`/api/edr/process-tree`) ──────────────────────
export const ProcessTreeConsumer = {
  fetch: (opts = {}) => _call("GET", "/api/edr/process-tree", { params: opts }),
};

// ── Behavior registry ───────────────────────────────────────────
export const BehaviorRegistryConsumer = {
  forRule: (ruleId) => _call("GET", "/api/behavior-registry", { params: { rule_id: ruleId } }),
  forProcess: (pid) => _call("GET", "/api/behavior-registry", { params: { pid } }),
};

// ── DIE · Deterministic Investigation Engine ────────────────────
// `/api/die/*` (see /app/backend/routers/die.py).  XDR NEVER
// implements a second decoder — it CONSUMES DIE's authoritative
// stages and renders them with full provenance.
export const DieConsumer = {
  /** POST /api/die/analyze — full DIE analyze + narrate. */
  analyze:   (body) => _call("POST", "/api/die/analyze",      { data: body }),
  /** POST /api/die/understand — input-understanding stage. */
  understand:(body) => _call("POST", "/api/die/understand",   { data: body }),
  /** POST /api/die/chain — deterministic recursive decode chain. */
  chain:     (body) => _call("POST", "/api/die/chain",        { data: body }),
  /** POST /api/die/iocs — IOC extraction from a payload. */
  iocs:      (body) => _call("POST", "/api/die/iocs",         { data: body }),
  /** POST /api/die/intent — intent extraction. */
  intent:    (body) => _call("POST", "/api/die/intent",       { data: body }),
  /** POST /api/die/narrate — analyst narrative. */
  narrate:   (body) => _call("POST", "/api/die/narrate",      { data: body }),
  /** GET  /api/die/lolbas/{binary} — LOLBAS lookup. */
  lolbas:    (binary) => _call("GET", `/api/die/lolbas/${encodeURIComponent(binary)}`),
  /** GET  /api/die/case/{case_id} — bundled DIE results for a case. */
  forCase:   (caseId) => _call("GET", `/api/die/case/${encodeURIComponent(caseId)}`),
  /** POST /api/die/powershell/ast — powershell AST. */
  powershellAst: (input) => _call("POST", "/api/die/powershell/ast", { data: { input } }),
};

// ── IEDDE · Iterative Evidence-Driven Decoding Engine ───────────
// `/api/iedde/analyze` (see /app/backend/routers/iedde.py).
// Deterministic Stage-1/2/3 loop.  Response body carries the
// authoritative stage trace analysts have asked for.
export const IeddeConsumer = {
  /** POST /api/iedde/analyze — { input } → stage-by-stage trace. */
  analyze: (input) => _call("POST", "/api/iedde/analyze", { data: { input } }),
};

// ── IUE · Investigation Understanding Engine ────────────────────
// `/api/iue/lane-{a,b,c}/*` + `/api/iue/timeline/fuse`.
// XDR NEVER re-implements the unified timeline — it fuses via
// `/api/iue/timeline/fuse` and consumes the lanes for per-artefact
// understanding.
export const IueConsumer = {
  laneAStatus:  ()      => _call("GET",  "/api/iue/lane-a/status"),
  laneAAnalyze: (body)  => _call("POST", "/api/iue/lane-a/analyze",  { data: body }),
  laneBAnalyze: (body)  => _call("POST", "/api/iue/lane-b/analyze",  { data: body }),
  laneCStatus:  ()      => _call("GET",  "/api/iue/lane-c/status"),
  laneCAnalyze: (body)  => _call("POST", "/api/iue/lane-c/analyze",  { data: body }),
  laneCAnalyzeB64: (b64)=> _call("POST", "/api/iue/lane-c/analyze-b64", { data: { b64 } }),
  /** POST /api/iue/timeline/fuse — the authoritative unified timeline. */
  timelineFuse: (body)  => _call("POST", "/api/iue/timeline/fuse",   { data: body }),
};

// ── UAIE · Universal Artefact Investigation Engine ──────────────
// Capability catalog + planner.  `/api/uaie/catalog` returns the
// relationship-rich catalog; XDR uses it to explain "why did this
// capability fire?" without re-implementing the planner.
export const UaieConsumer = {
  /** GET /api/uaie/catalog — relationship-rich capability catalog. */
  catalog:  ()     => _call("GET", "/api/uaie/catalog"),
  /** GET /api/uaie/catalog.dot — Graphviz dot source. */
  catalogDot: ()   => _call("GET", "/api/uaie/catalog.dot",
                              { responseType: "text" }),
  /** POST /api/uaie/dry-run — planner dry-run trace for an artefact. */
  dryRun:   (body) => _call("POST", "/api/uaie/dry-run", { data: body }),
  /** POST /api/uaie/compare — compare two planner outputs. */
  compare:  (body) => _call("POST", "/api/uaie/compare", { data: body }),
};

// ── UIL · Unified Input Layer ───────────────────────────────────
// `/api/uil/*` (see /app/backend/routers/uil.py).  Classifier +
// mixed-input splitter + recursive investigator.
export const UilConsumer = {
  classify:    (input) => _call("POST", "/api/uil/classify",    { data: { input } }),
  split:       (input) => _call("POST", "/api/uil/split",       { data: { input } }),
  investigate: (input) => _call("POST", "/api/uil/investigate", { data: { input } }),
};

// ── ICE · Investigation Correlation Engine (via /api/correlations) ─
// ICE is the engine behind /api/correlations/*.  In addition to the
// generic CorrelationConsumer above, we expose analyst-facing
// projections that ICE produces: cluster/phase/kill-chain.
export const IceConsumer = {
  forCase:     (caseId) => _call("GET",  `/api/correlations/cem/${encodeURIComponent(caseId)}`),
  fingerprint: (caseId) => _call("GET",  `/api/correlations/fingerprint/${encodeURIComponent(caseId)}`),
  provenance:  (caseId) => _call("GET",  `/api/correlations/provenance/${encodeURIComponent(caseId)}`),
  suggestions: (cid)    => _call("GET",  `/api/correlations/${encodeURIComponent(cid)}/suggestions`),
};
