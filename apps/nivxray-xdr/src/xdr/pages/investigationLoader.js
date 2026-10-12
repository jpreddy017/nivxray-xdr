import { securitySnapshot, subscribeSecurity } from "@/lib/securityState";

export function investigationFailure(error) {
  if (error?.code === "ERR_CANCELED" || error?.name === "AbortError") return "unavailable";
  const status = error?.response?.status;
  if (status === 401 || status === 403) return "denied";
  if ([404, 405, 501].includes(status)) return "unavailable";
  return "error";
}

// Compatibility is explicit: an absent v2 route returns FastAPI 404 / detail=Not Found. No other
// status, transport error, cancellation or malformed payload authorizes fallback.
export async function readEngineInvestigation(api, caseId, profile, signal) {
  const id = encodeURIComponent(caseId);
  let data;
  try {
    data = (await api.get(`/v2/cases/${id}/investigation?limit=500&profile=${encodeURIComponent(profile)}`, { signal })).data;
  } catch (error) {
    if (signal.aborted || error?.code === "ERR_CANCELED" || error?.response?.status !== 404 || error?.response?.data?.detail !== "Not Found") throw error;
    const incident = (await api.get(`/incidents/${id}`, { signal })).data;
    if (!incident || String(incident.id || incident.case_id || "") !== String(caseId)) throw new Error("Incident identity unavailable or mismatched");
    data = incidentInvestigation(incident, caseId);
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new Error("Invalid investigation response");
  if (data.case_id != null && String(data.case_id) !== String(caseId)) throw new Error("Investigation identity mismatch");
  return data;
}

export function incidentInvestigation(inc, caseId) {
  return {
    case_id: inc.id || caseId,
    header: {
      verdict_band: inc.verdict_stage2?.label || inc.verdict || null,
      device_score: inc.device_score ?? inc.verdict_stage2?.risk_score ?? null,
      incident_score: inc.incident_score ?? inc.verdict_stage2?.risk_score ?? null,
      confidence: inc.confidence ?? inc.verdict_stage2?.confidence ?? null,
      event_count: inc.evidence_count ?? (Array.isArray(inc.evidence) ? inc.evidence.length : null),
      process_count: inc.process_count ?? null,
      chain_count: inc.chain_count ?? null,
    },
    ikg: {
      stats: {
        nodes: inc.ikg_nodes ?? (Array.isArray(inc.nodes) ? inc.nodes.length : null),
        edges: inc.ikg_edges ?? (Array.isArray(inc.edges) ? inc.edges.length : null),
      },
      nodes: inc.nodes ?? null,
      edges: inc.edges ?? null,
    },
    story: {
      narrative: inc.attack_story?.narrative || inc.description || "No causal narrative available for this incident.",
      steps: inc.attack_story?.steps || [],
    },
    explainability: {
      positive: {
        reasons: inc.explainability?.positive?.reasons ?? null,
      },
      negative_patterns: inc.explainability?.negative_patterns || [],
    },
    engine_version: inc.engine_version || null,
    patient_zero: inc.patient_zero || inc.host || null,
    root_process: inc.root_process || null,
    target_identity: inc.target_identity || inc.user || null,
    c2_endpoints: inc.c2_endpoints || null,
    containment: inc.containment || inc.recommendations || null,
    security_state: inc.security_state || null,
    mitre_techniques: inc.mitre_techniques || inc.techniques || [],
  };
}

export function validateContext(value, caseId, tenantId) {
  if (value?.case_id != null && String(value.case_id) !== String(caseId)) throw new Error("Investigation identity mismatch");
  if (value?.tenant_id != null && String(value.tenant_id) !== String(tenantId)) throw new Error("Customer identity mismatch");
}

export function startInvestigationLoad({ api, caseId, profile, tenantId, onPrimary, onSecondary, onInvalidate }) {
  const controller = new AbortController();
  const epoch = securitySnapshot().epoch;
  let active = true;
  const current = () => active && !controller.signal.aborted && securitySnapshot().epoch === epoch;
  const stop = () => { active = false; controller.abort(); };
  const unsubscribe = subscribeSecurity(() => { stop(); onInvalidate(); });
  const run = async () => {
    try {
      if (!caseId || !tenantId) { if (current()) onPrimary("unavailable", null); return; }
      const data = await readEngineInvestigation(api, caseId, profile, controller.signal);
      if (!current()) return;
      validateContext(data, caseId, tenantId);
      if (Object.keys(data).length === 0) { onPrimary("empty", null); return; }
      onPrimary("ready", data);
      const id = encodeURIComponent(caseId);
      const endpoints = {
        trajectory: `/v2/cases/${id}/trajectory/device?limit=500`,
        process: `/edr/process-tree?incident_id=${id}`,
        artifacts: `/v2/cases/${id}/artifacts?limit=500`,
        security: `/v2/security-state/${id}?tenant_id=${encodeURIComponent(tenantId)}`,
      };
      await Promise.all(Object.entries(endpoints).map(async ([key, url]) => {
        if (!current()) return;
        onSecondary(key, "loading", null);
        try {
          const response = await api.get(url, { signal: controller.signal });
          if (!current()) return;
          const value = response.data;
          validateContext(value, caseId, tenantId);
          const items = key === "trajectory" ? value?.frames : key === "process" ? value?.nodes : key === "artifacts" ? value?.artifacts : null;
          const state = key === "security"
            ? (value?.state || value?.attack_state || value?.current_state || value?.states?.[0]?.state || value?.states?.[0]?.attack_state || value?.states?.[0]?.current_state ? "ready" : Array.isArray(value?.states) && value.states.length === 0 ? "empty" : "unavailable")
            : Array.isArray(items) ? (items.length ? "ready" : "empty") : "unavailable";
          onSecondary(key, state, state === "unavailable" ? null : value);
        } catch (error) {
          if (current()) onSecondary(key, investigationFailure(error), null);
        }
      }));
    } catch (error) {
      if (current()) onPrimary(investigationFailure(error), null);
    }
  };
  const done = run();
  return { done, cancel: () => { stop(); unsubscribe(); } };
}
