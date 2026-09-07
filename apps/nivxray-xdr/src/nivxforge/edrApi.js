/**
 * EDR API client · Slice 2 + Slice 6 · P0.
 * Fetches READ-ONLY projections from /api/edr/*.  Never mutates.
 */
import api from "@/lib/api";

export async function listEdrDetections(incidentId) {
  const { data } = await api.get("/edr/detections",
                                    { params: { incident_id: incidentId }});
  return data;
}

/**
 * P0-F · endpoint-scoped detections. These are the AUTHORITATIVE records
 * written by the XDR detection fabric onto the immutable raw endpoint
 * event — not a second detection store, and not case-derived.
 */
export async function listEndpointDetections(endpointId, hours = 24) {
  const { data } = await api.get("/edr/endpoint-detections",
                                    { params: { endpoint_id: endpointId,
                                                hours }});
  return data;
}

export async function getEdrProcessTree(incidentId) {
  const { data } = await api.get("/edr/process-tree",
                                    { params: { incident_id: incidentId }});
  return data;
}

/**
 * P0-F.4 · endpoint-keyed ancestry from REAL sensor evidence. Links are
 * canonical process identities, never pid alone.
 */
export async function getEndpointProcessTree(endpointId, hours = 24) {
  const { data } = await api.get("/edr/process-tree",
                                    { params: { endpoint_id: endpointId,
                                                hours }});
  return data;
}

// ── Slice 6 ────────────────────────────────────────────────────────
export async function listEndpoints() {
  const { data } = await api.get("/edr/endpoints");
  return data;
}

export async function getDeviceTrajectory(device, hours = 24) {
  const params = hours === 0
    ? { device, all_time: true }
    : { device, hours };
  const { data } = await api.get("/edr/device-trajectory", { params });
  return data;
}

/** P1.8 · Fleet (multi-endpoint) artifact trajectory. */
export async function getFileTrajectory(key, keyType = "name") {
  const { data } = await api.get("/edr/file-trajectory",
                                 { params: { key, key_type: keyType } });
  return data;
}

export async function getFleetSpreadIndex() {
  const { data } = await api.get("/edr/fleet-spread-index");
  return data;
}

/**
 * P0-W.F-2 · the AUTHORITATIVE capability-truth registry.
 *
 * `GET /api/edr/wave0/capabilities` is the single place that grades every
 * EDR capability across all three planes.  The console must read this
 * instead of hardcoding availability: no capability may be presented as
 * unavailable when the registry grades it implemented, and none may be
 * presented as operational because a route or component exists.
 */
export async function getEdrCapabilities() {
  const { data } = await api.get("/edr/wave0/capabilities");
  return data;
}

/**
 * P0-2A · EDR Response surface data.
 *
 * Two authorities, never merged into one invented state:
 *  · `/edr/response/actions`  — NivXForge EDR owns endpoint execution
 *    AND verification. Its `state` + `proof` are the truth about what
 *    happened on the endpoint.
 *  · `/xdr/respond/*`         — the XDR orchestration plane owns
 *    request, approval and dispatch, and reports capability truth
 *    (`dispatch_mode`) per action.
 */
export async function listEndpointCommands(params = {}) {
  const { data } = await api.get("/edr/response/actions", { params });
  return data;
}

export async function getIsolationPolicy() {
  const { data } = await api.get("/edr/response/isolation-policy");
  return data;
}

export async function getResponseCatalogue() {
  const { data } = await api.get("/xdr/respond/actions");
  return data;
}

export async function getResponseEngineHealth() {
  const { data } = await api.get("/xdr/respond/health");
  return data;
}

export async function getPendingApprovals() {
  const { data } = await api.get("/xdr/respond/pending-approvals");
  return data;
}

/** Evidence-gated prose for one persisted observation. */
export async function getObservationNarrative(device, eventIid) {
  const { data } = await api.get("/edr/observation-narrative",
                                 { params: { device, event_iid: eventIid }});
  return data;
}

/**
 * Static analysis bridge · VERIFIED CONTRACT.
 *
 * `GET /api/v2/decoded-artifacts/{sha256}` (backend/routers/decoded_artifacts.py)
 * is the only hash-keyed static-analysis surface that exists.  It is
 * read-only: it returns the persisted AnalystReport for a hash the
 * static pipeline has already processed, and 404 when it has not.
 * There is NO submit-by-hash route, because analysing a file requires
 * the file bytes, which endpoint telemetry does not carry.
 */
export async function getDecodedArtifact(sha256) {
  // 404 ("no record for this digest") is a legitimate evidence answer, not
  // a transport failure, so it is not raised as an exception.
  const res = await api.get(
    `/v2/decoded-artifacts/${encodeURIComponent(sha256)}`,
    { validateStatus: (s) => s === 200 || s === 404 });
  return { status: res.status, data: res.data };
}

export async function getDecodedArtifactStats() {
  const { data } = await api.get("/v2/decoded-artifacts/stats/summary");
  return data;
}

/**
 * P0-F.13.3 · EDR entry context.
 *
 * Answers two different questions the UI must never conflate:
 * WHO owns the data (tenant/customer) and WHY the analyst is here
 * (investigation context). The server validates the incident against
 * the principal's tenant scope — the browser only names it.
 */
export async function getEdrEntryContext(endpointId, incidentId) {
  const params = {};
  if (endpointId) params.endpoint_id = endpointId;
  if (incidentId) params.incident_id = incidentId;
  const { data } = await api.get("/edr/context", { params });
  return data;
}

/** Principal + authorised customers, for the shell's customer pill. */
export async function getSessionContext() {
  const { data } = await api.get("/xdr/rbac/session-context");
  return data?.data || null;
}
