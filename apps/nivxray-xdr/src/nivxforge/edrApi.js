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

export async function getEdrProcessTree(incidentId) {
  const { data } = await api.get("/edr/process-tree",
                                    { params: { incident_id: incidentId }});
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
