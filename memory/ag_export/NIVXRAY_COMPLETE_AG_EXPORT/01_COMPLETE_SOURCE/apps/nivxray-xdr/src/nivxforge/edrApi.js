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
  const { data } = await api.get("/edr/device-trajectory",
                                    { params: { device, hours }});
  return data;
}
