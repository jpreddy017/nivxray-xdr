/**
 * EDR API client · Slice 2 · P0.
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
