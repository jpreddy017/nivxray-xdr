/**
 * Canonical Incident API client — matches the /api/incidents router.
 * Uses the shared axios instance (auth headers + timeout policy).
 */
import api from "@/lib/api";

export async function listIncidents({
  limit = 100, lens = null, state = null, priority = null, severity = null,
  verdict = null, confidence = null, customer = null,
  detection_source = null, technique = null,
  sort = "updated_at", order = "desc",
} = {}) {
  const params = { limit, sort, order };
  if (lens) params.lens = lens;
  if (state) params.state = state;
  if (priority) params.priority = priority;
  if (severity) params.severity = severity;
  if (verdict) params.verdict = verdict;
  if (confidence) params.confidence = confidence;
  if (customer) params.customer = customer;
  if (detection_source) params.detection_source = detection_source;
  if (technique) params.technique = technique;
  const { data } = await api.get("/incidents", { params });
  return data;
}

// ── Bulk operations + Saved Views (Phase 2) ────────────────────────
export async function bulkAssign(incidentIds, assignee, reason = null) {
  const { data } = await api.post("/xdr/incidents/bulk/assign",
    { incident_ids: incidentIds, assignee, reason });
  return data;
}
export async function bulkState(incidentIds, targetState, note = null) {
  const { data } = await api.post("/xdr/incidents/bulk/state",
    { incident_ids: incidentIds, target_state: targetState, note });
  return data;
}
export async function listSavedViews() {
  const { data } = await api.get("/xdr/saved-views");
  return data;
}
export async function createSavedView(view) {
  const { data } = await api.post("/xdr/saved-views", view);
  return data;
}
export async function updateSavedView(id, view) {
  const { data } = await api.put(`/xdr/saved-views/${id}`, view);
  return data;
}
export async function deleteSavedView(id) {
  const { data } = await api.delete(`/xdr/saved-views/${id}`);
  return data;
}

export async function getDashboardTiles() {
  const { data } = await api.get("/xdr/dashboard/tiles");
  return data;
}

// ── MSS Dashboard projections ───────────────────────────────────────
export async function getMssKpis() {
  const { data } = await api.get("/xdr/mss/kpis");
  return data;
}
export async function getMssStateDistribution() {
  const { data } = await api.get("/xdr/mss/state-distribution");
  return data;
}
export async function getMssSocQueue(limit = 10) {
  const { data } = await api.get("/xdr/mss/soc-queue", { params: { limit } });
  return data;
}
export async function getMssAnalystWorkload() {
  const { data } = await api.get("/xdr/mss/analyst-workload");
  return data;
}
export async function getMssCustomerOperations() {
  const { data } = await api.get("/xdr/mss/customer-operations");
  return data;
}
export async function getMssAutoInvestigation() {
  const { data } = await api.get("/xdr/mss/auto-investigation");
  return data;
}
export async function getMssDetectionOverview() {
  const { data } = await api.get("/xdr/mss/detection-overview");
  return data;
}
export async function getMssRecentActivity(limit = 15) {
  const { data } = await api.get("/xdr/mss/recent-activity", { params: { limit } });
  return data;
}

export async function patchIncidentOperations(incidentId, fields) {
  const { data } = await api.patch(
    `/incidents/${encodeURIComponent(incidentId)}/operations`,
    fields,
  );
  return data;
}

export async function getIncident(incidentId) {
  const { data } = await api.get(`/incidents/${encodeURIComponent(incidentId)}`);
  return data;
}

export async function getIncidentSummary(incidentId) {
  const { data } = await api.get(
    `/incidents/${encodeURIComponent(incidentId)}/summary`,
  );
  return data;
}

export async function transitionIncidentState(incidentId, targetState, note) {
  const { data } = await api.patch(
    `/incidents/${encodeURIComponent(incidentId)}/state`,
    { target_state: targetState, note: note || null },
  );
  return data;
}

export async function setIncidentAssignee(incidentId, assignee) {
  const { data } = await api.patch(
    `/incidents/${encodeURIComponent(incidentId)}/assignee`,
    { assignee: assignee || null },
  );
  return data;
}

// Mirrors backend/routers/incidents.py LIFECYCLE_TRANSITIONS.
export const LIFECYCLE_STATES = [
  { key: "new",         label: "New" },
  { key: "in_progress", label: "In Progress" },
  { key: "on_hold",     label: "On Hold" },
  { key: "resolved",    label: "Resolved" },
  { key: "closed",      label: "Closed" },
];

export const LIFECYCLE_TRANSITIONS = {
  new:         ["in_progress", "on_hold", "closed"],
  in_progress: ["on_hold", "resolved", "closed"],
  on_hold:     ["in_progress", "closed"],
  resolved:    ["in_progress", "closed"],
  closed:      [],
};
