/**
 * Canonical Incident API client — matches the /api/incidents router.
 * Uses the shared axios instance (auth headers + timeout policy).
 */
import api from "@/lib/api";

export async function listIncidents({ limit = 100 } = {}) {
  const { data } = await api.get("/incidents", { params: { limit } });
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
