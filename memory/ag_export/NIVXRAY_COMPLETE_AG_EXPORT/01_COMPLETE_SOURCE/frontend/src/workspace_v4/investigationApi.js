/**
 * Thin client for the PR-2 L1 Investigation APIs (Blueprint §10).
 *
 * Deliberately minimal — every call maps 1:1 to an endpoint in
 * `L1_INVESTIGATION_API_PLAYBOOK.md`. No caching, no derived state.
 * Higher-level state management lands with lens content in PR-4+.
 */
import api from "@/lib/api";

const R = (path) => `/investigation${path}`;

export async function createCase({ bundle, mode }) {
  const { data } = await api.post(R(""), { bundle, mode });
  return data;
}

export async function listCases() {
  const { data } = await api.get(R(""));
  return data.cases || [];
}

export async function getWorkspaceBundle(caseId) {
  const { data } = await api.get(R(`/${caseId}`));
  return data;
}

export async function deleteCase(caseId) {
  await api.delete(R(`/${caseId}`));
}

export async function getWorkspaceState(caseId) {
  const { data } = await api.get(R(`/${caseId}/workspace`));
  return data;
}

export async function putWorkspaceState(caseId, patch) {
  const { data } = await api.put(R(`/${caseId}/workspace`), patch);
  return data;
}

export async function getState(caseId) {
  const { data } = await api.get(R(`/${caseId}/state`));
  return data;
}

export async function transitionState(caseId, target, reason = "") {
  const { data } = await api.post(R(`/${caseId}/state/transition`), { target, reason });
  return data;
}

const services = {
  summary:      "summary",
  story:        "story",
  iocs:         "iocs",
  capabilities: "capabilities",
  threat:       "threat",
  detections:   "detections",
  hunting:      "hunting",
};

export async function getService(caseId, name) {
  const path = services[name];
  if (!path) throw new Error(`unknown service: ${name}`);
  const { data } = await api.get(R(`/${caseId}/${path}`));
  return data;
}

export default {
  createCase,
  listCases,
  getWorkspaceBundle,
  deleteCase,
  getWorkspaceState,
  putWorkspaceState,
  getState,
  transitionState,
  getService,
};
