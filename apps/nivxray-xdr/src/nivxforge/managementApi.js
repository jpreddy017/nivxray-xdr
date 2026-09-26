/**
 * NivXForge EDR · management plane API client.
 *
 * Policies (Gate 5), Exclusions (Gate 7), Events (Gate 11) and the
 * connector release catalog. Every state token, basis sentence and
 * lifecycle label rendered by these surfaces comes from the server —
 * the console never invents one.
 */
import api from "@/lib/api";

// ── Gate 11 · events ───────────────────────────────────────────────
export async function listEvents(params = {}) {
  const { data } = await api.get("/edr/events", { params });
  return data;
}

export async function getEventFacets(hours = 24) {
  const { data } = await api.get("/edr/events/facets", { params: { hours } });
  return data;
}

export async function getEvent(rawId) {
  const { data } = await api.get(`/edr/events/${encodeURIComponent(rawId)}`);
  return data;
}

// ── Gate 5 · policy authority ──────────────────────────────────────
export async function listPolicies() {
  const { data } = await api.get("/edr/policies");
  return data;
}

export async function getPolicy(policyId) {
  const { data } = await api.get(`/edr/policies/${encodeURIComponent(policyId)}`);
  return data;
}

export async function createPolicy(body) {
  const { data } = await api.post("/edr/policies", body);
  return data;
}

export async function createPolicyVersion(policyId, body) {
  const { data } = await api.post(
    `/edr/policies/${encodeURIComponent(policyId)}/versions`, body);
  return data;
}

export async function assignPolicy(policyId, body) {
  const { data } = await api.post(
    `/edr/policies/${encodeURIComponent(policyId)}/assign`, body);
  return data;
}

export async function getPolicyDeployment(policyId) {
  const { data } = await api.get("/edr/policies/deployment",
                                 { params: policyId ? { policy_id: policyId } : {} });
  return data;
}

export async function getPolicyAudit(limit = 200) {
  const { data } = await api.get("/edr/policies/audit", { params: { limit } });
  return data;
}

export async function listGroups() {
  const { data } = await api.get("/edr/groups");
  return data;
}

export async function createGroup(body) {
  const { data } = await api.post("/edr/groups", body);
  return data;
}

// ── Gate 7 · exclusions ────────────────────────────────────────────
export async function getExclusionTaxonomy() {
  const { data } = await api.get("/edr/exclusions/taxonomy");
  return data;
}

export async function listExclusionSets() {
  const { data } = await api.get("/edr/exclusions/sets");
  return data;
}

export async function createExclusionSet(body) {
  const { data } = await api.post("/edr/exclusions/sets", body);
  return data;
}

export async function listExclusions(setId) {
  const { data } = await api.get("/edr/exclusions",
                                 { params: setId ? { set_id: setId } : {} });
  return data;
}

export async function createExclusion(body) {
  const { data } = await api.post("/edr/exclusions", body);
  return data;
}

export async function decideExclusion(exclusionId, body) {
  const { data } = await api.post(
    `/edr/exclusions/${encodeURIComponent(exclusionId)}/approval`, body);
  return data;
}

export async function revokeExclusion(exclusionId, reason) {
  const { data } = await api.post(
    `/edr/exclusions/${encodeURIComponent(exclusionId)}/revoke`, { reason });
  return data;
}

export async function getEnforcementProof(sample = 300) {
  const { data } = await api.get("/edr/exclusions/enforcement-proof",
                                 { params: { sample } });
  return data;
}

// ── connector releases + deployment context ────────────────────────
export async function listConnectorReleases() {
  const { data } = await api.get("/edr/connector/releases");
  return data;
}

export async function createDeployment(body) {
  const { data } = await api.post("/edr/connector/deployments", body);
  return data;
}

export async function listDeployments() {
  const { data } = await api.get("/edr/connector/deployments");
  return data;
}

/** Download a RELEASED artifact. The same bytes for every device. */
export async function downloadReleaseArtifact(releaseId, name) {
  const res = await api.get(
    `/edr/connector/releases/${encodeURIComponent(releaseId)}`
    + `/artifact/${encodeURIComponent(name)}`, { responseType: "blob" });
  const url = window.URL.createObjectURL(new Blob([res.data]));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(url);
  return res.headers?.["x-nivxforge-sha256"] || null;
}
