/**
 * NivXForge EDR · onboarding + fleet operations API client.
 *
 * Read-only except for `mintEnrollmentToken`, which is the ONE write the
 * console performs: a bounded, tenant-bound, enrolment-purpose credential
 * whose plaintext exists only in that HTTP response.
 */
import api from "@/lib/api";

export async function getSensorPackages() {
  const { data } = await api.get("/edr/onboarding/packages");
  return data;
}

export async function getComputers(detectionWindowHours = 24) {
  const { data } = await api.get("/edr/onboarding/computers", {
    params: { detection_window_hours: detectionWindowHours },
  });
  return data;
}

export async function getComputer(endpointId, detectionWindowHours = 24) {
  const { data } = await api.get(
    `/edr/onboarding/computers/${encodeURIComponent(endpointId)}`,
    { params: { detection_window_hours: detectionWindowHours } });
  return data;
}

/** Observed endpoint command execution — NOT the response plane. */
export async function getEndpointCommands(endpointId, hours = 24,
                                          limit = 200) {
  const { data } = await api.get("/edr/endpoint-commands", {
    params: { endpoint_id: endpointId, hours, limit },
  });
  return data;
}

/**
 * Mint a one-time enrolment token.
 *
 * `ttl_seconds` is bounded server-side (60 … 86400). The plaintext is in
 * this response and nowhere else: it is never persisted by the console,
 * never written to localStorage and never embedded in the reusable
 * installer artifact.
 */
export async function mintEnrollmentToken({ label, ttlSeconds = 3600 }) {
  const { data } = await api.post("/edr/enrollment/tokens", {
    label: label || null, ttl_seconds: ttlSeconds,
  });
  return data;
}

/** Download an artifact through the authenticated API (no public URL). */
export async function downloadArtifact(packageId, name) {
  const res = await api.get(
    `/edr/onboarding/packages/${encodeURIComponent(packageId)}`
    + `/file/${encodeURIComponent(name)}`,
    { responseType: "blob" });
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
