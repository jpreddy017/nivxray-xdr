// Read-only client for /api/e3/trajectory/* (E3 contract preview). POST /approvals only records a request.
const BASE = `${process.env.REACT_APP_BACKEND_URL || ""}/api/e3/trajectory`;

async function call(path, { params, body, signal } = {}) {
  const qs = params ? `?${new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ""))}` : "";
  const res = await fetch(`${BASE}${path}${qs}`, body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body), signal }
    : { signal });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.detail || `HTTP ${res.status}`), { status: res.status });
  return data;
}

export const e3 = {
  scenarios: () => call("/scenarios"),
  dev: (s, part, extra, signal) => call(`/devices/${encodeURIComponent(s.device_id)}/${part}`,
    { params: { scenario: s.scenario_id, tenant: s.tenant_id, ...extra }, signal }),
  fileStatus: (s, sha) => call(`/files/${sha}/status`, { params: { scenario: s.scenario_id, tenant: s.tenant_id } }),
  statusEvents: (s) => call("/status-events", { params: { scenario: s.scenario_id, tenant: s.tenant_id } }),
  approvals: (s) => call("/approvals", { params: { tenant: s.tenant_id } }),
  requestApproval: (body) => call("/approvals", { body }),
  pivot: (kind, value) => call("/pivots", { params: { kind, value } }),
};
