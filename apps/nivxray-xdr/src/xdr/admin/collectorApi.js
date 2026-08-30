/**
 * XDR Collector API client · Phase B.5.
 *
 * Talks to the independently-deployed NivXRay XDR Collector service
 * (see /app/apps/nivxray-xdr-collector).  The base URL comes from
 * `import.meta.env.VITE_XDR_COLLECTOR_URL` — if unset, every call
 * surfaces the honest `COLLECTOR_RUNTIME_NOT_DEPLOYED` state instead
 * of silently failing.  Never fake connector data client-side.
 */
import axios from "axios";

const COLLECTOR_BASE = import.meta.env.VITE_XDR_COLLECTOR_URL || "";

const client = COLLECTOR_BASE
  ? axios.create({ baseURL: `${COLLECTOR_BASE.replace(/\/+$/, "")}/api/xdr`,
                     timeout: 8000 })
  : null;

function notDeployed() {
  const err = new Error("collector_runtime_not_deployed");
  err.code = "COLLECTOR_RUNTIME_NOT_DEPLOYED";
  err.note = "Set VITE_XDR_COLLECTOR_URL in the Vercel project settings "
              + "to point at the deployed NivXRay XDR Collector service.";
  throw err;
}

// ── Read-only ─────────────────────────────────────────────
export async function listCollectorConnectors() {
  if (!client) notDeployed();
  const { data } = await client.get("/connectors");
  return data;
}
export async function listCollectors() {
  if (!client) notDeployed();
  const { data } = await client.get("/collectors");
  return data;
}
export async function getTelemetryHealth() {
  if (!client) notDeployed();
  const { data } = await client.get("/telemetry-health");
  return data;
}
export async function listDataSources() {
  if (!client) notDeployed();
  const { data } = await client.get("/data-sources");
  return data;
}
export async function listSourceTypes() {
  if (!client) notDeployed();
  const { data } = await client.get("/source-types");
  return data;
}
export async function getOutboxHealth() {
  if (!client) notDeployed();
  const { data } = await client.get("/outbox/health");
  return data;
}
export async function ingestPreflight(tenantId = "default") {
  if (!client) notDeployed();
  const { data } = await client.post("/ingest-preflight", null,
                                          { headers: { "X-Tenant-Id": tenantId } });
  return data;
}

// ── CRUD + control ────────────────────────────────────────
export async function createConnector(body, tenantId = "default") {
  if (!client) notDeployed();
  const { data } = await client.post("/connectors", body,
                                          { headers: { "X-Tenant-Id": tenantId } });
  return data;
}
export async function updateConnector(id, patch) {
  if (!client) notDeployed();
  const { data } = await client.patch(`/connectors/${id}`, patch);
  return data;
}
export async function deleteConnector(id) {
  if (!client) notDeployed();
  const { data } = await client.delete(`/connectors/${id}`);
  return data;
}
export async function testConnector(id) {
  if (!client) notDeployed();
  const { data } = await client.post(`/connectors/${id}/test`);
  return data;
}
export async function startConnector(id) {
  if (!client) notDeployed();
  const { data } = await client.post(`/connectors/${id}/start`);
  return data;
}
export async function stopConnector(id) {
  if (!client) notDeployed();
  const { data } = await client.post(`/connectors/${id}/stop`);
  return data;
}

export const COLLECTOR_CONFIGURED = !!COLLECTOR_BASE;
export const COLLECTOR_BASE_URL   = COLLECTOR_BASE;
