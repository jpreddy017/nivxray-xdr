/**
 * XDR Collector API client · Round 24.95 (Collector Landing).
 *
 * Priority for the collector base URL:
 *   1. `VITE_XDR_COLLECTOR_URL` (explicit override for a separately
 *      deployed standalone collector — e.g. an on-prem syslog
 *      forwarder).  Path suffix `/api/xdr` (legacy standalone shape).
 *   2. `REACT_APP_BACKEND_URL` (default — the main NivXRay backend
 *      hosts the HTTP collector under `/api/xdr/collector`).
 *
 * Never fabricates data.  If neither URL is set the module surfaces
 * the honest `COLLECTOR_RUNTIME_NOT_DEPLOYED` state.
 */
import axios from "axios";

const CUSTOM_URL   = import.meta.env.VITE_XDR_COLLECTOR_URL || "";
// vite.config.js exposes REACT_APP_BACKEND_URL via `process.env.*`
// (bridged from REACT_APP_NIVXRAY_API_URL).  Use that channel so the
// landed-collector default path resolves the same way every other
// XDR module resolves the backend base URL.
const BACKEND_URL  =
  (typeof process !== "undefined"
    && process.env
    && process.env.REACT_APP_BACKEND_URL) || "";

const COLLECTOR_BASE = CUSTOM_URL
  ? `${CUSTOM_URL.replace(/\/+$/, "")}/api/xdr`
  : (BACKEND_URL
      ? `${BACKEND_URL.replace(/\/+$/, "")}/api/xdr/collector`
      : "");

const client = COLLECTOR_BASE
  ? axios.create({ baseURL: COLLECTOR_BASE, timeout: 8000 })
  : null;

function notDeployed() {
  const err = new Error("collector_runtime_not_deployed");
  err.code = "COLLECTOR_RUNTIME_NOT_DEPLOYED";
  err.note = "Neither VITE_XDR_COLLECTOR_URL nor REACT_APP_BACKEND_URL is "
              + "set. Set REACT_APP_BACKEND_URL to use the landed collector, "
              + "or VITE_XDR_COLLECTOR_URL to point at a separately deployed "
              + "standalone collector (on-prem syslog forwarder).";
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
