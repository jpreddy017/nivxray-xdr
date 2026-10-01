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

import { activeTenant } from "@/lib/tenant";

const CUSTOM_URL   = import.meta.env.VITE_XDR_COLLECTOR_URL || "";
// vite.config.js `define` replaces the EXACT literal
// `process.env.REACT_APP_BACKEND_URL` (bridged from
// REACT_APP_NIVXRAY_API_URL). Read it exactly as `lib/api.js` does.
//
// This used to be wrapped in `typeof process !== "undefined" && process.env
// && …`. `define` only substitutes the full literal, so in a PRODUCTION
// bundle the guard compiled to `typeof process<"u" && {} && "https://…"` —
// `process` does not exist in a browser, so it short-circuited to "" and
// COLLECTOR_CONFIGURED became false. The Vite DEV server defines `process`,
// so the defect was invisible in preview and only surfaced on Vercel as
// "COLLECTOR RUNTIME NOT WIRED" while authentication (lib/api.js, no guard)
// worked fine. scripts/verify-production-build.js now fails the build if the
// collector base is missing from the artifact.
const BACKEND_URL  = process.env.REACT_APP_BACKEND_URL || "";

const COLLECTOR_BASE = CUSTOM_URL
  ? `${CUSTOM_URL.replace(/\/+$/, "")}/api/xdr`
  : (BACKEND_URL
      ? `${BACKEND_URL.replace(/\/+$/, "")}/api/xdr/collector`
      : "");

const client = COLLECTOR_BASE
  ? axios.create({ baseURL: COLLECTOR_BASE, timeout: 8000 })
  : null;

// The collector plane is AUTHENTICATED and tenant-scoped. This client is a
// separate axios instance, so it needs the same one-place header attachment as
// `lib/api.js`: no call site can then forget the credential or the tenant, and
// none can substitute a default.
//
// Collector Auth P0 · this instance previously sent NO Authorization header at
// all, which was survivable only because the collector plane was anonymous.
// The bearer token is the SAME session token `lib/api.js` uses — no second
// credential, no collector-specific identity, nothing invented here. When no
// session exists no header is sent and the server answers ACCESS_DENIED /
// unauthenticated, which is the honest outcome.
if (client) {
  client.interceptors.request.use((config) => {
    if (config.headers.Authorization == null) {
      const token = localStorage.getItem("nvx_token");
      if (token) config.headers.Authorization = `Bearer ${token}`;
    }
    if (config.headers["X-Tenant-Id"] == null) {
      const tenant = activeTenant();
      if (tenant) config.headers["X-Tenant-Id"] = tenant;
    }
    return config;
  });
}

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
/**
 * The authoritative tenant for a collector-plane operation.
 *
 * B7 Option A · previously `tenantId = "default"`, so a preflight probe and a
 * connector CREATE could both name a tenant the operator never selected and
 * that the registry does not hold. Collector creation must never create or
 * infer tenancy. There is no default tenant, so an absent selection is an
 * explicit client-side refusal rather than a substituted value.
 */
function requireTenant(tenantId) {
  const tenant = (tenantId || activeTenant() || "").trim();
  if (!tenant) {
    const err = new Error(
      "NO_TENANT_CONTEXT — select an authoritative tenant first. "
      + "Collector operations are tenant-scoped and there is no default tenant.");
    err.code = "NO_TENANT_CONTEXT";
    throw err;
  }
  return tenant;
}

export async function ingestPreflight(tenantId) {
  if (!client) notDeployed();
  const { data } = await client.post("/ingest-preflight", null,
                                          { headers: { "X-Tenant-Id": requireTenant(tenantId) } });
  return data;
}

// ── CRUD + control ────────────────────────────────────────
export async function createConnector(body, tenantId) {
  if (!client) notDeployed();
  const { data } = await client.post("/connectors", body,
                                          { headers: { "X-Tenant-Id": requireTenant(tenantId) } });
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
