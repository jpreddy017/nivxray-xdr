/**
 * XDR Collector API client · Phase A.
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

export const COLLECTOR_CONFIGURED = !!COLLECTOR_BASE;
