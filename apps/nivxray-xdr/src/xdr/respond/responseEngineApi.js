/**
 * Response Engine API client.
 *
 * Talks to the independently-deployed NivXRay XDR Response Engine
 * (see /app/apps/nivxray-xdr-response).  Base URL from
 * `import.meta.env.VITE_XDR_RESPONSE_URL`.  When unset every call
 * surfaces `RESPONSE_ENGINE_NOT_DEPLOYED` — never a fake success.
 */
import axios from "axios";

const BASE = import.meta.env.VITE_XDR_RESPONSE_URL || "";

const client = BASE
  ? axios.create({ baseURL: `${BASE.replace(/\/+$/, "")}/api/respond`,
                     timeout: 15000 })
  : null;

function notDeployed() {
  const err = new Error("response_engine_not_deployed");
  err.code = "RESPONSE_ENGINE_NOT_DEPLOYED";
  err.note = "Set VITE_XDR_RESPONSE_URL to the deployed Response Engine URL.";
  throw err;
}

export const RESPONSE_ENGINE_CONFIGURED = !!BASE;
export const RESPONSE_ENGINE_URL        = BASE;

export async function listActions() {
  if (!client) notDeployed();
  const { data } = await client.get("/actions");
  return data;
}

export async function execute(body) {
  if (!client) notDeployed();
  const { data } = await client.post("/execute", body);
  return data;
}

export async function simulatePlaybook(body) {
  if (!client) notDeployed();
  const { data } = await client.post("/simulate-playbook", body);
  return data;
}

export async function getExecution(executionId, { tenantId, invokerKind, invokerId }) {
  if (!client) notDeployed();
  const { data } = await client.get(`/executions/${executionId}`, {
    params: { tenant_id: tenantId, invoker_kind: invokerKind, invoker_id: invokerId },
  });
  return data;
}
