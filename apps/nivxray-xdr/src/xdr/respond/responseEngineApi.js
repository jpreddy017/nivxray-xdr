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

// ── Canonical execution states ─────────────────────────────────────
export const EXEC_STATE = {
  QUEUED:             "QUEUED",
  RUNNING:            "RUNNING",
  WAITING_APPROVAL:   "WAITING_APPROVAL",
  EXECUTING:          "EXECUTING",
  FORWARDING:         "FORWARDING_EVIDENCE",
  SUCCEEDED:          "SUCCEEDED",
  FAILED_APPROVAL:    "FAILED_APPROVAL",
  FAILED_TARGET:      "FAILED_TARGET",
  FAILED_EXECUTION:   "FAILED_EXECUTION",
  FAILED_FORWARDING:  "FAILED_FORWARDING",
  FAILED_RECOVERED:   "FAILED_RECOVERED",
  REJECTED:           "REJECTED",
};

export const TERMINAL_STATES = new Set([
  EXEC_STATE.SUCCEEDED, EXEC_STATE.FAILED_APPROVAL, EXEC_STATE.FAILED_TARGET,
  EXEC_STATE.FAILED_EXECUTION, EXEC_STATE.FAILED_FORWARDING,
  EXEC_STATE.FAILED_RECOVERED, EXEC_STATE.REJECTED,
]);

// ── Action registry ────────────────────────────────────────────────
export async function listActions() {
  if (!client) notDeployed();
  const { data } = await client.get("/actions");
  return data;
}

// ── Single-action execute ──────────────────────────────────────────
export async function execute(body) {
  if (!client) notDeployed();
  const { data } = await client.post("/execute", body);
  return data;
}

// ── Read-back / poll ───────────────────────────────────────────────
export async function getExecution(executionId, opts = {}) {
  if (!client) notDeployed();
  const params = {};
  if (opts.tenantId)     params.tenant_id    = opts.tenantId;
  if (opts.invokerKind)  params.invoker_kind = opts.invokerKind;
  if (opts.invokerId)    params.invoker_id   = opts.invokerId;
  const { data } = await client.get(`/executions/${executionId}`, { params });
  return data;
}

// ── Approval decisions ─────────────────────────────────────────────
export async function approve(executionId, { approvedBy, approvalRef, reason } = {}) {
  if (!client) notDeployed();
  const { data } = await client.post(`/approve/${executionId}`, {
    approved_by:  approvedBy,
    approval_ref: approvalRef,
    reason,
  });
  return data;
}

export async function reject(executionId, { rejectedBy, reason } = {}) {
  if (!client) notDeployed();
  const { data } = await client.post(`/reject/${executionId}`, {
    rejected_by: rejectedBy,
    reason,
  });
  return data;
}

// ── Pending approvals queue ────────────────────────────────────────
export async function listPendingApprovals({ tenantId } = {}) {
  if (!client) notDeployed();
  const { data } = await client.get("/pending-approvals",
                                          { params: tenantId ? { tenant_id: tenantId } : {} });
  return data;
}

// ── Playbook dry-run simulator (unchanged wire contract) ───────────
export async function simulatePlaybook(body) {
  if (!client) notDeployed();
  const { data } = await client.post("/simulate-playbook", body);
  return data;
}

// ── Convenience: build an execute payload from an action node ──────
export function buildExecutePayload({
  executionId, tenantId, invoker, action, parameters,
  scopes = [], approval, dryRun = false,
}) {
  return {
    execution_id:  executionId,
    tenant_id:     tenantId,
    invoker,
    action:        { action_id: action, parameters: parameters || {} },
    authorization: {
      scopes,
      approval_ref: approval?.ref  || undefined,
      approved_by:  approval?.by   || undefined,
      reason:       approval?.reason || undefined,
    },
    constraints:   { dry_run: !!dryRun },
  };
}

// ── Live execution polling ─────────────────────────────────────────
// Polls /executions/{id} at ``intervalMs`` until the state is terminal
// or ``maxWaitMs`` elapses.  Returns the final row.  Caller supplies
// the same tenant / invoker used at enqueue time (all four keys form
// the canonical idempotency key).
export async function pollUntilTerminal(executionId, opts = {}) {
  const {
    tenantId, invokerKind, invokerId,
    intervalMs = 800, maxWaitMs = 30_000, onTick,
  } = opts;
  const deadline = Date.now() + maxWaitMs;
  let last = null;
  while (Date.now() < deadline) {
    last = await getExecution(executionId, { tenantId, invokerKind, invokerId });
    if (onTick) try { onTick(last); } catch (_) { /* swallow */ }
    if (TERMINAL_STATES.has(last.state) ||
          last.state === EXEC_STATE.WAITING_APPROVAL) {
      return last;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return last;
}
