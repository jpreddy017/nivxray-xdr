/**
 * Response Action Registry · owner-locked, execution-ready.
 *
 * DELIBERATELY DECOUPLED from the Collector Connector Registry.
 * Connectors are data-in; response actions are control-out.  Even
 * when the eventual Response Engine reuses the same vendor SDKs,
 * these two concepts stay separate to prevent evidence-plane and
 * response-plane bleed.
 *
 * Schema (per action, matches the target Response Engine record):
 *   action_id             — stable id, referenced by playbook nodes.
 *   provider              — vendor / domain (endpoint · identity · network · email · nivxray)
 *   capability            — short verb ("isolate_endpoint", "block_ip")
 *   label                 — human-friendly name
 *   description
 *   parameters            — [{ key, label, type, required }]
 *   required_permissions  — [{ role, scope }]
 *   approval_required     — bool  (Analyst-approval-required by default for destructive)
 *   reversible            — bool
 *   destructive           — bool
 *   execution_status      — "not_wired"  (until Response Engine lands)
 *   docs                  — external URL for the vendor action
 */
export const RESPONSE_ACTIONS = [
  // ── Endpoint ─────────────────────────────────────────────────
  { action_id: "endpoint.isolate",       provider: "endpoint", capability: "isolate_endpoint",
    label: "Isolate Endpoint",
    description: "Network-contain the endpoint via the connected EDR.",
    parameters: [{ key: "host_id", label: "Host ID", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "endpoint:isolate" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "endpoint.kill_process",  provider: "endpoint", capability: "kill_process",
    label: "Kill Process",
    parameters: [
      { key: "host_id", label: "Host ID",  type: "string", required: true },
      { key: "pid",     label: "PID",      type: "number", required: true },
    ],
    required_permissions: [{ role: "responder", scope: "endpoint:kill" }],
    approval_required: true, reversible: false, destructive: true,
    execution_status: "not_wired" },
  { action_id: "endpoint.quarantine_file", provider: "endpoint", capability: "quarantine_file",
    label: "Quarantine File",
    parameters: [
      { key: "host_id", label: "Host ID", type: "string", required: true },
      { key: "path",    label: "Path",    type: "string", required: true },
    ],
    required_permissions: [{ role: "responder", scope: "endpoint:quarantine" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "endpoint.collect_forensics", provider: "endpoint", capability: "collect_forensics",
    label: "Collect Forensic Snapshot",
    parameters: [{ key: "host_id", label: "Host ID", type: "string", required: true }],
    required_permissions: [{ role: "analyst", scope: "endpoint:collect" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },
  { action_id: "endpoint.live_query",    provider: "endpoint", capability: "live_query",
    label: "Run Live Query",
    parameters: [
      { key: "host_id", label: "Host ID", type: "string", required: true },
      { key: "query",   label: "Query",   type: "string", required: true },
    ],
    required_permissions: [{ role: "hunter", scope: "endpoint:query" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },

  // ── Identity ─────────────────────────────────────────────────
  { action_id: "identity.disable_user",  provider: "identity", capability: "disable_user",
    label: "Disable User",
    parameters: [{ key: "user_id", label: "User", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "identity:disable" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "identity.revoke_sessions", provider: "identity", capability: "revoke_sessions",
    label: "Revoke Sessions",
    parameters: [{ key: "user_id", label: "User", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "identity:revoke" }],
    approval_required: true, reversible: false, destructive: true,
    execution_status: "not_wired" },
  { action_id: "identity.reset_password", provider: "identity", capability: "reset_password",
    label: "Force Password Reset",
    parameters: [{ key: "user_id", label: "User", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "identity:reset" }],
    approval_required: true, reversible: false, destructive: true,
    execution_status: "not_wired" },

  // ── Network ──────────────────────────────────────────────────
  { action_id: "network.block_ip",       provider: "network", capability: "block_ip",
    label: "Block IP",
    parameters: [{ key: "ip", label: "IP", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "network:block" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "network.block_domain",   provider: "network", capability: "block_domain",
    label: "Block Domain",
    parameters: [{ key: "domain", label: "Domain", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "network:block" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "network.block_hash",     provider: "network", capability: "block_hash",
    label: "Block File Hash",
    parameters: [{ key: "hash", label: "SHA-256", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "network:block" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },

  // ── Email ────────────────────────────────────────────────────
  { action_id: "email.quarantine_message", provider: "email", capability: "quarantine_message",
    label: "Quarantine Message",
    parameters: [{ key: "message_id", label: "Message ID", type: "string", required: true }],
    required_permissions: [{ role: "responder", scope: "email:quarantine" }],
    approval_required: true, reversible: true, destructive: true,
    execution_status: "not_wired" },
  { action_id: "email.search_mailbox",   provider: "email", capability: "search_mailbox",
    label: "Search Mailbox",
    parameters: [{ key: "user", label: "Mailbox", type: "string", required: true },
                    { key: "query", label: "Query", type: "string", required: true }],
    required_permissions: [{ role: "analyst", scope: "email:search" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },

  // ── NivXRay ──────────────────────────────────────────────────
  { action_id: "nivxray.create_investigation", provider: "nivxray", capability: "create_investigation",
    label: "Create Investigation",
    parameters: [], required_permissions: [{ role: "analyst", scope: "case:create" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },
  { action_id: "nivxray.assign_analyst", provider: "nivxray", capability: "assign_analyst",
    label: "Assign Analyst",
    parameters: [{ key: "analyst", label: "Analyst", type: "string", required: true }],
    required_permissions: [{ role: "lead", scope: "case:assign" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },
  { action_id: "nivxray.change_verdict", provider: "nivxray", capability: "change_verdict",
    label: "Change Verdict",
    parameters: [{ key: "verdict", label: "Verdict", type: "string", required: true }],
    required_permissions: [{ role: "lead", scope: "verdict:override" }],
    approval_required: true, reversible: true, destructive: false,
    execution_status: "not_wired" },
  { action_id: "nivxray.notify",         provider: "nivxray", capability: "notify",
    label: "Send Notification",
    parameters: [{ key: "channel", label: "Channel", type: "string", required: true },
                    { key: "message", label: "Message", type: "string", required: true }],
    required_permissions: [{ role: "analyst", scope: "notify" }],
    approval_required: false, reversible: false, destructive: false,
    execution_status: "not_wired" },
  { action_id: "nivxray.create_ticket",  provider: "nivxray", capability: "create_ticket",
    label: "Create Ticket",
    parameters: [{ key: "system", label: "System", type: "string", required: true }],
    required_permissions: [{ role: "analyst", scope: "ticket:create" }],
    approval_required: false, reversible: true, destructive: false,
    execution_status: "not_wired" },
];

export const ACTIONS_BY_PROVIDER = RESPONSE_ACTIONS.reduce((acc, a) => {
  (acc[a.provider] = acc[a.provider] || []).push(a);
  return acc;
}, {});

export function getAction(id) {
  return RESPONSE_ACTIONS.find((a) => a.action_id === id) || null;
}

// Response Engine is not deployed yet.  UI treats every action as
// "not_wired" and refuses to execute — the Playbook Designer is
// design-only in this milestone.
export const RESPONSE_ENGINE_WIRED = false;
