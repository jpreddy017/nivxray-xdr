"""
Action adapters · Phase 1 stubs.

Each adapter is `async (params, ctx) → {ok, result, error?, reversal_id?}`.
Phase 1 ships DETERMINISTIC STUBS that never touch a real vendor —
they exist so the Response Engine's execution lifecycle, idempotency,
forwarder, and integration with playbooks/rules/analyst can be
exercised end-to-end.  Phase C swaps these for real CrowdStrike /
Defender / SentinelOne / Cisco SEP adapters WITHOUT changing the
execution model.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict

from framework.registry import ActionSpec


async def _stub_ok(params: Dict[str, Any], ctx: Dict[str, Any],
                       *, reversible: bool = False) -> Dict[str, Any]:
    """Deterministic success stub.  Records the params it saw so the
    caller can prove parameter routing worked."""
    return {
        "ok":         True,
        "result":     {"stub": True, "params": params, "adapter_version": "phase1.1"},
        "reversal_id": ("exec-rev-" + uuid.uuid4().hex[:12]) if reversible else None,
    }


# ── Endpoint ─────────────────────────────────────────────────
async def endpoint_isolate(params, ctx):        return await _stub_ok(params, ctx, reversible=True)
async def endpoint_kill_process(params, ctx):   return await _stub_ok(params, ctx)
async def endpoint_quarantine_file(params, ctx): return await _stub_ok(params, ctx, reversible=True)
async def endpoint_collect_forensics(params, ctx): return await _stub_ok(params, ctx, reversible=True)
async def endpoint_live_query(params, ctx):     return await _stub_ok(params, ctx)


# ── Identity ─────────────────────────────────────────────────
async def identity_disable_user(params, ctx):     return await _stub_ok(params, ctx, reversible=True)
async def identity_revoke_sessions(params, ctx):  return await _stub_ok(params, ctx)
async def identity_reset_password(params, ctx):   return await _stub_ok(params, ctx)


# ── Network ──────────────────────────────────────────────────
async def network_block_ip(params, ctx):     return await _stub_ok(params, ctx, reversible=True)
async def network_block_domain(params, ctx): return await _stub_ok(params, ctx, reversible=True)
async def network_block_hash(params, ctx):   return await _stub_ok(params, ctx, reversible=True)


# ── Email ────────────────────────────────────────────────────
async def email_quarantine_message(params, ctx): return await _stub_ok(params, ctx, reversible=True)
async def email_search_mailbox(params, ctx):     return await _stub_ok(params, ctx)


# ── NivXRay-native ───────────────────────────────────────────
async def nivxray_create_investigation(params, ctx):  return await _stub_ok(params, ctx, reversible=True)
async def nivxray_assign_analyst(params, ctx):        return await _stub_ok(params, ctx, reversible=True)
async def nivxray_change_verdict(params, ctx):        return await _stub_ok(params, ctx, reversible=True)
async def nivxray_notify(params, ctx):                return await _stub_ok(params, ctx)
async def nivxray_create_ticket(params, ctx):         return await _stub_ok(params, ctx, reversible=True)


STUB_ACTIONS = [
  # Endpoint
  ActionSpec("endpoint.isolate",           "endpoint", "isolate_endpoint",       "Isolate Endpoint",
      parameters=[{"key":"host_id","label":"Host ID","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"endpoint:isolate"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=endpoint_isolate),
  ActionSpec("endpoint.kill_process",      "endpoint", "kill_process",           "Kill Process",
      parameters=[{"key":"host_id","label":"Host ID","type":"string","required":True},
                     {"key":"pid","label":"PID","type":"number","required":True}],
      required_permissions=[{"role":"responder","scope":"endpoint:kill"}],
      approval_required=True, reversible=False, destructive=True,
      adapter=endpoint_kill_process),
  ActionSpec("endpoint.quarantine_file",   "endpoint", "quarantine_file",        "Quarantine File",
      parameters=[{"key":"host_id","label":"Host ID","type":"string","required":True},
                     {"key":"path","label":"Path","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"endpoint:quarantine"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=endpoint_quarantine_file),
  ActionSpec("endpoint.collect_forensics", "endpoint", "collect_forensics",      "Collect Forensic Snapshot",
      parameters=[{"key":"host_id","label":"Host ID","type":"string","required":True}],
      required_permissions=[{"role":"analyst","scope":"endpoint:collect"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=endpoint_collect_forensics),
  ActionSpec("endpoint.live_query",        "endpoint", "live_query",             "Run Live Query",
      parameters=[{"key":"host_id","label":"Host ID","type":"string","required":True},
                     {"key":"query","label":"Query","type":"string","required":True}],
      required_permissions=[{"role":"hunter","scope":"endpoint:query"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=endpoint_live_query),
  # Identity
  ActionSpec("identity.disable_user",      "identity", "disable_user",           "Disable User",
      parameters=[{"key":"user_id","label":"User","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"identity:disable"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=identity_disable_user),
  ActionSpec("identity.revoke_sessions",   "identity", "revoke_sessions",        "Revoke Sessions",
      parameters=[{"key":"user_id","label":"User","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"identity:revoke"}],
      approval_required=True, reversible=False, destructive=True,
      adapter=identity_revoke_sessions),
  ActionSpec("identity.reset_password",    "identity", "reset_password",         "Force Password Reset",
      parameters=[{"key":"user_id","label":"User","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"identity:reset"}],
      approval_required=True, reversible=False, destructive=True,
      adapter=identity_reset_password),
  # Network
  ActionSpec("network.block_ip",     "network", "block_ip",     "Block IP",
      parameters=[{"key":"ip","label":"IP","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"network:block"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=network_block_ip),
  ActionSpec("network.block_domain", "network", "block_domain", "Block Domain",
      parameters=[{"key":"domain","label":"Domain","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"network:block"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=network_block_domain),
  ActionSpec("network.block_hash",   "network", "block_hash",   "Block File Hash",
      parameters=[{"key":"hash","label":"SHA-256","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"network:block"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=network_block_hash),
  # Email
  ActionSpec("email.quarantine_message", "email", "quarantine_message", "Quarantine Message",
      parameters=[{"key":"message_id","label":"Message ID","type":"string","required":True}],
      required_permissions=[{"role":"responder","scope":"email:quarantine"}],
      approval_required=True, reversible=True, destructive=True,
      adapter=email_quarantine_message),
  ActionSpec("email.search_mailbox", "email", "search_mailbox", "Search Mailbox",
      parameters=[{"key":"user","label":"Mailbox","type":"string","required":True},
                     {"key":"query","label":"Query","type":"string","required":True}],
      required_permissions=[{"role":"analyst","scope":"email:search"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=email_search_mailbox),
  # NivXRay-native
  ActionSpec("nivxray.create_investigation", "nivxray", "create_investigation", "Create Investigation",
      parameters=[], required_permissions=[{"role":"analyst","scope":"case:create"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=nivxray_create_investigation),
  ActionSpec("nivxray.assign_analyst",       "nivxray", "assign_analyst",       "Assign Analyst",
      parameters=[{"key":"analyst","label":"Analyst","type":"string","required":True}],
      required_permissions=[{"role":"lead","scope":"case:assign"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=nivxray_assign_analyst),
  ActionSpec("nivxray.change_verdict",       "nivxray", "change_verdict",       "Change Verdict",
      parameters=[{"key":"verdict","label":"Verdict","type":"string","required":True}],
      required_permissions=[{"role":"lead","scope":"verdict:override"}],
      approval_required=True, reversible=True, destructive=False,
      adapter=nivxray_change_verdict),
  ActionSpec("nivxray.notify", "nivxray", "notify", "Send Notification",
      parameters=[{"key":"channel","label":"Channel","type":"string","required":True},
                     {"key":"message","label":"Message","type":"string","required":True}],
      required_permissions=[{"role":"analyst","scope":"notify"}],
      approval_required=False, reversible=False, destructive=False,
      adapter=nivxray_notify),
  ActionSpec("nivxray.create_ticket", "nivxray", "create_ticket", "Create Ticket",
      parameters=[{"key":"system","label":"System","type":"string","required":True}],
      required_permissions=[{"role":"analyst","scope":"ticket:create"}],
      approval_required=False, reversible=True, destructive=False,
      adapter=nivxray_create_ticket),
]
