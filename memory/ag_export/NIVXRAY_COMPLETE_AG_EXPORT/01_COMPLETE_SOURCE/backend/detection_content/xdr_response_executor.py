"""
P0.7 · Round 13 · Approval Policy + Action Executor
───────────────────────────────────────────────────

The executor is the **only** component allowed to claim execution.
State machine:

    QUEUED → APPROVAL_REQUIRED → APPROVED → RUNNING → SUCCEEDED
                                                     ↘ FAILED
                                                     ↘ TIMEOUT
                              ↘ REJECTED → CANCELLED
    NOT_CONFIGURED           (no integration wired)
    NOT_SUPPORTED            (adapter refused the target)

Golden rule (§37):
  * The executor NEVER reports SUCCESS because a request was
    dispatched.  Only a real adapter result flips SUCCEEDED.
  * When the required integration is not wired, state stays
    NOT_CONFIGURED — no fabricated SUCCESS.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any

from .xdr_action_registry import (
    action_entry, list_actions, ApprovalPolicy,
)


EXECUTOR_ENGINE_ID   = "nivxray::xdr::action_executor"
APPROVAL_ENGINE_ID   = "nivxray::xdr::approval_policy"
EXECUTOR_VERSION     = "1.0.0"


# ── Approval Policy ─────────────────────────────────────────────

def evaluate_approval(action_entry_dict: dict,
                            requester_role: str = "analyst") -> dict:
    """
    Deterministic approval routing.  APPROVAL_REQUIRED / DUAL_APPROVAL
    actions never auto-execute regardless of requester role.
    """
    policy = (action_entry_dict or {}).get("approval_policy")
    if policy == ApprovalPolicy.AUTO_APPROVE.value:
        return {"engine_id":    APPROVAL_ENGINE_ID,
                    "policy":        policy,
                    "state":         "AUTO_APPROVED",
                    "reason":        "policy=AUTO_APPROVE"}
    if policy == ApprovalPolicy.APPROVAL_REQUIRED.value:
        return {"engine_id":    APPROVAL_ENGINE_ID,
                    "policy":        policy,
                    "state":         "APPROVAL_REQUIRED",
                    "reason":        "policy=APPROVAL_REQUIRED · queue for reviewer"}
    if policy == ApprovalPolicy.DUAL_APPROVAL.value:
        return {"engine_id":    APPROVAL_ENGINE_ID,
                    "policy":        policy,
                    "state":         "APPROVAL_REQUIRED",
                    "reason":        "policy=DUAL_APPROVAL · requires two approvers"}
    return {"engine_id":    APPROVAL_ENGINE_ID,
                "policy":        policy or "UNKNOWN",
                "state":         "APPROVAL_REQUIRED",
                "reason":        f"unknown approval policy: {policy}"}


# ── Executor ────────────────────────────────────────────────────

async def execute_action(db, *, incident_id: str, action_id: str,
                             parameters: dict, principal_id: str,
                             tenant_id: str, approval: dict) -> dict:
    """
    Attempt to execute an action.  Persists the execution record to
    `xdr_response_executions` (existing collection, no parallel store).

    HONEST STATE:
      * If the required integration is not wired → state=NOT_CONFIGURED.
      * If approval is required but not granted → state=APPROVAL_REQUIRED
        and the record stays in the queue.
      * SUCCEEDED requires a real adapter confirmation — never fabricated.
    """
    entry = action_entry(action_id)
    if not entry:
        return await _record(db, incident_id=incident_id, action_id=action_id,
                                    parameters=parameters, principal_id=principal_id,
                                    tenant_id=tenant_id, approval=approval,
                                    state="NOT_SUPPORTED",
                                    reason=f"action_id '{action_id}' not in registry")

    # Runtime capability probe.
    live = {a["action_id"]: a for a in list_actions()}.get(action_id) or {}
    if not live.get("capability_available"):
        return await _record(db, incident_id=incident_id, action_id=action_id,
                                    parameters=parameters, principal_id=principal_id,
                                    tenant_id=tenant_id, approval=approval,
                                    state="NOT_CONFIGURED",
                                    reason=live.get("capability_reason")
                                             or "integration not configured",
                                    entry=entry)

    # Approval gate.
    if approval.get("state") != "AUTO_APPROVED":
        return await _record(db, incident_id=incident_id, action_id=action_id,
                                    parameters=parameters, principal_id=principal_id,
                                    tenant_id=tenant_id, approval=approval,
                                    state="APPROVAL_REQUIRED",
                                    reason="waiting for approver decision",
                                    entry=entry)

    # ── Real adapter bindings ────────────────────────────────
    #
    # OSINT enrichment uses the existing services/ioc_intelligence
    # engine (§4 · reuse).  Every other executor stays honestly
    # NOT_CONFIGURED because no external adapter is wired.
    executor = entry.get("executor")
    if executor and executor.startswith("osint."):
        try:
            adapter_result = await _run_osint(executor, parameters)
            return await _record(
                db, incident_id=incident_id, action_id=action_id,
                parameters=parameters, principal_id=principal_id,
                tenant_id=tenant_id, approval=approval,
                state="SUCCEEDED",
                reason=(f"OSINT enrichment complete · "
                          f"consensus={adapter_result.get('verdict')} "
                          f"score={adapter_result.get('score')}"),
                entry=entry, adapter_result=adapter_result)
        except Exception as e:
            return await _record(
                db, incident_id=incident_id, action_id=action_id,
                parameters=parameters, principal_id=principal_id,
                tenant_id=tenant_id, approval=approval,
                state="FAILED",
                reason=f"{type(e).__name__}: {e!s}",
                entry=entry)

    return await _record(db, incident_id=incident_id, action_id=action_id,
                                parameters=parameters, principal_id=principal_id,
                                tenant_id=tenant_id, approval=approval,
                                state="NOT_CONFIGURED",
                                reason=f"executor for '{entry['executor']}' has no "
                                         "adapter bound in this deployment (§37: "
                                         "no fabricated SUCCESS)",
                                entry=entry)


# ── OSINT executor binding — reuses existing engine ───────────

async def _run_osint(executor: str, parameters: dict) -> dict:
    """Dispatch OSINT enrichment through the existing IOC engine."""
    from services.ioc_intelligence.engine import enrich_ioc
    kind_map = {
        "osint.enrich_ip":     ("ip",     "ip"),
        "osint.enrich_url":    ("url",    "url"),
        "osint.enrich_domain": ("domain", "domain"),
        "osint.enrich_hash":   ("hash",   "hash"),
    }
    kind, param_name = kind_map.get(executor, (None, None))
    if not kind:
        raise ValueError(f"unknown OSINT executor: {executor}")
    value = parameters.get(param_name)
    if not value:
        raise ValueError(f"parameter '{param_name}' is required")
    card = await enrich_ioc(kind=kind, value=value, use_cache=True)
    d = card.to_dict() if hasattr(card, "to_dict") else dict(card)
    consensus = d.get("consensus") or {}
    return {
        "verdict":   consensus.get("verdict") or d.get("verdict") or "unknown",
        "score":     consensus.get("score")   or d.get("score")   or 0,
        "providers": d.get("providers") or [],
        "kind":      kind,
        "value":     value,
        "fetched_at": d.get("fetched_at"),
    }


# ── Persistence ─────────────────────────────────────────────────

async def _record(db, *, incident_id: str, action_id: str,
                    parameters: dict, principal_id: str,
                    tenant_id: str, approval: dict,
                    state: str, reason: str,
                    entry: dict | None = None,
                    adapter_result: dict | None = None) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    execution_id = f"exe_{uuid.uuid4().hex[:20]}"
    doc = {
        "execution_id":   execution_id,
        "incident_id":    incident_id,
        "action_id":      action_id,
        "tenant_id":      tenant_id,
        "principal_id":   principal_id,
        "parameters":     parameters,
        "approval":       approval,
        "state":          state,
        "reason":         reason,
        "adapter_result": adapter_result,
        "started_at":     now,
        "completed_at":   now if state in ("NOT_CONFIGURED",
                                                       "NOT_SUPPORTED",
                                                       "REJECTED",
                                                       "APPROVAL_REQUIRED",
                                                       "SUCCEEDED",
                                                       "FAILED")
                                 else None,
        "executor_id":    EXECUTOR_ENGINE_ID,
        "executor_version": EXECUTOR_VERSION,
        "action_entry":   entry,
    }
    await db["xdr_response_executions"].insert_one(dict(doc))
    # Emit into the existing tamper-evident audit chain.
    await _emit_audit_async(db, execution_id=execution_id,
                                 incident_id=incident_id,
                                 action_id=action_id,
                                 tenant_id=tenant_id,
                                 principal_id=principal_id,
                                 state=state, reason=reason)
    # Project a response timeline row keyed by execution_id.
    await db["xdr_response_timeline"].insert_one({
        "timeline_id":  f"tl_{uuid.uuid4().hex[:12]}",
        "execution_id": execution_id,
        "incident_id":  incident_id,
        "at":           now,
        "kind":         f"response_action_{state.lower()}",
        "label":        f"{action_id} · {state}",
        "reason":       reason,
    })
    doc.pop("_id", None)
    return doc


async def _emit_audit_async(db, *, execution_id: str, incident_id: str,
                                  action_id: str, tenant_id: str,
                                  principal_id: str, state: str,
                                  reason: str) -> None:
    """
    Async wrapper over the existing tamper-evident audit chain.  We
    write directly to `xdr_audit_log` collection here (motor) instead
    of importing the sync `emit_audit()` helper — this keeps async
    correctness without duplicating the SSOT.
    """
    now = datetime.now(timezone.utc).isoformat()
    event_id = f"aud_{uuid.uuid4().hex[:20]}"
    prev = await db["xdr_audit_log"].find_one(
        {"tenant_id": tenant_id}, sort=[("at", -1)])
    prev_sig = (prev or {}).get("sig", "genesis")
    base = {
        "id":            event_id,
        "tenant_id":     tenant_id,
        "principal_id":  principal_id,
        "principal_kind": "user",
        "action":        f"response.{action_id.lower()}",
        "resource_kind": "response_execution",
        "resource_id":   execution_id,
        "outcome":       state,
        "before":        None,
        "after":         {"state": state, "reason": reason},
        "correlation_id": incident_id,
        "source":        EXECUTOR_ENGINE_ID,
        "metadata":      {"reason": reason},
        "at":            now,
    }
    # Deterministic signature — same fields+prev_sig → same sig.
    import hashlib, json as _json
    payload = _json.dumps({**base, "prev_sig": prev_sig},
                                    sort_keys=True, separators=(",", ":"))
    sig = hashlib.sha256(payload.encode()).hexdigest()
    await db["xdr_audit_log"].insert_one({**base,
                                                       "prev_sig": prev_sig,
                                                       "sig":      sig})
