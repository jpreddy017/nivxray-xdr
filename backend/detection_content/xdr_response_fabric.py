"""
P0.7 · Round 13 · Response Fabric Orchestrator
──────────────────────────────────────────────

Ties Context → Recommendations → Decision → (Playbook) → Approval →
Executor → Audit → Timeline into one deterministic in-process flow.

Owner-locked (§4 · reuse existing infrastructure):
  * Audit chain lives in `xdr_audit_log` — no parallel audit store.
  * Response evidence lives in `xdr_response_executions/timeline/audit`
    (existing SSOT from `routers/xdr_response_evidence.py`).
  * This orchestrator is an in-process composer — NOT a second
    response engine.
"""
from __future__ import annotations
from typing import Any

from .xdr_response_decision import (
    build_response_context, recommend, decide,
    DECISION_ENGINE_ID,
)
from .xdr_response_executor import evaluate_approval, execute_action


FABRIC_ENGINE_ID = "nivxray::xdr::response_fabric"
FABRIC_VERSION   = "1.0.0"


async def orchestrate(db, incident_id: str, *,
                          principal_id: str = "system",
                          tenant_id: str = "default",
                          dry_run: bool = False) -> dict:
    """
    One-shot Response Fabric run for one incident.

    Returns the full record: context + recommendations + decision +
    approval + execution.  HONEST STATE preserved end-to-end.
    """
    context = await build_response_context(db, incident_id)
    if context.get("state") != "READY":
        return {
            "engine_id":     FABRIC_ENGINE_ID,
            "engine_version": FABRIC_VERSION,
            "state":         "BLOCKED",
            "reason":        context.get("reason")
                                or "response context not READY",
            "context":       context,
        }

    recos    = recommend(context)
    decision = decide(context, recos)

    approval = None
    execution = None
    playbook = _resolve_playbook(decision)

    if decision["decision"] == "DIRECT_ACTION_AVAILABLE":
        approval = evaluate_approval(decision.get("action_entry") or {})
        params = _resolve_parameters(decision, context, recos)
        if not dry_run:
            execution = await execute_action(
                db,
                incident_id=incident_id,
                action_id=decision["required_action"],
                parameters=params,
                principal_id=principal_id,
                tenant_id=tenant_id,
                approval=approval)
    elif decision["decision"] == "APPROVAL_REQUIRED":
        approval = evaluate_approval(decision.get("action_entry") or {})
        params = _resolve_parameters(decision, context, recos)
        # Queue the record honestly in APPROVAL_REQUIRED state.
        if not dry_run:
            execution = await execute_action(
                db,
                incident_id=incident_id,
                action_id=decision["required_action"],
                parameters=params,
                principal_id=principal_id,
                tenant_id=tenant_id,
                approval=approval)

    return {
        "engine_id":       FABRIC_ENGINE_ID,
        "engine_version":  FABRIC_VERSION,
        "state":           "READY",
        "incident_id":     incident_id,
        "context":         context,
        "recommendations": recos,
        "decision":        decision,
        "playbook":        playbook,
        "approval":        approval,
        "execution":       execution,
        "honesty_note":
            "Every stage is a projection of persisted evidence + a real "
            "capability probe.  A response reaches SUCCEEDED only when a "
            "real adapter confirms it — never fabricated.",
    }


# ── Parameter resolution — deterministic mapping from context ──

def _resolve_parameters(decision: dict, context: dict,
                            recos: list[dict]) -> dict:
    """
    Deterministically pick the first target entity for the chosen
    action.  Honest: if no entity supports the action, returns {}.
    """
    action_id = decision.get("required_action") or ""
    entities  = context.get("entities") or []

    # OSINT enrichment: pick the source-role IP first, then destination.
    if action_id == "OSINT_ENRICH_IP":
        for role in ("source", "destination"):
            for e in entities:
                if e.get("role") == role and e.get("kind", "").startswith("ipv"):
                    return {"ip": e["value"]}
        return {}
    if action_id == "IP_BLOCK":
        for e in entities:
            if e.get("role") == "source" and e.get("kind", "").startswith("ipv"):
                return {"ip": e["value"], "reason":
                              decision.get("reason") or "response-fabric"}
        return {}
    if action_id == "IOC_ADD_WATCHLIST":
        for e in entities:
            if e.get("kind", "").startswith("ipv"):
                return {"ioc": e["value"], "ioc_type": e["kind"]}
        return {}
    return {}


# ── Playbook Resolver ───────────────────────────────────────────

# Round 13 preview registers ZERO playbooks — they only appear when
# an actual orchestration definition is loaded.  This preserves the
# "Recommendations → Playbook is not hardcoded" rule from the master
# prompt.
_PLAYBOOKS: dict[str, dict] = {}


def _resolve_playbook(decision: dict) -> dict | None:
    if decision.get("decision") != "PLAYBOOK_AVAILABLE":
        return None
    action = decision.get("required_action")
    pb = _PLAYBOOKS.get(action or "")
    if not pb:
        return {"state": "MISSING",
                    "reason": f"no playbook registered for action {action}"}
    return {"state": "READY", **pb}
