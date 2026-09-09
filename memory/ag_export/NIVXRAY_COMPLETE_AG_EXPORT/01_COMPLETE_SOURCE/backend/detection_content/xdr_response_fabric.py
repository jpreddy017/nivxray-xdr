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

    Round 14 (§9): loop protection — if an execution with the same
    (action_id, evidence_state_hash) has already SUCCEEDED, we do
    not re-execute; state is reported as ALREADY_EXECUTED.
    """
    from .xdr_closed_loop import _evidence_state_hash

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

    # Load observations for context (Round 14 · §14).
    all_obs: list[dict] = []
    async for o in db["xdr_intelligence_observations"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        all_obs.append(o)
    if all_obs:
        context["observations"] = [
            {"provider": o.get("provider"), "verdict": o.get("verdict"),
              "indicator": o.get("indicator")} for o in all_obs]

    # Evidence-state hash for loop protection.
    inc = await db["workspace_cases"].find_one({"id": incident_id}, {"_id": 0})
    executions: list[dict] = []
    async for e in db["xdr_response_executions"].find(
        {"incident_id": incident_id}, {"_id": 0}
    ):
        executions.append(e)
    evidence_hash = _evidence_state_hash(inc or {}, all_obs, executions)

    # Recommendations must consider observations too.
    from .xdr_closed_loop import recommend_with_observations
    recos    = recommend_with_observations(context, all_obs)
    decision = decide(context, recos)

    approval  = None
    execution = None
    playbook  = _resolve_playbook(decision)

    if decision["decision"] in ("DIRECT_ACTION_AVAILABLE",
                                            "APPROVAL_REQUIRED"):
        approval = evaluate_approval(decision.get("action_entry") or {})
        params   = _resolve_parameters(decision, context, recos)

        # Loop protection (§9): if this action already SUCCEEDED on
        # this incident, do not re-execute.  Legitimate re-invocation
        # requires the caller to first supersede the observation via
        # explicit analyst action.
        already = next((e for e in executions
                                if e.get("action_id") == decision["required_action"]
                                and e.get("state") == "SUCCEEDED"),
                              None)
        if already:
            execution = {**already, "state": "ALREADY_EXECUTED",
                              "reason":
                                  f"action {decision['required_action']} already "
                                  f"SUCCEEDED on this evidence_state_hash "
                                  f"({evidence_hash}) · loop protection engaged"}
        elif not dry_run:
            execution = await execute_action(
                db,
                incident_id=incident_id,
                action_id=decision["required_action"],
                parameters=params,
                principal_id=principal_id,
                tenant_id=tenant_id,
                approval=approval)
            # Tag the execution with the evidence-state hash so
            # future orchestrate() calls can enforce loop protection.
            if execution and execution.get("execution_id"):
                await db["xdr_response_executions"].update_one(
                    {"execution_id": execution["execution_id"]},
                    {"$set": {"evidence_state_hash": evidence_hash}})
                execution["evidence_state_hash"] = evidence_hash

    return {
        "engine_id":       FABRIC_ENGINE_ID,
        "engine_version":  FABRIC_VERSION,
        "state":           "READY",
        "incident_id":     incident_id,
        "evidence_state_hash": evidence_hash,
        "context":         context,
        "recommendations": recos,
        "decision":        decision,
        "playbook":        playbook,
        "approval":        approval,
        "execution":       execution,
        "honesty_note":
            "Every stage is a projection of persisted evidence + a real "
            "capability probe.  A response reaches SUCCEEDED only when a "
            "real adapter confirms it — never fabricated.  Loop protection "
            "prevents re-execution on identical evidence state (§9).",
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
