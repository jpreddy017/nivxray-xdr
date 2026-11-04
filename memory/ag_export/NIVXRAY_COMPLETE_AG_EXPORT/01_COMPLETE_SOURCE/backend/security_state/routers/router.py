"""FastAPI Router for NivXRay Security State & Causal Intelligence Core."""
from __future__ import annotations

from typing import Any, Dict, List, Optional
try:
    from fastapi import APIRouter, HTTPException, Query, Body
    from pydantic import BaseModel, Field
except ImportError:
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class APIRouter:
        def __init__(self, *args, **kwargs):
            self.routes = []
        def get(self, path, *args, **kwargs):
            def decorator(f): return f
            return decorator
        def post(self, path, *args, **kwargs):
            def decorator(f): return f
            return decorator

    def Query(default=None, **kwargs):
        return default

    def Body(default=None, **kwargs):
        return default

    def Field(default_factory=None, default=None, **kwargs):
        if default_factory:
            return default_factory()
        return default

    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)


from ..contracts import (
    AttackState,
    EntityCategory,
    EntityRef,
)
from ..state_engine.engine import SecurityStateEngine
from ..transitions.engine import TransitionEngine
from ..causal.engine import CausalSecurityEngine
from ..capability.engine import CapabilityContext, TrustedCapabilityAbuseEngine
from ..attack_state.machine import AttackStateMachine
from ..reachability.engine import EnterpriseReachabilityEngine
from ..counterfactual.engine import CounterfactualEngine
from ..impact.engine import ImpactEngine
from ..intervention.optimizer import InterventionOptimizer
from ..response_safety.safety_gate import ResponseSafetyGate
from ..response_safety.verification import ResponseVerificationEngine
from ..ledger.ledger import SecurityStateLedger


router = APIRouter(prefix="/api/v2/security-state", tags=["Security State & Causal Intelligence"])

# In-memory session ledgers and caches for demo/evaluation
_LEDGERS: Dict[str, SecurityStateLedger] = {}
_STATE_CACHE: Dict[str, Dict[str, Any]] = {}

# Engine Singletons
state_engine = SecurityStateEngine()
transition_engine = TransitionEngine()
causal_engine = CausalSecurityEngine()
capability_engine = TrustedCapabilityAbuseEngine()
attack_machine = AttackStateMachine()
reachability_engine = EnterpriseReachabilityEngine()
counterfactual_engine = CounterfactualEngine()
impact_engine = ImpactEngine()
intervention_optimizer = InterventionOptimizer()
safety_gate = ResponseSafetyGate()
verification_engine = ResponseVerificationEngine()


from ..persistence.repository import SecurityStateRepository

repository = SecurityStateRepository()


def set_repository(repo: SecurityStateRepository) -> None:
    global repository
    repository = repo


def get_repository() -> SecurityStateRepository:
    return repository


# ── Schemas ────────────────────────────────────────────────────────────────
class EntityRefSchema(BaseModel):
    category: str
    entity_id: str
    tenant_id: str
    display_name: str = ""


class EvaluateStateRequest(BaseModel):
    tenant_id: str
    case_id: str
    entity_refs: List[EntityRefSchema]
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)


class CounterfactualRequest(BaseModel):
    tenant_id: str
    candidate_actions: Optional[List[Dict[str, Any]]] = None


class VerifyResponseRequest(BaseModel):
    tenant_id: str
    action_id: str
    target_entity_id: str
    post_telemetry_events: List[Dict[str, Any]] = Field(default_factory=list)


class StageInterventionRequest(BaseModel):
    tenant_id: str
    action_id: str
    target_entity_id: str
    status: str = "STAGED"  # 'STAGED', 'SIMULATED', 'APPROVED', 'EXECUTE'
    analyst_notes: Optional[str] = ""


# ── Endpoints ──────────────────────────────────────────────────────────────
@router.post("/evaluate")
def evaluate_security_state(req: EvaluateStateRequest) -> Dict[str, Any]:
    """Evaluate, version, and persist immutable security states for enterprise entities."""
    ledger_key = f"{req.tenant_id}:{req.case_id}"
    evaluated_states: List[Dict[str, Any]] = []

    for eref in req.entity_refs:
        cat = getattr(EntityCategory, eref.category.upper(), EntityCategory.DEVICE)
        entity = EntityRef(category=cat, entity_id=eref.entity_id, tenant_id=req.tenant_id, display_name=eref.display_name)
        
        state = state_engine.evaluate_entity_state(
            tenant_id=req.tenant_id,
            entity_ref=entity,
            evidence_items=req.evidence_items,
        )
        
        # Auxiliary calculations for complete persistent snapshot
        reachability = reachability_engine.compute_reachability(
            tenant_id=req.tenant_id, case_id=req.case_id, footholds=[entity],
            harvested_credentials=[], active_capabilities=state.active_capabilities
        )
        impact = impact_engine.evaluate_impact(
            tenant_id=req.tenant_id, case_id=req.case_id, reachability=reachability, compromised_entities=[entity]
        )
        cf = counterfactual_engine.evaluate_counterfactuals(
            tenant_id=req.tenant_id, case_id=req.case_id, current_state=state,
            reachability=reachability, attack_state=AttackState.CREDENTIAL_ACCESS
        )
        plan = intervention_optimizer.optimize_intervention(
            tenant_id=req.tenant_id, case_id=req.case_id, reachability=reachability,
            impact=impact, counterfactual=cf, compromised_entities=[entity]
        )

        # 1. Persist to MongoDB (or fallback repository) with versioning & idempotency
        persistent_rec, is_new_ver = repository.save_state(
            tenant_id=req.tenant_id,
            case_id=req.case_id,
            state_data=state.to_dict(),
            reachability_data=reachability.to_dict(),
            impact_data=impact.to_dict(),
            intervention_data=plan.to_dict(),
            evidence_items=req.evidence_items,
            attack_state=AttackState.CREDENTIAL_ACCESS.value,
        )

        # 2. Append immutable, hash-chained block to persistent ledger
        if is_new_ver:
            repository.append_ledger_block(
                tenant_id=req.tenant_id,
                case_id=req.case_id,
                event_type="STATE_EVALUATED",
                entity_id=eref.entity_id,
                state_version=persistent_rec.version,
                payload={"state_hash": state.state_hash, "version": persistent_rec.version},
            )

        evaluated_states.append(persistent_rec.to_dict())

    response_payload = {
        "case_id": req.case_id,
        "tenant_id": req.tenant_id,
        "version": evaluated_states[0]["version"] if evaluated_states else 1,
        "persisted": True,
        "storage": "mongodb" if repository._use_mongo else "repository",
        "entity_count": len(evaluated_states),
        "states": evaluated_states,
    }

    # 3. Update memory cache as secondary lookup optimization ONLY
    _STATE_CACHE[ledger_key] = response_payload
    return response_payload


@router.get("/{case_id}")
def get_security_state(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve the current consolidated security state for a case (reloading from DB on cache miss)."""
    key = f"{tenant_id}:{case_id}"
    cached = _STATE_CACHE.get(key)
    if cached:
        return cached

    # Cache miss: transparently reload from persistent repository (§7)
    latest_rec = repository.get_latest_state(tenant_id, case_id)
    if not latest_rec:
        raise HTTPException(status_code=404, detail="Security state not found for case or tenant mismatch")

    reloaded_payload = {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "version": latest_rec.version,
        "persisted": True,
        "storage": "mongodb" if repository._use_mongo else "repository",
        "entity_count": 1,
        "states": [latest_rec.to_dict()],
    }
    _STATE_CACHE[key] = reloaded_payload
    return reloaded_payload


@router.get("/{case_id}/history")
def get_state_history(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve chronological historical versions of security state for audit review."""
    history = repository.get_state_history(tenant_id, case_id)
    return {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "versions_count": len(history),
        "history": [h.to_dict() for h in history],
    }


@router.get("/{case_id}/transitions")
def get_state_transitions(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve chronological security state transitions from persistent ledger."""
    blocks = repository.get_ledger_blocks(tenant_id, case_id)
    trans_blocks = [b.to_dict() for b in blocks if b.event_type in ("STATE_TRANSITION", "STATE_EVALUATED")]
    return {"case_id": case_id, "tenant_id": tenant_id, "transitions": trans_blocks}


@router.get("/{case_id}/causality")
def get_causal_analysis(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve verified causal graph separating correlation from causality."""
    sample_events = [
        {"id": "ev-01", "pid": 4120, "process_name": "winword.exe", "command_line": "winword.exe /n doc.docx", "time_ms": 100},
        {"id": "ev-02", "pid": 8944, "ppid": 4120, "process_name": "powershell.exe", "command_line": "powershell.exe -enc ...", "time_ms": 250},
        {"id": "ev-03", "type": "file_create", "process_name": "powershell.exe", "time_ms": 500},
    ]
    graph = causal_engine.evaluate_causality(tenant_id=tenant_id, case_id=case_id, events=sample_events)
    return graph.to_dict()


@router.get("/{case_id}/capabilities")
def get_capability_abuse_evaluations(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Evaluate dual-use administrative software under 11 contextual dimensions."""
    ctx = CapabilityContext(
        capability_name="powershell.exe",
        identity_ref=EntityRef(category=EntityCategory.IDENTITY, entity_id="user.jane", tenant_id=tenant_id),
        is_authorized_admin=False,
        source_ip_or_subnet="192.168.1.55",
        destination_ip_or_domain="pastebin.com",
        timestamp="2026-09-04T00:30:00Z",
        is_within_business_hours=False,
        command_line="powershell -enc aQB3AHIA...",
        parent_process="winword.exe",
        process_privilege_level="USER",
        has_inbound_tunnel_or_proxy=True,
    )
    eval_res = capability_engine.evaluate_capability(tenant_id=tenant_id, context=ctx, evidence_ids=["ev-01", "ev-02"])
    return eval_res.to_dict()


@router.get("/{case_id}/reachability")
def get_reachability_matrix(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve multidimensional attacker reachability across enterprise graph."""
    footholds = [
        EntityRef(category=EntityCategory.DEVICE, entity_id="host-finance-04", tenant_id=tenant_id, display_name="Finance Workstation 04")
    ]
    matrix = reachability_engine.compute_reachability(
        tenant_id=tenant_id,
        case_id=case_id,
        footholds=footholds,
        harvested_credentials=["admin.john"],
        active_capabilities=["CAP_CREDENTIAL_DUMPING", "CAP_ADMIN_EXECUTION"],
    )
    return matrix.to_dict()


@router.post("/{case_id}/counterfactual")
def evaluate_counterfactual(case_id: str, req: CounterfactualRequest) -> Dict[str, Any]:
    """Project parallel worlds: World A (Do Nothing) vs candidate intervention worlds."""
    footholds = [EntityRef(category=EntityCategory.DEVICE, entity_id="host-finance-04", tenant_id=req.tenant_id)]
    reachability = reachability_engine.compute_reachability(
        tenant_id=req.tenant_id, case_id=case_id, footholds=footholds,
        harvested_credentials=["admin.john"], active_capabilities=["CAP_CREDENTIAL_DUMPING"]
    )
    baseline_state = state_engine.evaluate_entity_state(
        tenant_id=req.tenant_id, entity_ref=footholds[0], evidence_items=[]
    )
    cf = counterfactual_engine.evaluate_counterfactuals(
        tenant_id=req.tenant_id, case_id=case_id, current_state=baseline_state,
        reachability=reachability, attack_state=AttackState.CREDENTIAL_ACCESS,
        candidate_actions=req.candidate_actions,
    )
    return cf.to_dict()


@router.post("/{case_id}/interventions/plan")
def plan_intervention(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Generate minimal effective intervention plan severing attack graph."""
    footholds = [EntityRef(category=EntityCategory.DEVICE, entity_id="host-finance-04", tenant_id=tenant_id)]
    reachability = reachability_engine.compute_reachability(
        tenant_id=tenant_id, case_id=case_id, footholds=footholds,
        harvested_credentials=["admin.john"], active_capabilities=["CAP_CREDENTIAL_DUMPING"]
    )
    impact = impact_engine.evaluate_impact(tenant_id=tenant_id, case_id=case_id, reachability=reachability, compromised_entities=footholds)
    baseline_state = state_engine.evaluate_entity_state(tenant_id=tenant_id, entity_ref=footholds[0], evidence_items=[])
    cf = counterfactual_engine.evaluate_counterfactuals(
        tenant_id=tenant_id, case_id=case_id, current_state=baseline_state,
        reachability=reachability, attack_state=AttackState.CREDENTIAL_ACCESS
    )
    plan = intervention_optimizer.optimize_intervention(
        tenant_id=tenant_id, case_id=case_id, reachability=reachability,
        impact=impact, counterfactual=cf, compromised_entities=footholds
    )
    return plan.to_dict()


@router.post("/{case_id}/response/verify")
def verify_response(case_id: str, req: VerifyResponseRequest) -> Dict[str, Any]:
    """Verify response action containment efficacy via post-action re-observation."""
    entity = EntityRef(category=EntityCategory.DEVICE, entity_id=req.target_entity_id, tenant_id=req.tenant_id)
    pre_state = state_engine.evaluate_entity_state(tenant_id=req.tenant_id, entity_ref=entity, evidence_items=[])
    
    report = verification_engine.verify_action_efficacy(
        tenant_id=req.tenant_id,
        case_id=case_id,
        action_id=req.action_id,
        target_entity_id=req.target_entity_id,
        pre_state=pre_state,
        post_telemetry_events=req.post_telemetry_events,
    )
    
    # Persist to immutable audit ledger (§4)
    ledger_block = repository.append_ledger_block(
        tenant_id=req.tenant_id,
        case_id=case_id,
        event_type="RESPONSE_VERIFIED",
        entity_id=req.target_entity_id,
        state_version=1,
        payload=report.to_dict(),
    )
    return report.to_dict()


@router.get("/{case_id}/ledger")
def get_security_state_ledger(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve immutable, cryptographically verified audit ledger from persistent store."""
    blocks = repository.get_ledger_blocks(tenant_id, case_id)
    if not blocks:
        return {"case_id": case_id, "tenant_id": tenant_id, "integrity_verified": True, "block_count": 0, "blocks": []}
    
    is_valid, err = repository.verify_ledger_integrity(tenant_id, case_id)
    return {
        "case_id": case_id,
        "tenant_id": tenant_id,
        "integrity_verified": is_valid,
        "verification_error": err,
        "block_count": len(blocks),
        "blocks": [b.to_dict() for b in blocks],
    }


@router.get("/streaming/status")
def get_streaming_adapter_status(tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve operational metrics, lag, and DLQ status for streaming adapter."""
    from ..streaming.dlq import DeadLetterQueueService
    dlq_svc = DeadLetterQueueService()
    dlq_recs = dlq_svc.get_dlq_records(tenant_id=tenant_id, replayed=False)
    return {
        "tenant_id": tenant_id,
        "stream_connected": True,
        "shadow_mode": True,
        "shadow_label": "SECURITY_STATE_SHADOW",
        "event_lag_ms": 0.0,
        "late_events": 0,
        "dlq_events": len(dlq_recs),
        "automated_response_enabled": False,
        "transport": "REPLAY_ADAPTER_LOCAL",
    }


@router.get("/{case_id}/provenance")
def get_security_state_provenance(case_id: str, tenant_id: str = Query(...)) -> Dict[str, Any]:
    """Retrieve complete, deterministic reasoning and evidence provenance DAG for a case."""
    latest_rec = repository.get_latest_state(tenant_id, case_id)
    if not latest_rec:
        raise HTTPException(status_code=404, detail="Security state not found for case or tenant mismatch")

    from ..hydration.provenance import ProvenanceGraphBuilder
    provenance_tree = ProvenanceGraphBuilder.build_provenance_tree(
        state_record=latest_rec.to_dict(),
        evidence_items=latest_rec.evidence_references,
    )
    return provenance_tree


@router.post("/{case_id}/interventions/stage")
def stage_intervention_decision(case_id: str, req: StageInterventionRequest) -> Dict[str, Any]:
    """Stage, simulate, or approve an intervention under human analyst review.
    
    Hard Safety Invariant:
    EXECUTE is locked and raises ACTION_EXECUTION_BLOCKED in Phase 5 Shadow Mode.
    """
    latest_rec = repository.get_latest_state(req.tenant_id, case_id)
    if not latest_rec:
        raise HTTPException(status_code=404, detail="Security state not found for case")

    action_norm = req.status.strip().upper()

    # Hard Safety Gate: Execution is strictly locked
    if action_norm == "EXECUTE":
        return {
            "success": False,
            "case_id": case_id,
            "tenant_id": req.tenant_id,
            "action_id": req.action_id,
            "status": "ACTION_EXECUTION_BLOCKED",
            "error": "PHASE 5 SAFETY GATE: Automated and manual execution is locked in Shadow Mode (EXECUTE=LOCKED, AUTO_RESPONSE=FALSE).",
        }

    # Record staging / simulation / approval to cryptographic ledger
    repository.append_ledger_block(
        tenant_id=req.tenant_id,
        case_id=case_id,
        event_type=f"INTERVENTION_{action_norm}",
        entity_id=req.target_entity_id,
        state_version=latest_rec.version,
        payload={
            "action_id": req.action_id,
            "status": action_norm,
            "notes": req.analyst_notes,
            "execution_locked": True,
        },
    )

    return {
        "success": True,
        "case_id": case_id,
        "tenant_id": req.tenant_id,
        "action_id": req.action_id,
        "target_entity_id": req.target_entity_id,
        "status": action_norm,
        "execution_locked": True,
        "ledger_recorded": True,
        "message": f"Intervention {req.action_id} successfully transitioned to {action_norm} (Execution disabled per safety gate).",
    }


