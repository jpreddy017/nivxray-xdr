"""Analyst Workspace · L1 Investigation APIs (Blueprint §10).

Routes registered under ``/api``::

    POST   /api/investigation                                   create case from a bundle payload
    GET    /api/investigation                                   list cases (owner-scoped)
    GET    /api/investigation/{case_id}                         full workspace bundle (L2 workspace_bundle service)
    GET    /api/investigation/{case_id}/workspace               Workspace State (§8.3)
    PUT    /api/investigation/{case_id}/workspace               persist Workspace State (idempotent)
    POST   /api/investigation/{case_id}/state/transition        move case through §8.1 state machine
    GET    /api/investigation/{case_id}/summary                 executive_summary
    GET    /api/investigation/{case_id}/story                   attack_story
    GET    /api/investigation/{case_id}/iocs                    ioc_intelligence
    GET    /api/investigation/{case_id}/capabilities            capability_explorer
    GET    /api/investigation/{case_id}/threat                  threat_assessment
    GET    /api/investigation/{case_id}/detections              detection_rules
    GET    /api/investigation/{case_id}/hunting                 hunting_queries
    DELETE /api/investigation/{case_id}                         delete case (owner-scoped)

Determinism: every read endpoint returns the deterministic L2 service
output. Same case ⇒ same JSON body (proven in tests via fingerprint
comparison). Same request idempotent.

Auth: all endpoints require ``get_current_user`` (JWT). Owner scoping
is enforced on every access — a user may only view/mutate cases they
own. This mirrors the existing pattern in ``routers/cases.py``.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, status
from pydantic import BaseModel, Field

from deps import get_current_user, sync_collection
from l1_evidence.case_store import CaseNotFound, CaseStore
from l2_investigation.schemas import (
    CapabilityEvidence,
    EvidenceBundle,
    IocEvidence,
    MitreEvidence,
    SampleMetadata,
    TransformationEvidence,
)
from l2_investigation.services.attack_story import run as run_attack_story
from l2_investigation.services.capability_explorer import run as run_capability_explorer
from l2_investigation.services.detection_rules import run as run_detection_rules
from l2_investigation.services.executive_summary import run as run_executive_summary
from l2_investigation.services.hunting_queries import run as run_hunting_queries
from l2_investigation.services.ioc_intelligence import run as run_ioc_intelligence
from l2_investigation.services.threat_assessment import run as run_threat_assessment
from l2_investigation.services.workspace_bundle import run as run_workspace_bundle
from l2_investigation.state import (
    InvalidStateTransition,
    InvestigationState,
    STATE_ORDER,
)
from l2_investigation.workspace_state import (
    WorkspaceLens,
    WorkspaceMode,
    WorkspaceState,
)

router = APIRouter()

_STORE = CaseStore(sync_collection("investigation_cases"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _user_email(user: Any) -> str:
    if isinstance(user, dict):
        return user.get("email") or ""
    return getattr(user, "email", "") or ""


def _load(case_id: str, user: Any) -> Any:
    try:
        rec = _STORE.get(case_id)
    except CaseNotFound:
        raise HTTPException(status_code=404, detail=f"case_not_found:{case_id}")
    email = _user_email(user)
    if rec.owner_email != email:
        # Owner scoping (matches routers/cases.py pattern; SEC-003).
        raise HTTPException(status_code=403, detail="case_owner_mismatch")
    return rec


def _bundle_from_record(rec: Any) -> EvidenceBundle:
    b = rec.bundle
    return EvidenceBundle(
        case_id=b["case_id"],
        certificate=b.get("certificate") or {},
        canonical_output=b.get("canonical_output") or "",
        transformations=tuple(
            TransformationEvidence(
                iteration=int(t["iteration"]),
                pass_name=t["pass_name"],
                transformation=t["transformation"],
                changed=bool(t.get("changed", False)),
                before_hash=t.get("before_hash", ""),
                after_hash=t.get("after_hash", ""),
            )
            for t in b.get("transformations") or []
        ),
        iocs=tuple(
            IocEvidence(
                ioc_id=i["ioc_id"],
                ioc_type=i["ioc_type"],
                value=i["value"],
                source_iteration=int(i.get("source_iteration", 0)),
                source_span=tuple(i.get("source_span") or (0, 0)),  # type: ignore[arg-type]
                context=i.get("context", ""),
            )
            for i in b.get("iocs") or []
        ),
        capabilities=tuple(
            CapabilityEvidence(
                capability_id=c["capability_id"],
                display_name=c["display_name"],
                confidence=c.get("confidence", "high"),
                source_iterations=tuple(c.get("source_iterations") or ()),
            )
            for c in b.get("capabilities") or []
        ),
        mitre=tuple(
            MitreEvidence(
                technique_id=m["technique_id"],
                technique_name=m["technique_name"],
                tactic=m["tactic"],
                via_capability=m["via_capability"],
                source_iterations=tuple(m.get("source_iterations") or ()),
            )
            for m in b.get("mitre") or []
        ),
        sample=SampleMetadata(
            family=(b.get("sample") or {}).get("family", ""),
            technique=(b.get("sample") or {}).get("technique", ""),
            variant=(b.get("sample") or {}).get("variant", ""),
            sample_id=(b.get("sample") or {}).get("sample_id", ""),
        ),
    )


# ---------------------------------------------------------------------------
# Pydantic models (I/O envelopes)
# ---------------------------------------------------------------------------


class CreateCaseIn(BaseModel):
    """Case-creation payload. ``bundle`` is an EvidenceBundle dict.

    For PR-2, the analyst / client supplies the bundle directly (this
    surfaces every L2 service over HTTP without waiting on the PR-3
    L0→bundle bridge). The bundle must include at minimum a ``case_id``
    and a ``certificate`` field.
    """

    bundle: dict = Field(..., description="EvidenceBundle payload")
    mode: str = Field(
        default=WorkspaceMode.INVESTIGATION.value,
        description="Initial Workspace mode (quick_triage · investigation · deep_analysis)",
    )


class WorkspaceStateIn(BaseModel):
    mode: Optional[str] = None
    active_lens: Optional[str] = None
    scroll_positions: Optional[dict] = None
    selected_evidence_id: Optional[str] = None
    filters: Optional[dict] = None
    timeline_position: Optional[int] = None


class StateTransitionIn(BaseModel):
    target: str = Field(..., description="Target state value")
    reason: str = ""


# ---------------------------------------------------------------------------
# Create / list
# ---------------------------------------------------------------------------


@router.post("/investigation", tags=["investigation"], status_code=201)
async def create_case(body: CreateCaseIn, user=Depends(get_current_user)):
    b = dict(body.bundle or {})
    case_id = b.get("case_id") or f"case-{uuid.uuid4().hex[:12]}"
    b["case_id"] = case_id

    try:
        mode = WorkspaceMode(body.mode)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid_mode:{body.mode}")

    workspace = WorkspaceState.initial(case_id, mode=mode).to_dict()

    if _STORE.exists(case_id):
        raise HTTPException(status_code=409, detail=f"case_exists:{case_id}")

    rec = _STORE.create(
        case_id=case_id,
        owner_email=_user_email(user),
        bundle=b,
        workspace=workspace,
    )
    return {
        "case_id": rec.case_id,
        "state": rec.current_state.value,
        "workspace": rec.workspace,
    }


@router.get("/investigation", tags=["investigation"])
async def list_cases(user=Depends(get_current_user)):
    email = _user_email(user)
    recs = _STORE.list(owner_email=email)
    return {
        "cases": [
            {
                "case_id": r.case_id,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
                "state": r.current_state.value,
                "sample": r.bundle.get("sample", {}),
            }
            for r in recs
        ],
    }


# ---------------------------------------------------------------------------
# Workspace bundle (single-call hydration)
# ---------------------------------------------------------------------------


@router.get("/investigation/{case_id}", tags=["investigation"])
async def get_workspace_bundle(case_id: str, user=Depends(get_current_user)):
    rec = _load(case_id, user)
    bundle = _bundle_from_record(rec)
    out = run_workspace_bundle(bundle)
    return {
        "case_id": rec.case_id,
        "state": rec.current_state.value,
        "workspace": rec.workspace,
        "output": out.to_dict(),
        "fingerprint": out.fingerprint,
    }


# ---------------------------------------------------------------------------
# Per-service reads
# ---------------------------------------------------------------------------


_SERVICE_RUNNERS = {
    "summary": run_executive_summary,
    "story": run_attack_story,
    "iocs": run_ioc_intelligence,
    "capabilities": run_capability_explorer,
    "threat": run_threat_assessment,
    "detections": run_detection_rules,
    "hunting": run_hunting_queries,
}


def _service_endpoint(path: str):
    runner = _SERVICE_RUNNERS[path]

    async def endpoint(case_id: str, user=Depends(get_current_user)):
        rec = _load(case_id, user)
        bundle = _bundle_from_record(rec)
        out = runner(bundle)
        return out.to_dict() | {"fingerprint": out.fingerprint}

    endpoint.__name__ = f"get_{path}"
    return endpoint


for _path in _SERVICE_RUNNERS:
    router.add_api_route(
        f"/investigation/{{case_id}}/{_path}",
        _service_endpoint(_path),
        methods=["GET"],
        tags=["investigation"],
    )


# ---------------------------------------------------------------------------
# Workspace State (Blueprint §8.3)
# ---------------------------------------------------------------------------


@router.get("/investigation/{case_id}/workspace", tags=["investigation"])
async def get_workspace_state(case_id: str, user=Depends(get_current_user)):
    rec = _load(case_id, user)
    return rec.workspace


@router.put("/investigation/{case_id}/workspace", tags=["investigation"])
async def put_workspace_state(
    case_id: str,
    body: WorkspaceStateIn,
    user=Depends(get_current_user),
):
    rec = _load(case_id, user)
    current = WorkspaceState.from_dict(rec.workspace)
    patch: dict[str, Any] = {}
    if body.mode is not None:
        try:
            patch["mode"] = WorkspaceMode(body.mode)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"invalid_mode:{body.mode}")
    if body.active_lens is not None:
        try:
            patch["active_lens"] = WorkspaceLens(body.active_lens)
        except ValueError:
            raise HTTPException(
                status_code=400, detail=f"invalid_lens:{body.active_lens}"
            )
    if body.scroll_positions is not None:
        patch["scroll_positions"] = dict(body.scroll_positions)
    if body.selected_evidence_id is not None:
        patch["selected_evidence_id"] = body.selected_evidence_id
    if body.filters is not None:
        patch["filters"] = dict(body.filters)
    if body.timeline_position is not None:
        patch["timeline_position"] = int(body.timeline_position)

    from dataclasses import replace

    updated = replace(current, **patch)
    _STORE.update_workspace(case_id, updated.to_dict())
    return updated.to_dict() | {"fingerprint": updated.fingerprint}


# ---------------------------------------------------------------------------
# State machine transitions (Blueprint §8.1)
# ---------------------------------------------------------------------------


@router.post("/investigation/{case_id}/state/transition", tags=["investigation"])
async def transition_state(
    case_id: str,
    body: StateTransitionIn,
    user=Depends(get_current_user),
):
    rec = _load(case_id, user)
    try:
        target = InvestigationState(body.target)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"invalid_state:{body.target}")

    try:
        new_rec, entry = _STORE.transition_state(
            case_id=case_id,
            target=target,
            actor=_user_email(user) or "system",
            reason=body.reason or "",
        )
    except InvalidStateTransition as ex:
        raise HTTPException(status_code=409, detail=str(ex))

    return {
        "case_id": new_rec.case_id,
        "current_state": new_rec.current_state.value,
        "transition": entry.to_dict(),
        "history": new_rec.state_history,
    }


@router.get("/investigation/{case_id}/state", tags=["investigation"])
async def get_state(case_id: str, user=Depends(get_current_user)):
    rec = _load(case_id, user)
    return {
        "case_id": rec.case_id,
        "current_state": rec.current_state.value,
        "history": rec.state_history,
        "allowed_states": [s.value for s in STATE_ORDER],
    }


# ---------------------------------------------------------------------------
# Delete (dev / cleanup only — owner-scoped)
# ---------------------------------------------------------------------------


@router.delete("/investigation/{case_id}", tags=["investigation"], status_code=204)
async def delete_case(case_id: str, user=Depends(get_current_user)):
    rec = _load(case_id, user)  # 403 / 404 as needed
    _STORE.delete(rec.case_id)
    return None


__all__ = ["router"]
