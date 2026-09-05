"""HTTP surface for NivXRay XDR Intelligence Controls.

    GET  /api/intelligence/policy/global
    PUT  /api/intelligence/policy/global
    GET  /api/intelligence/policy/incident/{id}
    PUT  /api/intelligence/policy/incident/{id}
    DELETE /api/intelligence/policy/incident/{id}       — clear override
    GET  /api/intelligence/policy/incident/{id}/effective
    GET  /api/intelligence/policy/{scope}/{id}/history
    GET  /api/intelligence/health

RBAC (server-side, not just UI):
    intelligence_policy.read     — view
    intelligence_policy.update   — mutate global policy
    intelligence_policy.override — mutate incident override

Authorization is enforced through `require_permission(...)` — the
same dependency used by every other governed router in the app.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from deps import db
from routers.xdr_rbac import require_permission, _principal
from services.intelligence_policy import (
    IntelligencePolicy, IntelligencePolicyService,
    default_global_policy, default_incident_override,
    resolve_effective,
)
from services.intelligence_policy.service import (
    _offline_ai_health, _offline_llm_health,
)


router = APIRouter(prefix="/intelligence", tags=["intelligence"])


# ─── Request bodies ────────────────────────────────────────────────
class GlobalPolicyBody(BaseModel):
    online_ai:  Literal["on", "off"] = Field(...)
    online_llm: Literal["on", "off"] = Field(...)
    reason:     str | None = None


class IncidentPolicyBody(BaseModel):
    # None = inherit from global
    online_ai:  Literal["on", "off"] | None = None
    online_llm: Literal["on", "off"] | None = None
    reason:     str | None = None


# ─── Helpers ────────────────────────────────────────────────────────
def _svc() -> IntelligencePolicyService:
    return IntelligencePolicyService(db)


def _role_hint(request: Request) -> str:
    """Best-effort role name for audit; RBAC has already authorised the call."""
    return (request.headers.get("X-Principal-Role")
            or request.headers.get("X-Role") or "unknown")


def _global_payload(p: IntelligencePolicy) -> dict[str, Any]:
    return {
        "scope":          "global",
        "online_ai":      p.online_ai  or "on",
        "online_llm":     p.online_llm or "on",
        "offline_ai":     "on",
        "offline_llm":    "on",
        "nivxray_narration_engine": "on",
    }


def _incident_payload(
    p: IntelligencePolicy, tenant_id: str, incident_id: str,
) -> dict[str, Any]:
    return {
        "scope":       "incident_override",
        "tenant_id":   tenant_id,
        "incident_id": incident_id,
        "online_ai":   p.online_ai,        # may be null → inherit
        "online_llm":  p.online_llm,
        "offline_ai":     "on",
        "offline_llm":    "on",
        "nivxray_narration_engine": "on",
    }


# ─── Global policy ─────────────────────────────────────────────────
@router.get(
    "/policy/global",
    dependencies=[Depends(require_permission("intelligence_policy.read"))],
)
async def get_global_policy(request: Request):
    ten, _, _ = _principal(request)
    p = await _svc().get_global(ten)
    return _global_payload(p)


@router.put(
    "/policy/global",
    dependencies=[Depends(require_permission("intelligence_policy.update"))],
)
async def set_global_policy(request: Request, body: GlobalPolicyBody):
    ten, pid, _ = _principal(request)
    new_p = IntelligencePolicy(
        online_ai=body.online_ai, online_llm=body.online_llm)
    saved = await _svc().set_global(
        ten, new_p,
        changed_by=pid, changed_by_role=_role_hint(request),
        reason=body.reason,
    )
    return _global_payload(saved)


# ─── Incident override ─────────────────────────────────────────────
@router.get(
    "/policy/incident/{incident_id}",
    dependencies=[Depends(require_permission("intelligence_policy.read"))],
)
async def get_incident_policy(request: Request, incident_id: str):
    ten, _, _ = _principal(request)
    p = await _svc().get_incident(ten, incident_id)
    return _incident_payload(p, ten, incident_id)


@router.put(
    "/policy/incident/{incident_id}",
    dependencies=[Depends(require_permission("intelligence_policy.override"))],
)
async def set_incident_policy(
    request: Request, incident_id: str, body: IncidentPolicyBody,
):
    ten, pid, _ = _principal(request)
    new_p = IntelligencePolicy(
        online_ai=body.online_ai, online_llm=body.online_llm)
    saved = await _svc().set_incident(
        ten, incident_id, new_p,
        changed_by=pid, changed_by_role=_role_hint(request),
        reason=body.reason,
    )
    return _incident_payload(saved, ten, incident_id)


@router.delete(
    "/policy/incident/{incident_id}",
    dependencies=[Depends(require_permission("intelligence_policy.override"))],
)
async def clear_incident_override(request: Request, incident_id: str,
                                                                    reason: str | None = None):
    ten, pid, _ = _principal(request)
    cleared = await _svc().clear_incident_override(
        ten, incident_id,
        changed_by=pid, changed_by_role=_role_hint(request),
        reason=reason,
    )
    return _incident_payload(cleared, ten, incident_id)


# ─── Effective + snapshot ──────────────────────────────────────────
@router.get(
    "/policy/incident/{incident_id}/effective",
    dependencies=[Depends(require_permission("intelligence_policy.read"))],
)
async def get_incident_effective(request: Request, incident_id: str):
    ten, _, _ = _principal(request)
    eff = await _svc().effective_for_incident(ten, incident_id)
    g = await _svc().get_global(ten)
    return {
        "tenant_id":   ten,
        "incident_id": incident_id,
        "effective":   eff.to_dict(),
        "global":      _global_payload(g),
        "override":    _incident_payload(
            await _svc().get_incident(ten, incident_id), ten, incident_id),
    }


# ─── History ───────────────────────────────────────────────────────
@router.get(
    "/policy/{scope}/{scope_id}/history",
    dependencies=[Depends(require_permission("intelligence_policy.read"))],
)
async def policy_history(request: Request, scope: str, scope_id: str,
                                                   limit: int = 200):
    if scope not in ("global", "incident"):
        raise HTTPException(status_code=400,
                            detail={"code": "BAD_SCOPE",
                                            "allowed": ["global", "incident"]})
    ten, _, _ = _principal(request)
    return {
        "scope":    scope,
        "scope_id": scope_id,
        "history":  await _svc().history(ten, scope, scope_id, limit=limit),
    }


# ─── Health (public within the app) ────────────────────────────────
@router.get(
    "/health",
    dependencies=[Depends(require_permission("intelligence_policy.read"))],
)
async def intelligence_health():
    return {
        "offline_ai":  {"health": _offline_ai_health()},
        "offline_llm": {"health": _offline_llm_health()},
        "nivxray_narration_engine": {"health": "ready"},
    }
