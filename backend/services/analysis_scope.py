"""Strict analysis ownership, delegated to existing stored-principal authorities.

Headers/query values select a tenant; they never grant access or role authority.
No fallback owner or default tenant is introduced.
"""
from dataclasses import dataclass
from fastapi import HTTPException
from services.session_context import ScopeDenied, authorize_requested_tenant
from services.tenant_registry import TenantRegistryError, authoritative_required

@dataclass(frozen=True)
class AnalysisOwner:
    tenant_id: str
    principal_email: str


def resolve_analysis_owner(request, user) -> AnalysisOwner:
    email = (user or {}).get('email')
    if type(email) is not str or not email.strip():
        raise HTTPException(401, detail='ANALYSIS_IDENTITY_REQUIRED')
    claims = request.headers.getlist('x-tenant-id') + request.query_params.getlist('tenant_id')
    if any(not c.strip() for c in claims) or len(set(claims)) > 1:
        raise HTTPException(403, detail='ANALYSIS_SCOPE_DENIED')
    try:
        tenant, _ = authorize_requested_tenant(email, claims[0] if claims else None)
        tenant = authoritative_required(tenant, purpose='analysis.ownership')
    except ScopeDenied as exc:
        raise HTTPException(exc.http, detail=exc.detail()) from exc
    except TenantRegistryError as exc:
        raise HTTPException(exc.http, detail=exc.detail()) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, detail='ANALYSIS_AUTHORITY_UNAVAILABLE') from exc
    return AnalysisOwner(tenant, email)
