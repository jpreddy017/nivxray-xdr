"""Collector resource scope comes from authentication, never a route header."""
from fastapi import HTTPException, Request


def tenant_scope(request: Request) -> str:
    tenant = getattr(request.state, 'collector_tenant_id', None)
    if not tenant:
        raise HTTPException(403, detail={'code': 'AUTHENTICATED_TENANT_REQUIRED'})
    return tenant


async def bind_scope(request: Request, tenant: str) -> None:
    """Reject conflicting compatibility claims before any route side effect."""
    claims = []
    for key in ('X-Tenant-Id', 'X-Authenticated-Tenant'):
        claims.extend(request.headers.getlist(key))
    for key in ('tenant_id', 'tenant'):
        claims.extend(request.query_params.getlist(key))
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        try:
            body = await request.json()
        except (ValueError, UnicodeDecodeError):
            body = None  # Framework/body-model validation remains authoritative.
        if isinstance(body, dict):
            claims.extend(body[k] for k in ('tenant_id', 'tenant') if k in body)
    if any(not isinstance(value, str) or value.strip() != tenant for value in claims):
        raise HTTPException(403, detail={'code': 'TENANT_ASSERTION_MISMATCH'})
    request.state.collector_tenant_id = tenant


def owned_connector(request: Request, cid: str):
    rec = request.app.state.store.get(cid)
    if rec is None or rec.tenant_id != tenant_scope(request):
        raise HTTPException(404, detail={'error': 'connector_not_found'})
    return rec
