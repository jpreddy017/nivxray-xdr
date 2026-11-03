from fastapi import APIRouter, Depends
from deps import get_current_user
from routers.edr_tenancy import edr_scope, edr_tenant

board_router = APIRouter(prefix="/edr/dashboard", tags=["nivxforge-edr-dashboard"])


@board_router.get("/fleet")
async def dashboard_fleet(user: dict = Depends(get_current_user),
                          tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    from services.edr import dashboard as board_svc
    return {"ok": True, "tenant_id": tenant_id,
            "fleet": board_svc.fleet_status(tenant_id)}


@board_router.get("/board")
async def dashboard_board(start: str, end: str, sha256: str | None = None,
                          path_contains: str | None = None,
                          activity: str | None = None, limit: int = 100,
                          user: dict = Depends(get_current_user),
                          tenant_id: str = Depends(edr_tenant)) -> dict:
    edr_scope(tenant_id, user)
    from services.edr import dashboard as board_svc
    return board_svc.board(tenant_id, start=start, end=end, sha256=sha256,
                           path_contains=path_contains, activity=activity,
                           limit=limit)


