]633;E;{ echo 'from fastapi import APIRouter, Depends, HTTPException'\x3b echo 'from deps import get_current_user'\x3b echo 'from routers.edr_tenancy import edr_scope, edr_tenant'\x3b sed -n '/^board_router =/,/^class SnapshotBody/{ /^class SnapshotBody/!p\x3b }' /app/backend/routers/edr_forensics.py\x3b } >backend/routers/edr_dashboard.py\x3b sed -i '/^app.include_router(api)/i from routers.edr_dashboard import board_router\x0aapi.include_router(board_router)' backend/server.py\x3b cat backend/routers/edr_dashboard.py |head -14\x3b tail -6 /tmp/edr-release-test2.log\x3b git status --short |tail -12;d98f63a2-d852-4206-85e7-966050773020]633;Cfrom fastapi import APIRouter, Depends, HTTPException
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


