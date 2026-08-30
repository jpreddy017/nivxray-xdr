from fastapi import APIRouter, HTTPException, Request

router = APIRouter(tags=["connectors"])


@router.get("/connectors")
def list_connectors(request: Request):
    """List every connector configured for the caller's tenant.

    Phase A: registry is empty; response is `NEVER CONNECTED`
    honestly with the list of source-types the framework CAN host
    once vendor adapters land.  The Admin UI reads this list to
    render its Data Sources / Integrations tables.
    """
    reg = request.app.state.registry
    return {
        "connectors":   [c.describe() for c in reg.all()],
        "source_types": reg.source_types(),
        "phase":        "A",
        "note":         "Framework skeleton · no vendor adapters registered yet.",
    }


@router.get("/connectors/{identity}")
def get_connector(identity: str, request: Request):
    reg = request.app.state.registry
    c = reg.get(identity)
    if not c:
        raise HTTPException(404, detail={"error": "connector_not_found",
                                              "identity": identity})
    return c.describe()


@router.post("/connectors/{identity}/test")
async def test_connector(identity: str, request: Request):
    reg = request.app.state.registry
    c = reg.get(identity)
    if not c:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    return await c.test_connection()


@router.post("/connectors/{identity}/start")
async def start_connector(identity: str, request: Request):
    reg = request.app.state.registry
    c = reg.get(identity)
    if not c:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    await c.start()
    return {"ok": True, "identity": identity, "health": c.health.value}


@router.post("/connectors/{identity}/stop")
async def stop_connector(identity: str, request: Request):
    reg = request.app.state.registry
    c = reg.get(identity)
    if not c:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    await c.stop()
    return {"ok": True, "identity": identity, "health": c.health.value}
