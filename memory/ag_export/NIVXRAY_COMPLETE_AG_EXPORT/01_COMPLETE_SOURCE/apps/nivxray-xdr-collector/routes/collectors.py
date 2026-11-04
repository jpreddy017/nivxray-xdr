from fastapi import APIRouter, Request
import os, platform, socket

router = APIRouter(tags=["collectors"])


def _self_identity() -> dict:
    return {
        "collector_id":  os.environ.get("XDR_COLLECTOR_ID", "collector-local"),
        "version":       "0.1.0-phaseA",
        "runtime":       f"python-{platform.python_version()}",
        "host":          socket.gethostname(),
        "status":        "healthy",
        "active_connectors": 0,
        "events_processed":  0,
        "errors":            0,
        "last_heartbeat":    None,
    }


@router.get("/collectors")
def list_collectors(request: Request):
    """Return this collector's own identity + status.

    Phase A: only one collector runtime is defined (this process).
    Multi-collector orchestration (leader election, fleet view) lands
    in Phase E.  The fleet field is `NOT AVAILABLE` today, never faked.
    """
    reg = request.app.state.registry
    me = _self_identity()
    me["active_connectors"] = len(reg.list_ids())
    return {
        "collectors": [me],
        "fleet":      "not_available",
        "phase":      "A",
    }


@router.get("/collectors/{collector_id}")
def get_collector(collector_id: str):
    me = _self_identity()
    if collector_id in (me["collector_id"], "self", "local"):
        return me
    return {"error": "collector_not_found", "id": collector_id}
