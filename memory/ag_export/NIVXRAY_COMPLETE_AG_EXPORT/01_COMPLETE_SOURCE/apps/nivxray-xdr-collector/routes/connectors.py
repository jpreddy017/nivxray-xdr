"""
Routes · connectors CRUD + control plane (Phase B).

Endpoints (all tenant-scoped via the X-Tenant-Id header; a proxy/
gateway in front of this service is responsible for populating it):

  GET    /api/xdr/source-types                 → catalogue
  GET    /api/xdr/connectors                   → list
  POST   /api/xdr/connectors                   → create (rest|webhook|syslog)
  GET    /api/xdr/connectors/{id}              → get
  PATCH  /api/xdr/connectors/{id}              → update config
  DELETE /api/xdr/connectors/{id}              → delete
  POST   /api/xdr/connectors/{id}/test         → dry-run
  POST   /api/xdr/connectors/{id}/start        → start scheduler / bind socket
  POST   /api/xdr/connectors/{id}/stop         → stop
  POST   /api/xdr/connectors/{id}/inject       → local test injection
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi   import APIRouter, HTTPException, Request, Header
from pydantic  import BaseModel, Field

from framework.rest_poller import RestPollerConnector
from framework.webhook     import WebhookConnector
from framework.syslog      import SyslogConnector


router = APIRouter(tags=["connectors"])


# ── request bodies ────────────────────────────────────────────
class ConnectorCreate(BaseModel):
    source_type: str = Field(..., description="rest | webhook | syslog")
    label:       str
    config:      Dict[str, Any] = Field(default_factory=dict)


class ConnectorUpdate(BaseModel):
    label:   Optional[str] = None
    config:  Optional[Dict[str, Any]] = None
    enabled: Optional[bool] = None


class InjectBody(BaseModel):
    payload: Any


SOURCE_CATALOGUE = [
    {
        "source_type":  "rest",
        "label":        "Generic REST Poller",
        "category":     "api",
        "transport":    "http",
        "config_schema": RestPollerConnector.configuration_schema,
        "capabilities": [c.value for c in RestPollerConnector.capabilities],
        "credentials":  ["token", "api_key", "username", "password"],
    },
    {
        "source_type":  "webhook",
        "label":        "Generic Webhook Receiver",
        "category":     "push",
        "transport":    "https",
        "config_schema": WebhookConnector.configuration_schema,
        "capabilities": [c.value for c in WebhookConnector.capabilities],
        "credentials":  ["hmac_secret"],
    },
    {
        "source_type":  "syslog",
        "label":        "Generic Syslog Receiver (RFC3164 / RFC5424)",
        "category":     "push",
        "transport":    "udp/tcp",
        "config_schema": SyslogConnector.configuration_schema,
        "capabilities": [c.value for c in SyslogConnector.capabilities],
        "credentials":  [],
    },
]


CLASS_BY_TYPE = {
    "rest":    RestPollerConnector,
    "webhook": WebhookConnector,
    "syslog":  SyslogConnector,
}


def _tenant(x_tenant_id: Optional[str]) -> str:
    return x_tenant_id or "default"


# ── catalogue ─────────────────────────────────────────────────
@router.get("/source-types")
def source_types() -> Dict[str, Any]:
    return {"source_types": SOURCE_CATALOGUE,
              "note": "Phase B · REST poller · webhook receiver · syslog collector"}


# ── list ──────────────────────────────────────────────────────
@router.get("/connectors")
def list_connectors(request: Request,
                     x_tenant_id: Optional[str] = Header(default=None)):
    tenant = _tenant(x_tenant_id)
    store  = request.app.state.store
    rows   = []
    for rec in store.list(tenant_id=tenant):
        inst = request.app.state.instances.get(rec.id)
        base = rec.redacted()
        base["runtime"] = inst.describe() if inst else {"health": "not_started"}
        rows.append(base)
    return {"connectors": rows, "count": len(rows), "phase": "B"}


# ── create ────────────────────────────────────────────────────
@router.post("/connectors", status_code=201)
async def create_connector(body: ConnectorCreate, request: Request,
                              x_tenant_id: Optional[str] = Header(default=None)):
    if body.source_type not in CLASS_BY_TYPE:
        raise HTTPException(400, detail={"error": "unknown_source_type",
                                              "known": list(CLASS_BY_TYPE.keys())})
    tenant = _tenant(x_tenant_id)
    store  = request.app.state.store
    rec    = store.create(tenant_id=tenant, source_type=body.source_type,
                              label=body.label, config=body.config)
    # instantiate live object (not started)
    cls   = CLASS_BY_TYPE[body.source_type]
    inst  = cls(tenant_id=tenant, config=body.config, identity=rec.id)
    request.app.state.instances[rec.id] = inst
    request.app.state.registry.register_instance(inst)
    return rec.redacted()


# ── get ───────────────────────────────────────────────────────
@router.get("/connectors/{cid}")
def get_connector(cid: str, request: Request):
    store = request.app.state.store
    rec   = store.get(cid)
    if not rec:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    inst = request.app.state.instances.get(cid)
    out  = rec.redacted()
    out["runtime"] = inst.describe() if inst else {"health": "not_started"}
    return out


# ── update ────────────────────────────────────────────────────
@router.patch("/connectors/{cid}")
async def update_connector(cid: str, body: ConnectorUpdate, request: Request):
    store = request.app.state.store
    rec   = store.get(cid)
    if not rec:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    changes = {}
    if body.label   is not None: changes["label"]   = body.label
    if body.config  is not None: changes["config"]  = body.config
    if body.enabled is not None: changes["enabled"] = body.enabled
    rec = store.update(cid, **changes)

    # rebuild live instance to pick up the new config
    inst = request.app.state.instances.get(cid)
    if inst:
        # stop before mutating
        runtime = request.app.state.runtime
        await runtime.stop(inst)
    cls = CLASS_BY_TYPE[rec.source_type]
    inst = cls(tenant_id=rec.tenant_id, config=rec.config, identity=rec.id)
    request.app.state.instances[cid] = inst
    request.app.state.registry.register_instance(inst)
    return rec.redacted()


# ── delete ────────────────────────────────────────────────────
@router.delete("/connectors/{cid}")
async def delete_connector(cid: str, request: Request):
    store = request.app.state.store
    inst  = request.app.state.instances.pop(cid, None)
    if inst is not None:
        await request.app.state.runtime.stop(inst)
    gone = store.delete(cid)
    if not gone:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    return {"ok": True, "deleted": cid}


# ── control · test / start / stop / inject ────────────────────
@router.post("/connectors/{cid}/test")
async def test_connector(cid: str, request: Request):
    inst = request.app.state.instances.get(cid)
    if not inst:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    return await inst.test_connection() if hasattr(inst, "test_connection") \
             else {"ok": False, "reason": "not_supported"}


@router.post("/connectors/{cid}/start")
async def start_connector(cid: str, request: Request):
    inst = request.app.state.instances.get(cid)
    if not inst:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    result = await request.app.state.runtime.start(inst)
    return {"ok": result.get("ok", True), "identity": cid,
              "health": inst.health.value, "detail": result}


@router.post("/connectors/{cid}/stop")
async def stop_connector(cid: str, request: Request):
    inst = request.app.state.instances.get(cid)
    if not inst:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    result = await request.app.state.runtime.stop(inst)
    return {"ok": True, "identity": cid, "health": inst.health.value, "detail": result}


@router.post("/connectors/{cid}/inject")
async def inject(cid: str, body: InjectBody, request: Request):
    """Test-plane: shove a synthetic payload through the connector's
    parser + dedup + delivery so operators can validate config without
    waiting on real vendor traffic.  Never callable in production ingress
    paths — it's guarded by the framework's `X-Debug-Inject: 1` header.
    """
    if request.headers.get("X-Debug-Inject") != "1":
        raise HTTPException(403, detail={"error": "inject_requires_debug_header"})
    inst = request.app.state.instances.get(cid)
    if not inst:
        raise HTTPException(404, detail={"error": "connector_not_found"})
    runtime = request.app.state.runtime
    envs    = await runtime.handle_inject(inst, body.payload)
    return {"ok": True, "delivered": [e.to_dict() for e in envs]}
