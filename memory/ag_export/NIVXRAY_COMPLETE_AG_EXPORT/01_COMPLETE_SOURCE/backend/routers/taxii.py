"""TAXII 2.1 Push router — /api/admin/taxii/*.

Endpoints (admin-only)
    GET  /api/admin/taxii/config      — return current config (secrets redacted)
    POST /api/admin/taxii/config      — upsert config
    POST /api/admin/taxii/test        — hit discovery endpoint to verify connectivity
    POST /api/admin/taxii/push        — publish IOCs as STIX 2.1 objects
    GET  /api/admin/taxii/history     — recent push results
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import db, require_admin
from taxii import (
    get_config_redacted, save_config,
    test_connection, push_stix_bundle, list_push_log,
    build_stix_bundle,
)


router = APIRouter()


class TaxiiConfigIn(BaseModel):
    server_url: str = Field("", description="Base URL of the TAXII 2.1 server, e.g. https://otx.alienvault.com")
    collection_id: str = Field("", description="Collection UUID to publish to")
    api_root: str = Field("taxii2", description="API root path (default 'taxii2')")
    auth_type: str = Field("none", description="none | basic | bearer | header")
    username: Optional[str] = None
    password: Optional[str] = None
    token: Optional[str] = None
    auth_header_key: Optional[str] = None
    auth_header_value: Optional[str] = None
    verify_tls: bool = True
    identity_name: str = "NivXRay"


class TaxiiPushIn(BaseModel):
    iocs: Dict[str, List[str]] = Field(
        ..., description="IOC dict: {urls:[], ips:[], domains:[], md5:[], sha1:[], sha256:[], ...}"
    )
    description: str = Field("", description="Attached to every indicator")
    identity_name: Optional[str] = None


@router.get("/admin/taxii/config", tags=["admin"])
async def get_taxii_config(user=Depends(require_admin)):
    return {"config": await get_config_redacted(db)}


@router.post("/admin/taxii/config", tags=["admin"])
async def set_taxii_config(body: TaxiiConfigIn, user=Depends(require_admin)):
    updated = await save_config(db, body.model_dump(exclude_none=True))
    return {"ok": True, "config": updated}


@router.post("/admin/taxii/test", tags=["admin"])
async def test_taxii(user=Depends(require_admin)):
    return await test_connection(db)


@router.post("/admin/taxii/push", tags=["admin"])
async def push_taxii(body: TaxiiPushIn, user=Depends(require_admin)):
    bundle = build_stix_bundle(
        body.iocs,
        identity_name=body.identity_name or "NivXRay",
        description=body.description or "",
    )
    result = await push_stix_bundle(db, bundle)
    return {
        "ok": bool(result.get("ok")),
        "bundle_id": bundle.get("id"),
        "object_count": len(bundle.get("objects", [])),
        "result": result,
    }


@router.get("/admin/taxii/history", tags=["admin"])
async def taxii_history(limit: int = 50, user=Depends(require_admin)):
    events = await list_push_log(db, limit=limit)
    return {"events": events, "count": len(events)}
