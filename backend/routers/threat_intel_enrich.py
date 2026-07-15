"""Threat Intel Enrichment router — /api/threat-intel/*.

Endpoints
    GET  /api/threat-intel/config              admin — redacted config
    POST /api/threat-intel/config              admin — upsert keys/toggles
    POST /api/threat-intel/enrich              analyst — enrich one IOC
    POST /api/threat-intel/enrich-batch        analyst — enrich a list of IOCs
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin
from threat_intel_enrich import (
    get_config_redacted, save_config, enrich, detect_kind,
)


router = APIRouter()


class TIConfigIn(BaseModel):
    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    enable_virustotal: bool = False
    enable_otx: bool = False
    enable_abuseipdb: bool = False


class EnrichIn(BaseModel):
    value: str
    providers: Optional[List[str]] = None


class EnrichBatchIn(BaseModel):
    values: List[str]
    providers: Optional[List[str]] = None


@router.get("/threat-intel/config", tags=["threat-intel"])
async def get_ti_config(user=Depends(require_admin)):
    return {"config": await get_config_redacted(db)}


@router.post("/threat-intel/config", tags=["threat-intel"])
async def set_ti_config(body: TIConfigIn, user=Depends(require_admin)):
    updated = await save_config(db, body.model_dump(exclude_none=False))
    return {"ok": True, "config": updated}


@router.post("/threat-intel/enrich", tags=["threat-intel"])
async def enrich_one(body: EnrichIn, user=Depends(get_current_user)):
    return await enrich(db, body.value, providers=body.providers)


@router.post("/threat-intel/enrich-batch", tags=["threat-intel"])
async def enrich_batch(body: EnrichBatchIn, user=Depends(get_current_user)):
    limited = list(body.values or [])[:25]
    out: List[Dict[str, Any]] = []
    for v in limited:
        out.append(await enrich(db, v, providers=body.providers))
    return {"count": len(out), "results": out}
