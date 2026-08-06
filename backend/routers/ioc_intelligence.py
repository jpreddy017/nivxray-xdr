"""
IOC Intelligence · HTTP router (2026-03-02)
────────────────────────────────────────────
Analyst-facing enrichment endpoint.

    POST /api/ioc/enrich          { iocs: [{kind, value}, …] }
        → { results: [ IocCard, … ] }

    POST /api/ioc/enrich/one      { kind, value }
        → { card: IocCard }

Cache-first, parallel fan-out.  See services/ioc_intelligence for
the provider architecture.
"""
from __future__ import annotations
from typing import Any, Dict, List

from fastapi import APIRouter
from pydantic import BaseModel, Field

from services.ioc_intelligence import enrich_ioc, enrich_iocs

router = APIRouter(prefix="/ioc", tags=["ioc-intelligence"])


class IocIn(BaseModel):
    kind:  str = Field(..., description="hash · url · domain · ip")
    value: str


class EnrichBody(BaseModel):
    iocs:      List[IocIn]
    use_cache: bool = True


class EnrichOneBody(BaseModel):
    kind:      str
    value:     str
    use_cache: bool = True


@router.post("/enrich")
async def enrich_batch(body: EnrichBody) -> Dict[str, Any]:
    iocs = [{"kind": i.kind, "value": i.value} for i in body.iocs]
    cards = await enrich_iocs(iocs, use_cache=body.use_cache)
    return {"results": [c.to_dict() for c in cards]}


@router.post("/enrich/one")
async def enrich_single(body: EnrichOneBody) -> Dict[str, Any]:
    card = await enrich_ioc(body.kind, body.value, use_cache=body.use_cache)
    return {"card": card.to_dict()}
