"""Threat Intelligence Enrichment router — /api/enrichment/*."""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin
from enrichment import (
    get_config_redacted, save_config, enrich_ioc, enrich_iocs, classify_ioc,
)
from timeline import record as _tl_record


router = APIRouter()


class EnrichmentConfigIn(BaseModel):
    vt_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None
    abuseipdb_api_key: Optional[str] = None
    enable_vt: bool = True
    enable_otx: bool = True
    enable_abuseipdb: bool = True
    cache_ttl_hours: int = 24


class EnrichIocIn(BaseModel):
    value: str = Field(..., description="URL, IP, domain, MD5, SHA-1, or SHA-256")


class EnrichBulkIn(BaseModel):
    iocs: Dict[str, List[str]] = Field(
        default_factory=dict,
        description='e.g. {"urls":[...], "ips":[...], "sha256":[...]}',
    )
    input: Optional[str] = Field(
        None,
        description=(
            "If set, enrichment events are logged to the investigation "
            "identified by sha256(input)[:16]. Enables the timeline."
        ),
    )


@router.get("/enrichment/config", tags=["enrichment"])
async def config_get(user=Depends(require_admin)):
    return {"config": await get_config_redacted(db)}


@router.post("/enrichment/config", tags=["enrichment"])
async def config_set(body: EnrichmentConfigIn, user=Depends(require_admin)):
    payload = body.model_dump(exclude_none=True)
    cfg = await save_config(db, payload)
    return {"ok": True, "config": cfg}


@router.post("/enrichment/ioc", tags=["enrichment"])
async def enrich_one(body: EnrichIocIn, user=Depends(get_current_user)):
    return await enrich_ioc(db, body.value)


@router.post("/enrichment/bulk", tags=["enrichment"])
async def enrich_many(body: EnrichBulkIn, user=Depends(get_current_user)):
    result = await enrich_iocs(db, body.iocs or {})
    # If an investigation input was provided, log an aggregate event.
    if body.input:
        try:
            summary = result["summary"]
            malicious_iocs = [
                r["value"] for r in result["results"]
                if r["aggregate"]["verdict"] == "malicious"
            ][:20]
            await _tl_record(
                db,
                kind="enrichment",
                title=(
                    f"Enrichment: {summary.get('malicious', 0)} malicious · "
                    f"{summary.get('suspicious', 0)} suspicious · "
                    f"{summary.get('clean', 0)} clean · "
                    f"{summary.get('unknown', 0)} unknown"
                ),
                input_text=body.input,
                actor=user.get("email"),
                summary=(
                    "Malicious IOCs: " + ", ".join(malicious_iocs)
                    if malicious_iocs else
                    f"Checked {len(result['results'])} IOCs across enabled providers."
                ),
                metadata={
                    "summary": summary,
                    "ioc_count": len(result["results"]),
                    "malicious_iocs": malicious_iocs,
                },
                severity=(
                    "fail" if summary.get("malicious", 0) >= 1
                    else "warn" if summary.get("suspicious", 0) >= 1
                    else "success"
                ),
            )
        except Exception:
            pass
    return result


@router.get("/enrichment/classify", tags=["enrichment"])
async def classify(value: str, user=Depends(get_current_user)):
    return {"value": value, "kind": classify_ioc(value)}
