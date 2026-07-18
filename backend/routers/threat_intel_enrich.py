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
    # v1.5.3 — route through the full osint.enrich_iocs so ALL 9 providers
    # fire (VT, AbuseIPDB, Shodan, GreyNoise, URLScan, OTX, IPinfo, Hybrid
    # Analysis, abuse.ch). Keys are pulled from the admin-panel-managed
    # `settings.osint_keys` doc via `load_osint_keys()`.
    from osint import enrich_iocs
    from deps import load_osint_keys as _load_osint_keys
    keys = await _load_osint_keys()
    # Bucket the single value by kind for enrich_iocs signature
    from threat_intel_enrich import detect_kind
    kind = detect_kind(body.value)
    bucket = {"ips": [], "domains": [], "urls": [], "md5": [], "sha1": [], "sha256": []}
    kind_map = {"ip": "ips", "domain": "domains", "url": "urls",
                "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
    slot = kind_map.get(kind)
    if slot:
        bucket[slot].append(body.value)
    result = await enrich_iocs(bucket, keys, max_per_type=1)
    return {"value": body.value, "kind": kind, "results": result}


@router.post("/threat-intel/enrich-batch", tags=["threat-intel"])
async def enrich_batch(body: EnrichBatchIn, user=Depends(get_current_user)):
    """Batch-enrich a mixed list of IOCs (URL / IP / domain / hash).

    v1.5.3 — Uses the full `osint.enrich_iocs()` pipeline against ALL nine
    configured providers. Frontend reshapes into red/green pills.
    """
    from osint import enrich_iocs
    from deps import load_osint_keys as _load_osint_keys
    from threat_intel_enrich import detect_kind
    keys = await _load_osint_keys()
    limited = list(body.values or [])[:25]
    # Bucket by kind
    bucket = {"ips": [], "domains": [], "urls": [], "md5": [], "sha1": [], "sha256": []}
    kind_map = {"ip": "ips", "domain": "domains", "url": "urls",
                "md5": "md5", "sha1": "sha1", "sha256": "sha256"}
    for v in limited:
        kind = detect_kind(v)
        slot = kind_map.get(kind)
        if slot:
            bucket[slot].append(v)
    result = await enrich_iocs(bucket, keys, max_per_type=len(limited) or 25)

    # Flatten to a list the UI can render as pills. Each item has:
    #   value, kind, malicious_score (VT), abuse_confidence (AbuseIPDB),
    #   otx_pulses, providers (raw sub-dict), status
    flat: List[Dict[str, Any]] = []
    def _stat(x):
        return {"ok", "found"}.intersection([(x or {}).get("status")]) and "ok" or (x or {}).get("status")
    for kind_bucket in ("ips", "domains", "urls", "hashes"):
        for row in (result.get(kind_bucket) or []):
            providers = {}
            for k, v in (row or {}).items():
                if isinstance(v, dict):
                    providers[k] = v
            vt = providers.get("virustotal") or {}
            ab = providers.get("abuseipdb") or {}
            otx = providers.get("otx") or {}
            malicious_score = (vt.get("malicious") or 0) + (vt.get("suspicious") or 0)
            abuse_confidence = ab.get("abuse_confidence_score") or ab.get("abuseConfidenceScore") or 0
            otx_pulses = (otx.get("pulse_count") if isinstance(otx.get("pulse_count"), int)
                          else len(otx.get("pulses") or []))
            flat.append({
                "value":            row.get("value"),
                "kind":             kind_bucket[:-1] if kind_bucket != "hashes" else "hash",
                "malicious_score":  malicious_score,
                "abuse_confidence": abuse_confidence,
                "otx_pulses":       otx_pulses,
                "providers":        providers,
            })
    return {"count": len(flat), "results": flat, "sources_used": result.get("sources_used") or []}
