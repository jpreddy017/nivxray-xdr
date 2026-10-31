"""ThreatFox provider (abuse.ch) · IOC → malware family / campaign."""
from __future__ import annotations
import os
from typing import Any, Dict

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import pending_result, error_result, unknown_result

name = "threatfox"
SUPPORTED_KINDS = ("hash", "domain", "url", "ip")

_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


async def lookup(kind: str, value: str,
                   http: httpx.AsyncClient) -> ProviderResult:
    key = os.environ.get("ABUSE_CH_AUTH_KEY") or os.environ.get("THREATFOX_KEY")
    headers: Dict[str, str] = {}
    if key:
        headers["Auth-Key"] = key

    try:
        r = await http.post(
            _ENDPOINT,
            json={"query": "search_ioc", "search_term": value, "exact_match": True},
            headers=headers,
            timeout=8.0,
        )
    except Exception as e:
        return error_result(name, f"{type(e).__name__}: {e!s}")

    if r.status_code in (401, 403):
        return pending_result(name, "ThreatFox auth key required")
    if r.status_code >= 400:
        return error_result(name, f"HTTP {r.status_code}")

    try:
        payload: Dict[str, Any] = r.json()
    except Exception as e:
        return error_result(name, f"non-JSON: {e!s}")

    status = (payload.get("query_status") or "").lower()
    if status == "no_result":
        return ProviderResult(
            verdict=ProviderVerdict(provider=name, verdict="clean",
                                      detail="no ThreatFox record",
                                      source="live", score=0.0),
        )
    if status != "ok":
        if "auth" in status:
            return pending_result(name, "ThreatFox auth key required")
        return unknown_result(name, status or "unknown status")

    data = payload.get("data") or []
    if not data:
        return unknown_result(name, "empty result")

    row = data[0]
    family    = row.get("malware_printable") or row.get("malware") or ""
    threat    = row.get("threat_type") or ""
    first     = row.get("first_seen") or None
    last      = row.get("last_seen")  or first
    tags      = list(row.get("tags") or [])
    families  = [family] if family else []

    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name, verdict="malicious",
            detail=f"family={family or 'unknown'} · {threat}",
            source="live", score=1.0,
            raw={"malware": family, "threat_type": threat},
        ),
        first_seen=first,
        last_seen=last,
        families=families,
        threat_types=[threat] if threat else [],
        tags=tags,
        references=[f"https://threatfox.abuse.ch/ioc/{row.get('id')}/"]
                     if row.get("id") else [],
    )
