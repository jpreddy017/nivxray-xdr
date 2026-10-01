"""URLhaus provider (abuse.ch) · URL / domain reputation."""
from __future__ import annotations
import os
from typing import Any, Dict
from urllib.parse import urlparse

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import pending_result, error_result, unknown_result

name = "urlhaus"
SUPPORTED_KINDS = ("url", "domain")

_ENDPOINT_URL    = "https://urlhaus-api.abuse.ch/v1/url/"
_ENDPOINT_HOST   = "https://urlhaus-api.abuse.ch/v1/host/"


async def lookup(kind: str, value: str,
                   http: httpx.AsyncClient) -> ProviderResult:
    key = os.environ.get("ABUSE_CH_AUTH_KEY") or os.environ.get("URLHAUS_KEY")
    headers: Dict[str, str] = {}
    if key:
        headers["Auth-Key"] = key

    if kind == "url":
        endpoint = _ENDPOINT_URL
        data     = {"url": value}
    elif kind == "domain":
        endpoint = _ENDPOINT_HOST
        data     = {"host": _hostpart(value)}
    else:
        return unknown_result(name, "unsupported kind")

    try:
        r = await http.post(endpoint, data=data, headers=headers, timeout=8.0)
    except Exception as e:
        return error_result(name, f"{type(e).__name__}: {e!s}")

    if r.status_code in (401, 403):
        return pending_result(name, "URLhaus auth key required")
    if r.status_code >= 400:
        return error_result(name, f"HTTP {r.status_code}")

    try:
        payload: Dict[str, Any] = r.json()
    except Exception as e:
        return error_result(name, f"non-JSON: {e!s}")

    status = (payload.get("query_status") or "").lower()
    if status == "no_results":
        return ProviderResult(
            verdict=ProviderVerdict(provider=name, verdict="clean",
                                       detail="not indexed in URLhaus",
                                       source="live", score=0.0),
        )
    if status != "ok":
        if "auth" in status:
            return pending_result(name, "URLhaus auth key required")
        return unknown_result(name, status or "unknown status")

    threat        = payload.get("threat") or ""
    tags          = list(payload.get("tags") or [])
    date_added    = payload.get("date_added") or payload.get("firstseen") or None
    last_online   = payload.get("last_online") or None
    payloads      = payload.get("payloads") or []
    families      = [p.get("signature") for p in payloads if p.get("signature")]

    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name, verdict="malicious",
            detail=f"threat={threat or 'malware'} · {len(payloads)} payload(s)",
            source="live", score=1.0,
        ),
        first_seen=date_added,
        last_seen=last_online or date_added,
        families=families,
        threat_types=[threat] if threat else [],
        tags=tags,
        related_hashes=[p.get("response_sha256") for p in payloads
                          if p.get("response_sha256")],
        references=[payload.get("urlhaus_reference")]
                     if payload.get("urlhaus_reference") else [],
    )


def _hostpart(v: str) -> str:
    v = (v or "").strip()
    if "://" in v:
        try:
            return urlparse(v).hostname or v
        except Exception:
            return v
    return v.split("/", 1)[0]
