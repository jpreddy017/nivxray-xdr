"""VirusTotal & AbuseIPDB stubs — return `pending` unless keys present.

Both providers require API keys.  We surface them in the sources list
so the analyst KNOWS they were consulted (but pending) instead of
silently omitting them.  When VT_API_KEY / ABUSEIPDB_API_KEY are set
in the backend .env, we upgrade the stub to a live call.
"""
from __future__ import annotations
import os
from typing import Any, Dict

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import pending_result, error_result

name_vt = "virustotal"
name_ai = "abuseipdb"

_VT_ENDPOINT = "https://www.virustotal.com/api/v3/{kind_path}/{value}"


async def lookup_virustotal(kind: str, value: str,
                              http: httpx.AsyncClient) -> ProviderResult:
    key = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
    if not key:
        return pending_result(name_vt,
                                "VirusTotal API key not configured "
                                "(VT_API_KEY in backend/.env)")

    kind_path = {"hash": "files", "url": "urls",
                  "domain": "domains", "ip": "ip_addresses"}.get(kind)
    if not kind_path:
        return pending_result(name_vt, "unsupported kind")

    # URL IOCs need to be base64-url encoded per VT v3 spec.
    lookup_value = value
    if kind == "url":
        import base64
        lookup_value = base64.urlsafe_b64encode(value.encode("utf-8")) \
                             .rstrip(b"=").decode("ascii")
    try:
        r = await http.get(
            _VT_ENDPOINT.format(kind_path=kind_path, value=lookup_value),
            headers={"x-apikey": key}, timeout=8.0,
        )
    except Exception as e:
        return error_result(name_vt, f"{type(e).__name__}: {e!s}")

    if r.status_code == 404:
        return ProviderResult(
            verdict=ProviderVerdict(provider=name_vt, verdict="clean",
                                       detail="not indexed", source="live",
                                       score=0.0),
        )
    if r.status_code >= 400:
        return error_result(name_vt, f"HTTP {r.status_code}")

    try:
        payload: Dict[str, Any] = r.json()
    except Exception as e:
        return error_result(name_vt, f"non-JSON: {e!s}")

    attrs = (payload.get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    mal   = int(stats.get("malicious") or 0)
    susp  = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) or 1
    verdict = "malicious" if mal >= 5 else \
                "suspicious" if (mal + susp) >= 3 else \
                "clean"
    score = min(1.0, (mal * 1.0 + susp * 0.5) / max(total, 1))
    families = list((attrs.get("popular_threat_classification") or {})
                     .get("popular_threat_name") or [])
    families = [f.get("value") for f in families if isinstance(f, dict) and f.get("value")]

    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name_vt, verdict=verdict,
            detail=f"{mal}/{total} malicious",
            source="live", score=score,
        ),
        first_seen=attrs.get("first_submission_date_iso"),
        last_seen=attrs.get("last_analysis_date_iso"),
        families=families,
    )


async def lookup_abuseipdb(kind: str, value: str,
                             http: httpx.AsyncClient) -> ProviderResult:
    if kind != "ip":
        return pending_result(name_ai, "unsupported kind")
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        return pending_result(name_ai,
                                "AbuseIPDB API key not configured")
    try:
        r = await http.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=8.0,
        )
    except Exception as e:
        return error_result(name_ai, f"{type(e).__name__}: {e!s}")
    if r.status_code >= 400:
        return error_result(name_ai, f"HTTP {r.status_code}")
    try:
        data = (r.json() or {}).get("data") or {}
    except Exception as e:
        return error_result(name_ai, f"non-JSON: {e!s}")
    score = int(data.get("abuseConfidenceScore") or 0) / 100.0
    verdict = "malicious" if score >= 0.6 else "suspicious" if score >= 0.3 else "clean"
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name_ai, verdict=verdict,
            detail=f"confidence {int(score*100)}%",
            source="live", score=score,
        ),
        last_seen=data.get("lastReportedAt"),
    )
