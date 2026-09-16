"""Hybrid Analysis (Falcon Sandbox) provider · hash / URL sample lookup."""
from __future__ import annotations
import os
from typing import Any, Dict

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import pending_result, error_result, unknown_result

name = "hybrid-analysis"
SUPPORTED_KINDS = ("hash",)      # URL search deprecated in 2.35.0+

_ENDPOINT_OVERVIEW = "https://hybrid-analysis.com/api/v2/overview/{sha}"


async def lookup(kind: str, value: str,
                   http: httpx.AsyncClient) -> ProviderResult:
    key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
    if not key:
        return pending_result(name, "Hybrid Analysis API key not configured")
    if kind != "hash":
        return unknown_result(name, "unsupported kind (only sha256)")

    headers = {
        "api-key":    key,
        "user-agent": "Falcon Sandbox",
        "accept":     "application/json",
    }

    try:
        r = await http.get(
            _ENDPOINT_OVERVIEW.format(sha=value),
            headers=headers, timeout=8.0,
        )
    except Exception as e:
        return error_result(name, f"{type(e).__name__}: {e!s}")

    if r.status_code in (401, 403):
        return pending_result(name, "Hybrid Analysis API key rejected")
    if r.status_code == 404:
        return ProviderResult(
            verdict=ProviderVerdict(provider=name, verdict="clean",
                                       detail="no sample",
                                       source="live", score=0.0),
        )
    if r.status_code >= 400:
        return error_result(name, f"HTTP {r.status_code}")

    try:
        row: Dict[str, Any] = r.json() or {}
    except Exception as e:
        return error_result(name, f"non-JSON: {e!s}")

    if not row.get("sha256"):
        return ProviderResult(
            verdict=ProviderVerdict(provider=name, verdict="clean",
                                       detail="no sample",
                                       source="live", score=0.0),
        )

    threat_score = int(row.get("threat_score") or 0)          # 0..100
    verdict_str  = (row.get("verdict") or "").lower()
    scanners     = row.get("scanners") or []
    positives    = int(row.get("scanners_v2_positives")
                          or sum(1 for s in scanners
                                  if (s.get("status") or "") == "malicious"))
    total        = int(row.get("scanners_v2_total") or len(scanners) or 0) or 1
    ratio        = positives / total if total else 0.0

    if verdict_str == "malicious" or threat_score >= 60 or ratio >= 0.4:
        v = "malicious"
    elif verdict_str == "suspicious" or threat_score >= 30 or ratio >= 0.15:
        v = "suspicious"
    elif verdict_str == "no specific threat":
        v = "clean"
    else:
        v = "unknown"

    score = min(1.0, max(threat_score / 100.0, ratio))
    detail = f"threat_score={threat_score} · {positives}/{total} scanners"
    if verdict_str:
        detail += f" · {verdict_str}"

    families = []
    for k in ("vx_family", "malware_family"):
        fv = row.get(k)
        if fv: families.append(fv)
    for cls in (row.get("classification") or []):
        if isinstance(cls, dict) and cls.get("name"):
            families.append(cls["name"])
    tags = list(row.get("tags") or [])
    first = row.get("first_seen") or row.get("last_seen")
    last  = row.get("last_seen")  or first

    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name, verdict=v, detail=detail,
            source="live", score=score,
        ),
        first_seen=first,
        last_seen=last,
        families=list(dict.fromkeys(families))[:6],
        tags=tags[:20],
        references=[f"https://hybrid-analysis.com/sample/{row['sha256']}/"],
    )
