"""SANS Internet Storm Center · DShield — public top-attackers feed.

DShield publishes a keyless JSON of the top attacker IPs by report
count over the last 24h at
https://isc.sans.edu/api/sources/attacks/50/json .

We treat presence in that list as a `suspicious` (0.5) signal
scaled by report volume; absence is `clean` with score 0.
"""
from __future__ import annotations
import os
import time
from typing import Optional

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import error_result

name = "dshield"
SUPPORTED_KINDS = {"ip"}

_ENDPOINT = os.environ.get(
    "DSHIELD_TOP_ATTACKERS_URL",
    "https://isc.sans.edu/api/sources/attacks/1000/json",
)

_TTL_SECONDS = 15 * 60
_cache: dict = {"at": 0.0, "by_ip": None}


async def _top_attackers(http: httpx.AsyncClient) -> Optional[dict]:
    now = time.time()
    if _cache["by_ip"] is not None and (now - _cache["at"]) < _TTL_SECONDS:
        return _cache["by_ip"]
    try:
        r = await http.get(_ENDPOINT, timeout=8.0,
                                 headers={"User-Agent": "NivXRay/1.0"})
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    try:
        payload = r.json()
    except Exception:
        return None
    rows = payload if isinstance(payload, list) else payload.get("data") or []
    by_ip: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = row.get("source") or row.get("ipv4") or row.get("ip")
        if not ip:
            continue
        by_ip[ip] = int(row.get("attacks") or row.get("reports") or 1)
    _cache["at"]    = now
    _cache["by_ip"] = by_ip
    return by_ip


async def lookup(kind: str, value: str,
                    http: httpx.AsyncClient) -> ProviderResult:
    if kind != "ip":
        return error_result(name, "unsupported kind")
    table = await _top_attackers(http)
    if table is None:
        return error_result(name, "dshield unreachable")
    reports = table.get(value)
    if reports:
        # Bounded 0.5–0.9 by log scale of report count.
        import math
        score = min(0.9, 0.5 + math.log10(max(reports, 10)) / 10)
        return ProviderResult(
            verdict=ProviderVerdict(
                provider=name,
                verdict="suspicious",
                detail=f"{reports} attack reports in the last 24h "
                          "(DShield top-attackers feed)",
                source="live",
                score=round(score, 2),
            ),
        )
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name,
            verdict="clean",
            detail="not in DShield top-attackers feed",
            source="live", score=0.0,
        ),
    )
