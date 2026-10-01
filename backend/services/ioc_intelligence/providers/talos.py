"""Talos Intelligence — public IP blacklist provider.

Talos does not publish a keyed reputation API for community use;
their **public IP blacklist** at
https://talosintelligence.com/documents/ip-blacklist is a plain-text
newline-separated list refreshed hourly by Cisco.  We treat presence
in that list as a strong `malicious` signal (score = 0.8) and
absence as `clean` (score = 0.0).

Fully deterministic — no key required, no fabrication.  When the
Talos endpoint is unreachable we return an honest `error` result
so the analyst sees the miss.
"""
from __future__ import annotations
import os
import time
from typing import Optional

import httpx

from ..schema import ProviderResult, ProviderVerdict
from .base import error_result

name = "talos"
SUPPORTED_KINDS = {"ip"}

_ENDPOINT = os.environ.get(
    "TALOS_BLACKLIST_URL",
    "https://talosintelligence.com/documents/ip-blacklist",
)

# Lightweight in-process cache — the blacklist is ~2 MB and refreshed
# once an hour by Talos.  We refresh at most every 15 minutes.
_TTL_SECONDS = 15 * 60
_cache: dict = {"at": 0.0, "ips": None}


async def _blacklist(http: httpx.AsyncClient) -> Optional[set]:
    now = time.time()
    if _cache["ips"] is not None and (now - _cache["at"]) < _TTL_SECONDS:
        return _cache["ips"]
    try:
        r = await http.get(_ENDPOINT, timeout=8.0)
    except Exception:
        return None
    if r.status_code >= 400:
        return None
    ips = {ln.strip() for ln in r.text.splitlines()
              if ln.strip() and not ln.startswith("#")}
    _cache["at"]  = now
    _cache["ips"] = ips
    return ips


async def lookup(kind: str, value: str,
                    http: httpx.AsyncClient) -> ProviderResult:
    if kind != "ip":
        return error_result(name, "unsupported kind")
    ips = await _blacklist(http)
    if ips is None:
        return error_result(name, "talos blacklist unreachable")
    hit = value in ips
    return ProviderResult(
        verdict=ProviderVerdict(
            provider=name,
            verdict="malicious" if hit else "clean",
            detail=("listed on Talos public IP blacklist" if hit
                       else "not listed on Talos public IP blacklist"),
            source="live",
            score=0.8 if hit else 0.0,
        ),
    )
