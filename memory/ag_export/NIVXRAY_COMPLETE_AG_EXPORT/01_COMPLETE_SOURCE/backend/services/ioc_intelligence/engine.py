"""
IOC Intelligence Engine · orchestrator (2026-03-02)
────────────────────────────────────────────────────
Parallel fan-out across every registered provider, cache-first,
consensus-aggregated.  Deterministic key + safe degradation:
provider failures never break the card — they show up as "pending"
or "error" evidence bullets.
"""
from __future__ import annotations
import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from .cache      import get as cache_get, set as cache_set
from .consensus  import build_card
from .schema     import IocCard, ProviderResult

from .providers import malwarebazaar, threatfox, urlhaus, urlscan, hybrid_analysis
from .providers import talos, dshield
from .providers.virustotal_abuseipdb import (
    lookup_virustotal, lookup_abuseipdb,
)


# ══════════════════════════════════════════════════════════════════
# 1. Provider registry
# ══════════════════════════════════════════════════════════════════
# Each entry: (name, coroutine, {supported_kinds}).  Coroutines are
# `async def fn(kind, value, http) -> ProviderResult`.  Provider names
# must match the weights table in consensus._WEIGHTS.
_PROVIDERS: List[Tuple[str, Any, set]] = [
    (malwarebazaar.name,   malwarebazaar.lookup,   set(malwarebazaar.SUPPORTED_KINDS)),
    (threatfox.name,       threatfox.lookup,       set(threatfox.SUPPORTED_KINDS)),
    (urlhaus.name,         urlhaus.lookup,         set(urlhaus.SUPPORTED_KINDS)),
    (urlscan.name,         urlscan.lookup,         set(urlscan.SUPPORTED_KINDS)),
    (hybrid_analysis.name, hybrid_analysis.lookup, set(hybrid_analysis.SUPPORTED_KINDS)),
    (talos.name,           talos.lookup,           set(talos.SUPPORTED_KINDS)),
    (dshield.name,         dshield.lookup,         set(dshield.SUPPORTED_KINDS)),
    ("virustotal",         lookup_virustotal,      {"hash", "url", "domain", "ip"}),
    ("abuseipdb",          lookup_abuseipdb,       {"ip"}),
]


# ══════════════════════════════════════════════════════════════════
# 2. Normalisation
# ══════════════════════════════════════════════════════════════════
def _normalize(kind: str, value: str) -> str:
    if not value: return ""
    v = value.strip()
    k = kind.lower()
    if k == "hash":
        return v.lower()
    if k == "url":
        # Defang common analyst notations before hitting providers.
        return (v.replace("hxxp", "http")
                  .replace("[.]", ".")
                  .replace("[:]", ":"))
    if k == "domain":
        return v.lower().replace("[.]", ".").strip(".")
    if k == "ip":
        return v.replace("[.]", ".")
    return v


# ══════════════════════════════════════════════════════════════════
# 3. Public entry points
# ══════════════════════════════════════════════════════════════════
async def enrich_ioc(kind: str, value: str,
                       use_cache: bool = True) -> IocCard:
    """Enrich a single IOC.  Returns an IocCard (never raises)."""
    normalized = _normalize(kind, value)
    if use_cache:
        cached = cache_get(kind, normalized)
        if cached is not None:
            card = IocCard(**{**cached, "from_cache": True})
            return card

    started = time.perf_counter()
    async with httpx.AsyncClient(follow_redirects=True) as http:
        results = await _fan_out(kind, normalized, http)

    fetched_at = datetime.now(timezone.utc).isoformat()
    duration   = int((time.perf_counter() - started) * 1000)
    card = build_card(kind=kind, value=value, normalized=normalized,
                        provider_results=results,
                        fetched_at=fetched_at, duration_ms=duration,
                        from_cache=False)
    if use_cache:
        cache_set(kind, normalized, card.to_dict())
    return card


async def enrich_iocs(iocs: Iterable[Dict[str, str]],
                        use_cache: bool = True) -> List[IocCard]:
    """Enrich a batch of IOCs concurrently (each provider still fans
    out per-IOC, so overall latency is dominated by the slowest
    provider on the slowest IOC)."""
    tasks = [enrich_ioc(i.get("kind") or "", i.get("value") or "", use_cache=use_cache)
              for i in iocs or [] if i.get("value")]
    if not tasks:
        return []
    return list(await asyncio.gather(*tasks, return_exceptions=False))


# ══════════════════════════════════════════════════════════════════
# 4. Fan-out
# ══════════════════════════════════════════════════════════════════
async def _fan_out(kind: str, value: str,
                     http: httpx.AsyncClient) -> List[ProviderResult]:
    coros: List[asyncio.Task] = []
    names:  List[str]         = []
    for name, fn, kinds in _PROVIDERS:
        if kind not in kinds:
            continue
        names.append(name)
        coros.append(asyncio.create_task(_safe(fn, kind, value, http, name)))
    if not coros:
        return []
    return list(await asyncio.gather(*coros))


async def _safe(fn, kind, value, http, name) -> ProviderResult:
    from .providers.base import error_result
    try:
        return await asyncio.wait_for(fn(kind, value, http), timeout=10.0)
    except asyncio.TimeoutError:
        return error_result(name, "timeout")
    except Exception as e:                                # pragma: no cover
        return error_result(name, f"{type(e).__name__}: {e!s}")
