"""
P0 · Round 20 · OSINT Enrichment Cache
───────────────────────────────────────

**Deterministic, TTL-aware, provenance-preserving.**

Locked rule (PRD § Round 20):
    Recomputation MUST NOT repeatedly hit public feeds
    (VirusTotal / Talos / DShield / AbuseIPDB / URLscan) — and stale
    intelligence MUST NOT be presented as fresh.

Cache key:  (indicator, provider)
Value:      {verdict, score, detail, observed_at, fetched_at, ttl_s}

Callers MUST NOT bypass the cache. If a lookup is stale (>= TTL) the
next `fetch(...)` re-hits the upstream provider, records the fresh
observation, and refreshes the cache.  If the upstream call fails,
the LAST KNOWN value is returned WITH `is_stale=True` — never
fabricated.

Storage:  `xdr_osint_cache` collection.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any


COLLECTION = "xdr_osint_cache"

# TTL defaults per provider (seconds).  Every provider must have an
# entry; unknown providers use the DEFAULT_TTL_S.
_PROVIDER_TTL: dict[str, int] = {
    "talos":        6 * 3600,
    "dshield":      6 * 3600,
    "abuseipdb":    12 * 3600,
    "virustotal":   24 * 3600,
    "urlhaus":      6 * 3600,
    "urlscan":      12 * 3600,
    "threatfox":    6 * 3600,
    "malwarebazaar": 24 * 3600,
    "consensus":    3600,           # composed value expires quickly
}
DEFAULT_TTL_S = 6 * 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def ttl_for(provider: str) -> int:
    return _PROVIDER_TTL.get((provider or "").lower(), DEFAULT_TTL_S)


def _cache_id(indicator: str, provider: str) -> str:
    return f"{provider.lower()}::{indicator}"


async def read(db, indicator: str, provider: str) -> dict | None:
    """Return the cached entry with an added `is_stale` flag, or None
    if the cache doesn't hold this (indicator, provider)."""
    doc = await db[COLLECTION].find_one(
        {"id": _cache_id(indicator, provider)}, {"_id": 0})
    if not doc:
        return None
    fetched = doc.get("fetched_at")
    ttl_s   = int(doc.get("ttl_s") or ttl_for(provider))
    stale   = True
    if fetched:
        try:
            fdt = datetime.fromisoformat(fetched)
            stale = (_now() - fdt) >= timedelta(seconds=ttl_s)
        except ValueError:
            stale = True
    doc["is_stale"]  = stale
    doc["age_s"]     = int((_now() - datetime.fromisoformat(fetched)
                                        ).total_seconds()) if fetched else None
    return doc


async def write(db, indicator: str, provider: str,
                    verdict: str | None, *, detail: Any = None,
                    score: Any = None, ttl_s: int | None = None) -> dict:
    """
    Store or refresh a (indicator, provider) entry.  Never fabricates:
    a missing verdict yields verdict="unknown", which the analyst can
    honestly read as "we asked, provider didn't answer".
    """
    now = _now()
    doc = {
        "id":            _cache_id(indicator, provider),
        "indicator":     indicator,
        "provider":      provider,
        "verdict":       verdict or "unknown",
        "detail":        detail,
        "score":         score,
        "fetched_at":    _iso(now),
        "observed_at":   _iso(now),      # last time upstream returned
        "ttl_s":         int(ttl_s or ttl_for(provider)),
    }
    await db[COLLECTION].update_one(
        {"id": doc["id"]}, {"$set": doc}, upsert=True)
    return doc


async def fetch(db, indicator: str, provider: str,
                    fetcher, *, force_refresh: bool = False) -> dict:
    """
    Read-through cache. `fetcher` is an async callable receiving
    (indicator, provider) that MUST return a dict with at least
    `verdict`.  If it raises, the LAST KNOWN value is returned with
    `is_stale=True` (never a fabricated success).
    """
    if not force_refresh:
        cached = await read(db, indicator, provider)
        if cached and not cached["is_stale"]:
            cached["source"] = "cache_hit"
            return cached
    # Miss / stale / forced → hit upstream.
    try:
        result = await fetcher(indicator, provider)
    except Exception as e:  # noqa: BLE001
        stale = await read(db, indicator, provider)
        if stale:
            stale["source"] = "cache_stale_after_upstream_failure"
            stale["upstream_error"] = str(e)
            return stale
        # Nothing cached and upstream failed — honest empty.
        return {
            "id":         _cache_id(indicator, provider),
            "indicator":  indicator, "provider":  provider,
            "verdict":    "unknown", "detail":    None, "score": None,
            "fetched_at": None, "observed_at": None,
            "ttl_s":      ttl_for(provider),
            "is_stale":   True,
            "source":     "upstream_failure_no_cache",
            "upstream_error": str(e),
        }
    doc = await write(db, indicator, provider,
                                verdict=result.get("verdict"),
                                detail=result.get("detail"),
                                score=result.get("score"))
    doc["is_stale"] = False
    doc["source"]   = "cache_refresh"
    return doc


async def summary(db) -> dict:
    """Introspection helper — total entries + stale counts per provider."""
    entries = 0
    stale = 0
    per_provider: dict[str, dict[str, int]] = {}
    async for d in db[COLLECTION].find({}, {"_id": 0}):
        entries += 1
        p = d.get("provider") or "unknown"
        bucket = per_provider.setdefault(p, {"total": 0, "stale": 0})
        bucket["total"] += 1
        # inline staleness
        f = d.get("fetched_at")
        try:
            fdt = datetime.fromisoformat(f) if f else None
        except ValueError:
            fdt = None
        if not fdt or (_now() - fdt) >= timedelta(
                seconds=int(d.get("ttl_s") or ttl_for(p))):
            stale += 1
            bucket["stale"] += 1
    return {
        "collection":     COLLECTION,
        "total_entries":  entries,
        "stale_entries":  stale,
        "per_provider":   per_provider,
        "provider_ttl_s": dict(_PROVIDER_TTL),
        "default_ttl_s":  DEFAULT_TTL_S,
        "honesty_note":
            "Cache never fabricates values.  A missed upstream call "
            "returns the last-known entry tagged is_stale=True, or an "
            "honest 'unknown' when nothing was ever cached.",
    }
