"""NivXRay Threat Intelligence Enrichment (Feb-2026 roadmap #6).

Enriches IOCs with lookups against VirusTotal, AlienVault OTX, and
AbuseIPDB. Each provider adapter returns a normalized verdict:

    {
        "provider":   "virustotal" | "otx" | "abuseipdb",
        "verdict":    "malicious" | "suspicious" | "clean" | "unknown" | "no-key" | "error",
        "score":      float ∈ [0.0, 1.0]   — higher = more malicious
        "sources":    int                  — how many sub-detectors flagged it
        "details":    dict                 — raw provider response summary
        "queried_at": ISO-8601
    }

Provider selection is config-driven — the admin sets API keys via the
`/api/enrichment/config` endpoints. If a key is missing, the provider
returns `no-key` cleanly without raising.

Results are cached in the `enrichment_cache` collection with a 24 h TTL
to avoid burning through free-tier rate limits.

Data model
----------

`enrichment_config` (singleton)
    { _id: "singleton", vt_api_key, otx_api_key, abuseipdb_api_key,
      enable_vt, enable_otx, enable_abuseipdb, cache_ttl_hours }

`enrichment_cache`
    { _id: "<provider>:<kind>:<value>", verdict, score, sources, details,
      queried_at, expires_at }
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx


CONFIG = "enrichment_config"
CACHE = "enrichment_cache"
CONFIG_ID = "singleton"

DEFAULT_TTL_HOURS = 24
HTTP_TIMEOUT = 15.0


# --------------------------------------------------------------
# Config
# --------------------------------------------------------------
def _redact(cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not cfg:
        return {}
    safe = dict(cfg)
    for k in ("vt_api_key", "otx_api_key", "abuseipdb_api_key"):
        if safe.get(k):
            v = safe[k]
            safe[k] = f"{'*' * max(0, len(v) - 4)}{v[-4:]}" if len(v) > 4 else "****"
    return safe


async def get_config(db) -> Dict[str, Any]:
    doc = await db[CONFIG].find_one({"_id": CONFIG_ID}) or {}
    doc.pop("_id", None)
    return doc


async def get_config_redacted(db) -> Dict[str, Any]:
    return _redact(await get_config(db))


async def save_config(db, config: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "vt_api_key", "otx_api_key", "abuseipdb_api_key",
        "enable_vt", "enable_otx", "enable_abuseipdb",
        "cache_ttl_hours",
    }
    to_write = {k: config[k] for k in config if k in allowed}
    to_write.setdefault("cache_ttl_hours", DEFAULT_TTL_HOURS)
    to_write.setdefault("enable_vt", True)
    to_write.setdefault("enable_otx", True)
    to_write.setdefault("enable_abuseipdb", True)
    to_write["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db[CONFIG].update_one({"_id": CONFIG_ID}, {"$set": to_write}, upsert=True)
    return _redact(await get_config(db))


# --------------------------------------------------------------
# Cache
# --------------------------------------------------------------
def _cache_key(provider: str, kind: str, value: str) -> str:
    return f"{provider}:{kind}:{value}"


async def _cache_get(db, provider: str, kind: str, value: str) -> Optional[Dict[str, Any]]:
    doc = await db[CACHE].find_one({"_id": _cache_key(provider, kind, value)})
    if not doc:
        return None
    exp = doc.get("expires_at")
    if exp and exp < datetime.now(timezone.utc).isoformat():
        return None
    doc.pop("_id", None)
    return doc


async def _cache_put(db, provider: str, kind: str, value: str,
                      result: Dict[str, Any], ttl_hours: int) -> None:
    exp = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()
    entry = {**result, "expires_at": exp}
    await db[CACHE].update_one(
        {"_id": _cache_key(provider, kind, value)},
        {"$set": entry}, upsert=True,
    )


# --------------------------------------------------------------
# IOC kind detection
# --------------------------------------------------------------
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def classify_ioc(value: str) -> Optional[str]:
    v = (value or "").strip()
    if not v:
        return None
    if _URL_RE.match(v):
        return "url"
    if _IPV4_RE.match(v):
        return "ipv4"
    if _SHA256_RE.match(v):
        return "sha256"
    if _SHA1_RE.match(v):
        return "sha1"
    if _MD5_RE.match(v):
        return "md5"
    if _DOMAIN_RE.match(v):
        return "domain"
    return None


# --------------------------------------------------------------
# Provider adapters
# --------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _verdict_from_ratio(malicious: int, total: int) -> tuple:
    if total == 0:
        return "unknown", 0.0
    ratio = malicious / total
    if ratio >= 0.20:
        return "malicious", min(ratio, 1.0)
    if ratio >= 0.05:
        return "suspicious", ratio
    if ratio > 0:
        return "suspicious", ratio
    return "clean", 0.0


async def _lookup_virustotal(cfg: Dict[str, Any], kind: str, value: str) -> Dict[str, Any]:
    key = cfg.get("vt_api_key")
    if not key or not cfg.get("enable_vt", True):
        return {"provider": "virustotal", "verdict": "no-key",
                "score": 0.0, "sources": 0, "details": {}, "queried_at": _now()}
    # VT v3 endpoints
    endpoints = {
        "url": lambda v: f"https://www.virustotal.com/api/v3/urls/{_b64url_id(v)}",
        "ipv4": lambda v: f"https://www.virustotal.com/api/v3/ip_addresses/{v}",
        "domain": lambda v: f"https://www.virustotal.com/api/v3/domains/{v}",
        "md5": lambda v: f"https://www.virustotal.com/api/v3/files/{v}",
        "sha1": lambda v: f"https://www.virustotal.com/api/v3/files/{v}",
        "sha256": lambda v: f"https://www.virustotal.com/api/v3/files/{v}",
    }
    url_fn = endpoints.get(kind)
    if not url_fn:
        return {"provider": "virustotal", "verdict": "unknown",
                "score": 0.0, "sources": 0, "details": {"reason": f"unsupported-kind:{kind}"},
                "queried_at": _now()}
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(url_fn(value), headers={"x-apikey": key})
            if r.status_code == 404:
                return {"provider": "virustotal", "verdict": "unknown",
                        "score": 0.0, "sources": 0,
                        "details": {"status": 404, "reason": "not-found-in-vt"},
                        "queried_at": _now()}
            r.raise_for_status()
            body = r.json()
            attrs = (body.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
            harmless = int(stats.get("harmless") or 0)
            undetected = int(stats.get("undetected") or 0)
            total = malicious + suspicious + harmless + undetected
            verdict, score = _verdict_from_ratio(malicious + suspicious, total)
            return {
                "provider": "virustotal",
                "verdict": verdict,
                "score": round(score, 4),
                "sources": malicious + suspicious,
                "details": {
                    "stats": stats,
                    "reputation": attrs.get("reputation"),
                    "total_scanners": total,
                },
                "queried_at": _now(),
            }
    except Exception as e:
        return {"provider": "virustotal", "verdict": "error", "score": 0.0,
                "sources": 0, "details": {"error": str(e)}, "queried_at": _now()}


def _b64url_id(url: str) -> str:
    import base64
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


async def _lookup_otx(cfg: Dict[str, Any], kind: str, value: str) -> Dict[str, Any]:
    key = cfg.get("otx_api_key")
    if not key or not cfg.get("enable_otx", True):
        return {"provider": "otx", "verdict": "no-key",
                "score": 0.0, "sources": 0, "details": {}, "queried_at": _now()}
    otx_kind = {
        "url": "url", "ipv4": "IPv4", "domain": "domain",
        "md5": "file", "sha1": "file", "sha256": "file",
    }.get(kind)
    if not otx_kind:
        return {"provider": "otx", "verdict": "unknown", "score": 0.0,
                "sources": 0, "details": {"reason": f"unsupported-kind:{kind}"},
                "queried_at": _now()}
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_kind}/{value}/general"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(url, headers={"X-OTX-API-KEY": key})
            if r.status_code == 404:
                return {"provider": "otx", "verdict": "unknown",
                        "score": 0.0, "sources": 0,
                        "details": {"status": 404}, "queried_at": _now()}
            r.raise_for_status()
            body = r.json()
            pulse_info = body.get("pulse_info") or {}
            count = int(pulse_info.get("count") or 0)
            verdict, score = _verdict_from_ratio(count, max(count, 1) + 5)  # heuristic
            if count == 0:
                verdict = "clean"; score = 0.0
            elif count >= 3:
                verdict = "malicious"; score = min(1.0, count / 10.0)
            else:
                verdict = "suspicious"; score = count / 10.0
            return {
                "provider": "otx",
                "verdict": verdict,
                "score": round(score, 4),
                "sources": count,
                "details": {"pulse_count": count,
                             "reputation": body.get("reputation")},
                "queried_at": _now(),
            }
    except Exception as e:
        return {"provider": "otx", "verdict": "error", "score": 0.0,
                "sources": 0, "details": {"error": str(e)}, "queried_at": _now()}


async def _lookup_abuseipdb(cfg: Dict[str, Any], kind: str, value: str) -> Dict[str, Any]:
    key = cfg.get("abuseipdb_api_key")
    if not key or not cfg.get("enable_abuseipdb", True):
        return {"provider": "abuseipdb", "verdict": "no-key",
                "score": 0.0, "sources": 0, "details": {}, "queried_at": _now()}
    if kind != "ipv4":
        return {"provider": "abuseipdb", "verdict": "unknown", "score": 0.0,
                "sources": 0, "details": {"reason": "abuseipdb supports IPv4 only"},
                "queried_at": _now()}
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
            r = await client.get(url,
                                  headers={"Key": key, "Accept": "application/json"},
                                  params={"ipAddress": value, "maxAgeInDays": 90})
            r.raise_for_status()
            body = r.json().get("data") or {}
            score_pct = int(body.get("abuseConfidenceScore") or 0)
            reports = int(body.get("totalReports") or 0)
            if score_pct >= 75:
                verdict = "malicious"
            elif score_pct >= 25:
                verdict = "suspicious"
            elif score_pct > 0:
                verdict = "suspicious"
            else:
                verdict = "clean"
            return {
                "provider": "abuseipdb",
                "verdict": verdict,
                "score": round(score_pct / 100.0, 4),
                "sources": reports,
                "details": {
                    "abuse_confidence_score": score_pct,
                    "total_reports": reports,
                    "country": body.get("countryCode"),
                    "isp": body.get("isp"),
                },
                "queried_at": _now(),
            }
    except Exception as e:
        return {"provider": "abuseipdb", "verdict": "error", "score": 0.0,
                "sources": 0, "details": {"error": str(e)}, "queried_at": _now()}


PROVIDERS = {
    "virustotal": _lookup_virustotal,
    "otx": _lookup_otx,
    "abuseipdb": _lookup_abuseipdb,
}


# --------------------------------------------------------------
# Public: enrich a single IOC
# --------------------------------------------------------------
async def enrich_ioc(db, value: str, *, use_cache: bool = True) -> Dict[str, Any]:
    """Look up an IOC across every enabled provider and return an
    aggregate verdict + per-provider breakdown.
    """
    value = (value or "").strip()
    kind = classify_ioc(value)
    if kind is None:
        return {
            "value": value,
            "kind": None,
            "aggregate": {"verdict": "unknown", "score": 0.0, "sources": 0},
            "providers": [],
            "reason": "could-not-classify-ioc",
        }
    cfg = await get_config(db)
    ttl = int(cfg.get("cache_ttl_hours") or DEFAULT_TTL_HOURS)

    per_provider: List[Dict[str, Any]] = []
    for pname, lookup in PROVIDERS.items():
        cached = await _cache_get(db, pname, kind, value) if use_cache else None
        if cached:
            cached["cached"] = True
            per_provider.append(cached)
            continue
        result = await lookup(cfg, kind, value)
        result["cached"] = False
        if result.get("verdict") not in ("no-key", "error"):
            await _cache_put(db, pname, kind, value, result, ttl)
        per_provider.append(result)

    # Aggregate — MAX severity wins.
    priority = {"malicious": 4, "suspicious": 3, "clean": 2, "unknown": 1,
                "no-key": 0, "error": 0}
    worst = max(per_provider, key=lambda p: priority.get(p["verdict"], 0),
                default={"verdict": "unknown", "score": 0.0, "sources": 0})
    aggregate = {
        "verdict": worst.get("verdict", "unknown"),
        "score": max((p.get("score", 0.0) or 0.0) for p in per_provider) if per_provider else 0.0,
        "sources": sum((p.get("sources") or 0) for p in per_provider),
    }
    return {"value": value, "kind": kind, "aggregate": aggregate,
            "providers": per_provider}


async def enrich_iocs(db, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
    """Enrich a NivXRay-shaped IOC dict (from operations.extract_iocs).

    Returns:
        {
            "results": [ {value, kind, aggregate, providers[]}, ... ],
            "summary": {malicious: n, suspicious: n, clean: n, unknown: n},
        }
    """
    flat: List[str] = []
    for k, lst in (iocs or {}).items():
        for v in (lst or []):
            if v and v not in flat:
                flat.append(v)
    results: List[Dict[str, Any]] = []
    counters = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0,
                "no-key": 0, "error": 0}
    for value in flat:
        res = await enrich_ioc(db, value)
        results.append(res)
        counters[res["aggregate"]["verdict"]] = counters.get(
            res["aggregate"]["verdict"], 0) + 1
    return {"results": results, "summary": counters}
