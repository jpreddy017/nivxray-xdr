"""NivXRay Threat Intelligence Enrichment (Feb-2026 roadmap #6).

Given an IOC (URL, IP, domain, hash), enrich it with reputation and
detection info from configured providers:

    - VirusTotal (api.virustotal.com/api/v3)  — hash/domain/ip/url
    - AlienVault OTX (otx.alienvault.com)      — indicator "general" endpoint
    - AbuseIPDB (api.abuseipdb.com)            — ip only

All providers are OFF by default. Admins configure API keys via the
`/api/admin/threat-intel/config` endpoint. Enrichment returns whatever
providers are configured and succeed; missing keys are reported as
`"status": "no-key"` and cause no errors.

Storage
-------

`threat_intel_config`  — singleton config document
`threat_intel_cache`   — 1h cache per (provider, kind, value)
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx


CONFIG_COLL = "threat_intel_config"
CACHE_COLL = "threat_intel_cache"
CONFIG_ID = "singleton"
CACHE_TTL_MIN = 60
DEFAULT_TIMEOUT = 12.0


# ------------------------------------------------------------------
# Config
# ------------------------------------------------------------------
def _redact(cfg: Dict[str, Any]) -> Dict[str, Any]:
    if not cfg:
        return {}
    safe = dict(cfg)
    for k in ("virustotal_api_key", "otx_api_key", "abuseipdb_api_key"):
        v = safe.get(k) or ""
        if v:
            safe[k] = f"{'*' * max(0, len(v) - 4)}{v[-4:]}" if len(v) > 4 else "****"
    return safe


async def get_config(db) -> Dict[str, Any]:
    doc = await db[CONFIG_COLL].find_one({"_id": CONFIG_ID}) or {}
    doc.pop("_id", None)
    return doc


async def get_config_redacted(db) -> Dict[str, Any]:
    return _redact(await get_config(db))


async def save_config(db, cfg: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "virustotal_api_key", "otx_api_key", "abuseipdb_api_key",
        "enable_virustotal", "enable_otx", "enable_abuseipdb",
    }
    to_write = {k: cfg[k] for k in cfg if k in allowed}
    # Never overwrite a stored key with an empty/redacted value
    stored = await get_config(db)
    for k in ("virustotal_api_key", "otx_api_key", "abuseipdb_api_key"):
        if k in to_write:
            v = to_write[k]
            if not v or (isinstance(v, str) and v.startswith("*")):
                to_write[k] = stored.get(k, "")
    to_write["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db[CONFIG_COLL].update_one(
        {"_id": CONFIG_ID}, {"$set": to_write}, upsert=True,
    )
    return _redact(await get_config(db))


# ------------------------------------------------------------------
# Kind detection
# ------------------------------------------------------------------
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HASH_RES = [
    (32, re.compile(r"^[0-9a-fA-F]{32}$"), "md5"),
    (40, re.compile(r"^[0-9a-fA-F]{40}$"), "sha1"),
    (64, re.compile(r"^[0-9a-fA-F]{64}$"), "sha256"),
]
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def detect_kind(value: str) -> str:
    """Classify an IOC as url|ip|domain|md5|sha1|sha256|unknown."""
    v = (value or "").strip()
    if not v:
        return "unknown"
    if v.lower().startswith(("http://", "https://")):
        return "url"
    if _IP_RE.match(v):
        # 0.0.0.0 - 255.255.255.255
        try:
            parts = [int(x) for x in v.split(".")]
            if all(0 <= p <= 255 for p in parts):
                return "ip"
        except Exception:
            pass
    for L, rx, kind in _HASH_RES:
        if len(v) == L and rx.match(v):
            return kind
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# ------------------------------------------------------------------
# Cache
# ------------------------------------------------------------------
def _cache_key(provider: str, kind: str, value: str) -> str:
    raw = f"{provider}|{kind}|{value}".encode()
    return hashlib.sha256(raw).hexdigest()


async def _cache_get(db, provider: str, kind: str, value: str) -> Optional[Dict[str, Any]]:
    key = _cache_key(provider, kind, value)
    doc = await db[CACHE_COLL].find_one({"_id": key})
    if not doc:
        return None
    try:
        ts = datetime.fromisoformat(doc["cached_at"])
        if datetime.now(timezone.utc) - ts > timedelta(minutes=CACHE_TTL_MIN):
            return None
    except Exception:
        return None
    return doc.get("result")


async def _cache_put(db, provider: str, kind: str, value: str, result: Dict[str, Any]) -> None:
    key = _cache_key(provider, kind, value)
    try:
        await db[CACHE_COLL].update_one(
            {"_id": key},
            {"$set": {
                "provider": provider, "kind": kind, "value": value,
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "result": result,
            }},
            upsert=True,
        )
    except Exception:
        pass


# ------------------------------------------------------------------
# Providers
# ------------------------------------------------------------------
async def _lookup_virustotal(client: httpx.AsyncClient, cfg: Dict[str, Any],
                              kind: str, value: str) -> Dict[str, Any]:
    key = cfg.get("virustotal_api_key")
    if not key:
        return {"status": "no-key"}
    kind_path = {
        "md5": "files", "sha1": "files", "sha256": "files",
        "ip": "ip_addresses", "domain": "domains",
        "url": "urls",
    }.get(kind)
    if not kind_path:
        return {"status": "unsupported-kind", "kind": kind}
    if kind == "url":
        import base64
        vt_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    else:
        vt_id = value
    url = f"https://www.virustotal.com/api/v3/{kind_path}/{vt_id}"
    try:
        r = await client.get(url, headers={"x-apikey": key})
        if r.status_code == 404:
            return {"status": "not-found"}
        r.raise_for_status()
        data = r.json().get("data", {}).get("attributes", {}) or {}
        stats = data.get("last_analysis_stats") or {}
        return {
            "status": "ok",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": data.get("reputation"),
            "meaningful_name": data.get("meaningful_name"),
            "categories": data.get("categories"),
            "type_description": data.get("type_description"),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}


async def _lookup_otx(client: httpx.AsyncClient, cfg: Dict[str, Any],
                       kind: str, value: str) -> Dict[str, Any]:
    key = cfg.get("otx_api_key")
    if not key:
        return {"status": "no-key"}
    endpoint = {
        "md5": "file", "sha1": "file", "sha256": "file",
        "ip": "IPv4", "domain": "domain", "url": "url",
    }.get(kind)
    if not endpoint:
        return {"status": "unsupported-kind", "kind": kind}
    url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint}/{value}/general"
    try:
        r = await client.get(url, headers={"X-OTX-API-KEY": key})
        if r.status_code == 404:
            return {"status": "not-found"}
        r.raise_for_status()
        data = r.json() or {}
        return {
            "status": "ok",
            "pulse_count": (data.get("pulse_info") or {}).get("count", 0),
            "pulses": [
                {"name": p.get("name"), "id": p.get("id"),
                  "author": (p.get("author") or {}).get("username")}
                for p in ((data.get("pulse_info") or {}).get("pulses") or [])[:5]
            ],
            "reputation": data.get("reputation"),
            "country_code": data.get("country_code"),
            "asn": data.get("asn"),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}


async def _lookup_abuseipdb(client: httpx.AsyncClient, cfg: Dict[str, Any],
                              kind: str, value: str) -> Dict[str, Any]:
    if kind != "ip":
        return {"status": "unsupported-kind", "kind": kind}
    key = cfg.get("abuseipdb_api_key")
    if not key:
        return {"status": "no-key"}
    url = "https://api.abuseipdb.com/api/v2/check"
    try:
        r = await client.get(
            url,
            params={"ipAddress": value, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
        )
        r.raise_for_status()
        data = (r.json() or {}).get("data", {}) or {}
        return {
            "status": "ok",
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "country_code": data.get("countryCode"),
            "domain": data.get("domain"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:200]}


# ------------------------------------------------------------------
# Public enrichment entry point
# ------------------------------------------------------------------
async def enrich(db, value: str, providers: Optional[List[str]] = None) -> Dict[str, Any]:
    """Enrich `value` with all enabled providers. Cached for 60 minutes.

    Args:
        value: raw IOC (url, ip, domain, or hash).
        providers: optional whitelist — subset of {"virustotal", "otx",
            "abuseipdb"}. Defaults to all enabled.

    Returns:
        {value, kind, results: {virustotal:{...}, otx:{...}, abuseipdb:{...}}}
    """
    cfg = await get_config(db)
    kind = detect_kind(value)

    wanted: List[str] = []
    if providers is None:
        if cfg.get("enable_virustotal") and cfg.get("virustotal_api_key"):
            wanted.append("virustotal")
        if cfg.get("enable_otx") and cfg.get("otx_api_key"):
            wanted.append("otx")
        if cfg.get("enable_abuseipdb") and cfg.get("abuseipdb_api_key"):
            wanted.append("abuseipdb")
    else:
        wanted = [p for p in providers if p in {"virustotal", "otx", "abuseipdb"}]

    results: Dict[str, Any] = {}

    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        for prov in wanted:
            cached = await _cache_get(db, prov, kind, value)
            if cached is not None:
                results[prov] = {**cached, "_cached": True}
                continue
            if prov == "virustotal":
                r = await _lookup_virustotal(client, cfg, kind, value)
            elif prov == "otx":
                r = await _lookup_otx(client, cfg, kind, value)
            elif prov == "abuseipdb":
                r = await _lookup_abuseipdb(client, cfg, kind, value)
            else:
                r = {"status": "unknown-provider"}
            if r.get("status") == "ok":
                await _cache_put(db, prov, kind, value, r)
            results[prov] = r

    # If NO providers were queried (either not configured or filtered out),
    # still return a meaningful payload so the UI can render "no-key".
    if not results:
        results = {
            "virustotal": {"status": "no-key" if not cfg.get("virustotal_api_key") else "disabled"},
            "otx":        {"status": "no-key" if not cfg.get("otx_api_key") else "disabled"},
            "abuseipdb":  {"status": "no-key" if not cfg.get("abuseipdb_api_key") else "disabled"},
        }

    return {
        "value": value,
        "kind": kind,
        "results": results,
    }
