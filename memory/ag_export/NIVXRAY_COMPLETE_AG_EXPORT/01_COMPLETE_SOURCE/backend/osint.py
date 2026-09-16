"""NivXRay — OSINT enrichment for extracted IOCs.

Supports pluggable API keys (VirusTotal, AbuseIPDB, Shodan, GreyNoise,
URLScan.io, OTX AlienVault, IPinfo) loaded from the settings DB collection.
Always uses free sources (ip-api.com, system DNS) as a baseline.
"""
from __future__ import annotations
import asyncio
import base64
import ipaddress
import re
import socket
from typing import Any, Dict, List, Optional

try:
    import httpx
    _TIMEOUT = httpx.Timeout(8.0, connect=4.0)
except Exception:
    httpx = None
    _TIMEOUT = None

# ---------------------------------------------------------------------------
# Supported OSINT service catalog (drives the Admin UI too)
# ---------------------------------------------------------------------------
OSINT_SERVICES = [
    {"id": "virustotal", "label": "VirusTotal", "docs": "https://developers.virustotal.com/reference/overview", "supports": ["ip", "domain", "url", "hash"]},
    {"id": "abuseipdb", "label": "AbuseIPDB", "docs": "https://docs.abuseipdb.com/", "supports": ["ip"]},
    {"id": "shodan", "label": "Shodan", "docs": "https://developer.shodan.io/api", "supports": ["ip"]},
    {"id": "greynoise", "label": "GreyNoise", "docs": "https://docs.greynoise.io/", "supports": ["ip"]},
    {"id": "urlscan", "label": "URLScan.io", "docs": "https://urlscan.io/docs/api/", "supports": ["url", "domain"]},
    {"id": "otx", "label": "AlienVault OTX", "docs": "https://otx.alienvault.com/api", "supports": ["ip", "domain", "hash", "url"]},
    {"id": "ipinfo", "label": "IPinfo", "docs": "https://ipinfo.io/developers", "supports": ["ip"]},
    {"id": "hybrid_analysis", "label": "Hybrid Analysis", "docs": "https://www.hybrid-analysis.com/docs/api/v2", "supports": ["hash"]},
    {"id": "abusech", "label": "abuse.ch Auth-Key", "docs": "https://auth.abuse.ch/", "supports": ["ThreatFox", "MalwareBazaar", "URLhaus API"]},
]

_SERVICE_IDS = [s["id"] for s in OSINT_SERVICES]


# ---------------------------------------------------------------------------
# Classifiers
# ---------------------------------------------------------------------------
_TLD_HIGH_RISK = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "review", "country", "kim", "cricket", "download", "loan", "work", "party"}
_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _classify_domain(domain: str) -> Dict[str, Any]:
    tld = domain.rsplit(".", 1)[-1].lower()
    return {
        "tld": tld,
        "is_high_risk_tld": tld in _TLD_HIGH_RISK,
        "is_onion": domain.endswith(".onion"),
        "length": len(domain),
        "has_dashes": "-" in domain,
        "num_subdomains": max(0, domain.count(".") - 1),
    }


async def _reverse_dns(ip: str) -> Optional[str]:
    try:
        loop = asyncio.get_event_loop()
        host, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Free (no-key) sources
# ---------------------------------------------------------------------------
async def _ip_api(client: httpx.AsyncClient, ip: str) -> Optional[Dict[str, Any]]:
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,mobile,query"},
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Keyed sources
# ---------------------------------------------------------------------------
async def _virustotal_ip(c, ip, key):
    try:
        r = await c.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": key})
        if r.status_code == 200:
            a = r.json().get("data", {}).get("attributes", {}) or {}
            s = a.get("last_analysis_stats") or {}
            return {
                "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "reputation": a.get("reputation", 0),
                "asn": a.get("asn"), "as_owner": a.get("as_owner"), "country": a.get("country"),
            }
    except Exception: pass
    return None


async def _virustotal_domain(c, domain, key):
    try:
        r = await c.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers={"x-apikey": key})
        if r.status_code == 200:
            a = r.json().get("data", {}).get("attributes", {}) or {}
            s = a.get("last_analysis_stats") or {}
            return {
                "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "reputation": a.get("reputation", 0),
                "categories": a.get("categories") or {},
            }
    except Exception: pass
    return None


async def _virustotal_url(c, url, key):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = await c.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": key})
        if r.status_code == 200:
            a = r.json().get("data", {}).get("attributes", {}) or {}
            s = a.get("last_analysis_stats") or {}
            return {
                "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "reputation": a.get("reputation", 0),
                "categories": a.get("categories") or {}, "final_url": a.get("last_final_url"),
            }
    except Exception: pass
    return None


async def _virustotal_hash(c, h, key):
    try:
        r = await c.get(f"https://www.virustotal.com/api/v3/files/{h}", headers={"x-apikey": key})
        if r.status_code == 200:
            a = r.json().get("data", {}).get("attributes", {}) or {}
            s = a.get("last_analysis_stats") or {}
            return {
                "malicious": s.get("malicious", 0), "suspicious": s.get("suspicious", 0),
                "harmless": s.get("harmless", 0), "reputation": a.get("reputation", 0),
                "type_description": a.get("type_description"),
                "meaningful_name": a.get("meaningful_name"),
                "threat_label": (a.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            }
    except Exception: pass
    return None


async def _abuseipdb(c, ip, key):
    try:
        r = await c.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if r.status_code == 200:
            d = r.json().get("data") or {}
            return {
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "country_code": d.get("countryCode"),
                "usage_type": d.get("usageType"),
                "isp": d.get("isp"),
                "total_reports": d.get("totalReports"),
                "last_reported_at": d.get("lastReportedAt"),
                "is_tor": d.get("isTor"),
            }
    except Exception: pass
    return None


async def _shodan_ip(c, ip, key):
    try:
        r = await c.get(f"https://api.shodan.io/shodan/host/{ip}", params={"key": key})
        if r.status_code == 200:
            d = r.json()
            return {
                "org": d.get("org"),
                "isp": d.get("isp"),
                "country_name": d.get("country_name"),
                "os": d.get("os"),
                "ports": d.get("ports") or [],
                "hostnames": (d.get("hostnames") or [])[:5],
                "vulns": list((d.get("vulns") or []))[:10],
                "last_update": d.get("last_update"),
            }
    except Exception: pass
    return None


async def _greynoise(c, ip, key):
    try:
        r = await c.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": key})
        if r.status_code == 200:
            d = r.json()
            return {
                "classification": d.get("classification"),
                "name": d.get("name"),
                "noise": d.get("noise"),
                "riot": d.get("riot"),
                "last_seen": d.get("last_seen"),
            }
    except Exception: pass
    return None


async def _urlscan_search(c, target, key):
    try:
        r = await c.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"page.domain:{target} OR domain:{target}", "size": 3},
            headers={"API-Key": key} if key else {},
        )
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])[:3]
            return {
                "total": data.get("total", 0),
                "results": [
                    {
                        "url": r0.get("page", {}).get("url"),
                        "verdict": (r0.get("verdicts") or {}).get("overall", {}).get("malicious"),
                        "score": (r0.get("verdicts") or {}).get("overall", {}).get("score"),
                        "scan_id": r0.get("_id"),
                    } for r0 in results
                ],
            }
    except Exception: pass
    return None


async def _otx(c, kind, value, key):
    """AlienVault OTX general indicator query. kind: IPv4|domain|url|file"""
    endpoint_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
    section = endpoint_map.get(kind)
    if not section:
        return None
    try:
        r = await c.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{value}/general",
            headers={"X-OTX-API-KEY": key},
        )
        if r.status_code == 200:
            d = r.json()
            return {
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "reputation": d.get("reputation"),
                "pulses": [{"name": p.get("name"), "tags": (p.get("tags") or [])[:5]} for p in (d.get("pulse_info", {}).get("pulses") or [])[:3]],
            }
    except Exception: pass
    return None


async def _ipinfo(c, ip, key):
    try:
        r = await c.get(f"https://ipinfo.io/{ip}", params={"token": key})
        if r.status_code == 200:
            d = r.json()
            return {
                "org": d.get("org"),
                "hostname": d.get("hostname"),
                "country": d.get("country"),
                "region": d.get("region"),
                "city": d.get("city"),
                "loc": d.get("loc"),
                "postal": d.get("postal"),
                "timezone": d.get("timezone"),
            }
    except Exception: pass
    return None


async def _hybrid_analysis_hash(c, h, key):
    try:
        r = await c.get(
            f"https://www.hybrid-analysis.com/api/v2/search/hash",
            headers={"api-key": key, "user-agent": "Falcon Sandbox", "accept": "application/json"},
            params={"hash": h},
        )
        if r.status_code == 200:
            arr = r.json() or []
            if arr:
                d = arr[0]
                return {
                    "verdict": d.get("verdict"),
                    "threat_score": d.get("threat_score"),
                    "malware_family": d.get("vx_family"),
                    "environment": d.get("environment_description"),
                    "submit_name": d.get("submit_name"),
                }
    except Exception: pass
    return None


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------
async def enrich_iocs(iocs: Dict[str, List[str]], keys: Dict[str, str], max_per_type: int = 6) -> Dict[str, Any]:
    """Enrich IOCs. `keys` is a dict of {service_id: api_key} — empty strings ignored."""
    keys = {k: v for k, v in (keys or {}).items() if v}
    out: Dict[str, Any] = {
        "ips": [], "domains": [], "urls": [], "hashes": [],
        "sources_used": _sources_used(keys),
    }

    async with httpx.AsyncClient(timeout=_TIMEOUT, headers={"User-Agent": "NivXRay/1.0"}) as c:
        # IPs
        ip_tasks = []
        for ip in iocs.get("ips", [])[:max_per_type]:
            if _is_private_ip(ip):
                out["ips"].append({"value": ip, "is_private": True, "note": "RFC1918 / private address — not routable"})
                continue
            ip_tasks.append(_enrich_ip(c, ip, keys))
        for res in await asyncio.gather(*ip_tasks, return_exceptions=True):
            if isinstance(res, Exception) or not res: continue
            out["ips"].append(res)

        # Domains
        dom_tasks = [_enrich_domain(c, d, keys) for d in iocs.get("domains", [])[:max_per_type]]
        for res in await asyncio.gather(*dom_tasks, return_exceptions=True):
            if isinstance(res, Exception) or not res: continue
            out["domains"].append(res)

        # URLs
        url_tasks = [_enrich_url(c, u, keys) for u in iocs.get("urls", [])[:max_per_type]]
        for res in await asyncio.gather(*url_tasks, return_exceptions=True):
            if isinstance(res, Exception) or not res: continue
            out["urls"].append(res)

        # Hashes
        all_hashes = (
            [("md5", h) for h in iocs.get("md5", [])]
            + [("sha1", h) for h in iocs.get("sha1", [])]
            + [("sha256", h) for h in iocs.get("sha256", [])]
        )[:max_per_type]
        h_tasks = [_enrich_hash(c, algo, h, keys) for algo, h in all_hashes]
        for res in await asyncio.gather(*h_tasks, return_exceptions=True):
            if isinstance(res, Exception) or not res: continue
            out["hashes"].append(res)

    return out


async def _enrich_ip(c, ip, keys):
    tasks = {
        "reverse_dns": _reverse_dns(ip),
        "geo": _ip_api(c, ip),
    }
    if keys.get("virustotal"): tasks["virustotal"] = _virustotal_ip(c, ip, keys["virustotal"])
    if keys.get("abuseipdb"): tasks["abuseipdb"] = _abuseipdb(c, ip, keys["abuseipdb"])
    if keys.get("shodan"):    tasks["shodan"] = _shodan_ip(c, ip, keys["shodan"])
    if keys.get("greynoise"): tasks["greynoise"] = _greynoise(c, ip, keys["greynoise"])
    if keys.get("ipinfo"):    tasks["ipinfo"] = _ipinfo(c, ip, keys["ipinfo"])
    if keys.get("otx"):       tasks["otx"] = _otx(c, "ip", ip, keys["otx"])
    names = list(tasks.keys())
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    data = {"value": ip}
    for n, r in zip(names, results):
        data[n] = r if not isinstance(r, Exception) else None
    return data


async def _enrich_domain(c, domain, keys):
    resolved: List[str] = []
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.run_in_executor(None, socket.getaddrinfo, domain, None)
        resolved = list({info[4][0] for info in infos})[:4]
    except Exception:
        pass
    tasks = {}
    if keys.get("virustotal"): tasks["virustotal"] = _virustotal_domain(c, domain, keys["virustotal"])
    if keys.get("urlscan"):    tasks["urlscan"] = _urlscan_search(c, domain, keys["urlscan"])
    if keys.get("otx"):        tasks["otx"] = _otx(c, "domain", domain, keys["otx"])
    data = {"value": domain, "classification": _classify_domain(domain), "resolved_ips": resolved}
    if tasks:
        names = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for n, r in zip(names, results):
            data[n] = r if not isinstance(r, Exception) else None
    return data


async def _enrich_url(c, url, keys):
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.hostname or ""
    data = {
        "value": url, "scheme": p.scheme, "host": host, "path": p.path,
        "port": p.port, "is_onion": host.endswith(".onion"),
    }
    tasks = {}
    if keys.get("virustotal"): tasks["virustotal"] = _virustotal_url(c, url, keys["virustotal"])
    if keys.get("urlscan"):    tasks["urlscan"] = _urlscan_search(c, host, keys["urlscan"])
    if keys.get("otx"):        tasks["otx"] = _otx(c, "url", url, keys["otx"])
    if tasks:
        names = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for n, r in zip(names, results):
            data[n] = r if not isinstance(r, Exception) else None
    return data


async def _enrich_hash(c, algo, h, keys):
    data = {"algorithm": algo, "value": h}
    tasks = {}
    if keys.get("virustotal"):      tasks["virustotal"] = _virustotal_hash(c, h, keys["virustotal"])
    if keys.get("hybrid_analysis"): tasks["hybrid_analysis"] = _hybrid_analysis_hash(c, h, keys["hybrid_analysis"])
    if keys.get("otx"):             tasks["otx"] = _otx(c, "hash", h, keys["otx"])
    if tasks:
        names = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for n, r in zip(names, results):
            data[n] = r if not isinstance(r, Exception) else None
    return data


def _sources_used(keys: Dict[str, str]) -> List[str]:
    src = ["ip-api.com (geolocation, no key)", "system DNS (reverse lookup, resolution)"]
    for s in OSINT_SERVICES:
        if keys.get(s["id"]):
            src.append(s["label"])
    return src
