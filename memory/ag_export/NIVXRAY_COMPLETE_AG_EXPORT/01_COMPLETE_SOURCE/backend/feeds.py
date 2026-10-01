"""NivXRay — Threat-Intel bulk feed ingestion.

Syncs curated indicator feeds from public / keyed sources into MongoDB.
Sources supported:

BULK (fetch a list of indicators):
  - alienvault_otx     — subscribed pulses          (key: otx)
  - abuseipdb          — blacklist                  (key: abuseipdb)
  - malwarebytes       — Malwarebytes Labs blog IOC (public RSS-style feed)
  - talos              — Talos IP blocklist         (public)
  - threatfox          — abuse.ch ThreatFox recent  (public)
  - malwarebazaar      — abuse.ch MalwareBazaar     (public recent)
  - virustotal         — VirusTotal Enterprise      (requires enterprise; degrades gracefully)
  - urlhaus            — abuse.ch URLhaus recent    (public)
  - cins_army          — CINS Army Sentinel IPS     (public)

LOOKUP-ONLY (no bulk feed, kept for context):
  - urlscan
  - shodan
"""
from __future__ import annotations
import asyncio
import csv
import io
import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

_TIMEOUT = httpx.Timeout(30.0, connect=8.0)
_UA = {"User-Agent": "NivXRay/1.0 (+threat-intel)"}


# ---------------------------------------------------------------------------
# Source catalog (drives the UI cards)
# ---------------------------------------------------------------------------
SOURCES: List[Dict[str, Any]] = [
    {
        "id": "alienvault_otx", "label": "AlienVault OTX",
        "bulk": True, "needs_key": "otx",
        "description": "Subscribed OTX pulses (community threat intel)",
    },
    {
        "id": "abuseipdb", "label": "AbuseIPDB",
        "bulk": True, "needs_key": "abuseipdb",
        "description": "Blacklist of high-confidence malicious IPs",
    },
    {
        "id": "malwarebytes", "label": "Malwarebytes Labs",
        "bulk": True, "needs_key": None,
        "description": "Malwarebytes research blog IOC feed",
    },
    {
        "id": "talos", "label": "Talos-Community Blocklists (ET + Feodo)",
        "bulk": True, "needs_key": None,
        "description": "Cisco Talos community blocklist + Emerging Threats + Feodo",
    },
    {
        "id": "threatfox", "label": "ThreatFox (abuse.ch)",
        "bulk": True, "needs_key": None,
        "description": "Recent IOCs from abuse.ch ThreatFox",
    },
    {
        "id": "malwarebazaar", "label": "MalwareBazaar",
        "bulk": True, "needs_key": None,
        "description": "Recent malware sample hashes",
    },
    {
        "id": "virustotal_enterprise", "label": "VirusTotal (Enterprise)",
        "bulk": True, "needs_key": "virustotal",
        "description": "LiveHunt / RetroHunt feed (Enterprise API only)",
    },
    {
        "id": "urlhaus", "label": "URLhaus (abuse.ch)",
        "bulk": True, "needs_key": None,
        "description": "Recent malicious URLs",
    },
    {
        "id": "cins_army", "label": "CINS Army (Sentinel IPS)",
        "bulk": True, "needs_key": None,
        "description": "Sentinel Community Intel IP blocklist",
    },
    {
        "id": "urlscan", "label": "URLScan.io",
        "bulk": False, "needs_key": "urlscan",
        "description": "Bulk 'malicious verdicts' search requires urlscan Pro",
    },
    {
        "id": "shodan", "label": "Shodan",
        "bulk": False, "needs_key": "shodan",
        "description": "Not a curated IOC feed (internet scan engine)",
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _sev_from_score(score: int | None) -> str:
    if score is None: return "medium"
    if score >= 90: return "critical"
    if score >= 70: return "high"
    if score >= 40: return "medium"
    return "low"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _norm(kind: str, value: str, source: str, severity: str = "medium",
          tags: Optional[List[str]] = None, extra: Optional[Dict] = None) -> Dict[str, Any]:
    return {
        "kind": kind,             # ip | domain | url | md5 | sha1 | sha256
        "value": value.strip(),
        "source": source,
        "severity": severity,
        "tags": tags or [],
        "extra": extra or {},
        "first_seen": _now_iso(),
        "last_seen": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Individual source fetchers  — return list[dict]  (normalized IOC docs)
# ---------------------------------------------------------------------------
async def fetch_otx(c: httpx.AsyncClient, key: str, limit: int = 25) -> List[Dict[str, Any]]:
    r = await c.get("https://otx.alienvault.com/api/v1/pulses/subscribed",
                    headers={**_UA, "X-OTX-API-KEY": key},
                    params={"limit": limit, "page": 1})
    r.raise_for_status()
    out: List[Dict[str, Any]] = []
    for p in r.json().get("results", []):
        for ind in (p.get("indicators") or [])[:80]:
            typ = (ind.get("type") or "").lower()
            val = ind.get("indicator")
            if not val: continue
            kind = {"ipv4": "ip", "ipv6": "ip", "domain": "domain", "hostname": "domain",
                    "url": "url", "urI": "url", "filehash-md5": "md5",
                    "filehash-sha1": "sha1", "filehash-sha256": "sha256"}.get(typ)
            if not kind: continue
            out.append(_norm(kind, val, "alienvault_otx",
                             severity="high",
                             tags=(p.get("tags") or [])[:6],
                             extra={"pulse": p.get("name")}))
    return out


async def fetch_abuseipdb(c: httpx.AsyncClient, key: str, limit: int = 1000) -> List[Dict[str, Any]]:
    r = await c.get("https://api.abuseipdb.com/api/v2/blacklist",
                    headers={**_UA, "Key": key, "Accept": "application/json"},
                    params={"confidenceMinimum": 90, "limit": limit})
    r.raise_for_status()
    return [_norm("ip", d["ipAddress"], "abuseipdb",
                  severity=_sev_from_score(d.get("abuseConfidenceScore")),
                  extra={"score": d.get("abuseConfidenceScore"), "last_reported_at": d.get("lastReportedAt")})
            for d in (r.json().get("data") or [])]


async def fetch_talos(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    r = await c.get("https://talosintelligence.com/documents/ip-blacklist", headers=_UA)
    r.raise_for_status()
    ips = [ln.strip() for ln in r.text.splitlines() if ln.strip() and _is_ip(ln.strip())]
    return [_norm("ip", ip, "talos", severity="high", tags=["talos", "blocklist"]) for ip in ips[:5000]]


async def fetch_cins_army(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    r = await c.get("http://cinsscore.com/list/ci-badguys.txt", headers=_UA)
    r.raise_for_status()
    ips = [ln.strip() for ln in r.text.splitlines() if ln.strip() and not ln.strip().startswith("#") and _is_ip(ln.strip())]
    return [_norm("ip", ip, "cins_army", severity="high", tags=["cins", "sentinel-ips"]) for ip in ips[:5000]]


async def fetch_threatfox(c: httpx.AsyncClient, limit: int = 500, auth_key: str = "") -> List[Dict[str, Any]]:
    # POST recent IOCs from ThreatFox (requires abuse.ch Auth-Key)
    headers = {**_UA}
    if auth_key: headers["Auth-Key"] = auth_key
    r = await c.post("https://threatfox-api.abuse.ch/api/v1/",
                     headers=headers,
                     content=json.dumps({"query": "get_iocs", "days": 3}).encode("utf-8"))
    r.raise_for_status()
    data = r.json()
    if data.get("query_status") != "ok":
        return []
    out: List[Dict[str, Any]] = []
    for d in (data.get("data") or [])[:limit]:
        typ = (d.get("ioc_type") or "").lower()
        val = d.get("ioc") or d.get("ioc_value")
        if not val: continue
        kind = {"ip:port": "ip", "url": "url", "domain": "domain",
                "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}.get(typ)
        if not kind: continue
        if kind == "ip":
            val = val.split(":")[0]
        out.append(_norm(kind, val, "threatfox",
                         severity=_sev_from_score(int(d.get("confidence_level") or 60)),
                         tags=[d.get("malware")] if d.get("malware") else [],
                         extra={"threat_type": d.get("threat_type"), "reference": d.get("reference")}))
    return out


async def fetch_malwarebazaar(c: httpx.AsyncClient, limit: int = 500, auth_key: str = "") -> List[Dict[str, Any]]:
    headers = {**_UA}
    if auth_key: headers["Auth-Key"] = auth_key
    r = await c.post("https://mb-api.abuse.ch/api/v1/",
                     headers=headers,
                     data={"query": "get_recent", "selector": "time"})
    if r.status_code != 200:
        return []
    data = r.json()
    if data.get("query_status") != "ok":
        return []
    out: List[Dict[str, Any]] = []
    for d in (data.get("data") or [])[:limit]:
        sig = d.get("signature")
        tags = [t for t in [sig, d.get("file_type"), d.get("tags") and d["tags"][0] if d.get("tags") else None] if t]
        for algo in ("sha256", "sha1", "md5"):
            h = d.get(f"{algo}_hash")
            if h:
                out.append(_norm(algo, h, "malwarebazaar", severity="high",
                                 tags=tags[:4],
                                 extra={"signature": sig, "file_name": d.get("file_name"),
                                        "file_size": d.get("file_size")}))
    return out


async def fetch_urlhaus(c: httpx.AsyncClient, limit: int = 2500) -> List[Dict[str, Any]]:
    r = await c.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=_UA)
    if r.status_code != 200:
        return []
    text = r.text
    # remove comment lines
    body = "\n".join(ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    reader = csv.reader(io.StringIO(body))
    out: List[Dict[str, Any]] = []
    for i, row in enumerate(reader):
        if i >= limit: break
        # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        if len(row) < 7: continue
        _id, dateadded, url, status, last_online, threat, tags = row[:7]
        out.append(_norm("url", url, "urlhaus",
                         severity="high" if status == "online" else "medium",
                         tags=[t for t in (tags or "").split(",") if t] + [threat] if threat else [],
                         extra={"status": status, "added": dateadded, "last_online": last_online}))
    return out


async def fetch_malwarebytes(c: httpx.AsyncClient, limit: int = 100) -> List[Dict[str, Any]]:
    """Malwarebytes Labs research blog RSS — extract any IPs/domains/hashes mentioned in titles."""
    try:
        r = await c.get("https://www.malwarebytes.com/blog/feed/index.xml", headers=_UA)
        if r.status_code != 200:
            return []
        text = r.text
        titles = re.findall(r"<title>([^<]+)</title>", text)
        out: List[Dict[str, Any]] = []
        for t in titles[:limit]:
            for h in re.findall(r"\b[a-fA-F0-9]{64}\b", t):
                out.append(_norm("sha256", h, "malwarebytes", severity="medium", extra={"context": t[:120]}))
            for h in re.findall(r"\b[a-fA-F0-9]{40}\b", t):
                out.append(_norm("sha1", h, "malwarebytes", severity="medium", extra={"context": t[:120]}))
            for h in re.findall(r"\b[a-fA-F0-9]{32}\b", t):
                out.append(_norm("md5", h, "malwarebytes", severity="medium", extra={"context": t[:120]}))
        return out
    except Exception:
        return []


async def fetch_virustotal_enterprise(c: httpx.AsyncClient, key: str) -> List[Dict[str, Any]]:
    """VT LiveHunt / feed requires Enterprise. We probe an accessible endpoint and gracefully return empty."""
    try:
        r = await c.get("https://www.virustotal.com/api/v3/intelligence/hunting_notifications",
                        headers={"x-apikey": key}, params={"limit": 20})
        if r.status_code != 200:
            return []
        data = r.json() or {}
        out: List[Dict[str, Any]] = []
        for d in data.get("data") or []:
            ctx = d.get("context_attributes") or {}
            attrs = d.get("attributes") or {}
            for k in ("sha256", "sha1", "md5"):
                v = ctx.get(k) or attrs.get(k)
                if v:
                    out.append(_norm(k, v, "virustotal_enterprise", severity="high",
                                     tags=(attrs.get("tags") or [])[:5],
                                     extra={"rule": attrs.get("rule_name")}))
        return out
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------
async def sync_source(source_id: str, keys: Dict[str, str]) -> Dict[str, Any]:
    """Fetch and normalize IOCs from a single source. Returns {'iocs': [...], 'error': str|None}."""
    async with httpx.AsyncClient(timeout=_TIMEOUT) as c:
        try:
            if source_id == "alienvault_otx":
                if not keys.get("otx"): return {"error": "OTX API key not configured"}
                iocs = await fetch_otx(c, keys["otx"])
            elif source_id == "abuseipdb":
                if not keys.get("abuseipdb"): return {"error": "AbuseIPDB API key not configured"}
                iocs = await fetch_abuseipdb(c, keys["abuseipdb"])
            elif source_id == "talos":
                iocs = await fetch_talos(c)
            elif source_id == "cins_army":
                iocs = await fetch_cins_army(c)
            elif source_id == "threatfox":
                iocs = await fetch_threatfox(c, auth_key=keys.get("abusech", ""))
            elif source_id == "malwarebazaar":
                iocs = await fetch_malwarebazaar(c, auth_key=keys.get("abusech", ""))
            elif source_id == "urlhaus":
                iocs = await fetch_urlhaus(c)
            elif source_id == "malwarebytes":
                iocs = await fetch_malwarebytes(c)
            elif source_id == "virustotal_enterprise":
                if not keys.get("virustotal"): return {"error": "VirusTotal API key not configured"}
                iocs = await fetch_virustotal_enterprise(c, keys["virustotal"])
            else:
                return {"error": f"Source '{source_id}' does not offer a bulk feed"}
            return {"iocs": iocs, "error": None}
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP {e.response.status_code} from source"}
        except Exception as e:
            return {"error": str(e)}
