"""Free Public IOC Feeds — Feb 2026 v1.3.0

Pulls from the same public sources nivxmachines.com aggregates:
  - SANS ISC DShield  (top attacker IPs)
  - URLhaus abuse.ch  (live malware URLs)
  - Feodo Tracker     (active botnet C2 IPs)

Populates the `iocs` collection so that any post-decode lookup via
`/api/threat-intel/lookup/{value}` gets an instant local hit — no
external API key needed. Runs on-demand via `/api/threat-intel/feeds/sync`.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pymongo import MongoClient

from deps import get_current_user

router = APIRouter()

_client = MongoClient(os.environ.get("MONGO_URL"))
_db     = _client[os.environ.get("DB_NAME")]
_iocs   = _db.iocs


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _fetch_dshield(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """SANS ISC DShield top attacker IPs."""
    r = await c.get("https://isc.sans.edu/api/topips/records/50?json", timeout=20)
    r.raise_for_status()
    out: List[Dict[str, Any]] = []
    try:
        data = r.json()
        rows = data if isinstance(data, list) else data.get("topips") or []
        for row in rows[:50]:
            ip = row.get("source") or row.get("ipaddress") or row.get("ip") or ""
            if not ip:
                continue
            out.append({
                "value":    ip,
                "type":     "ip",
                "source":   "sans_dshield",
                "reports":  int(row.get("reports") or row.get("attacks") or 0),
                "first_seen": row.get("mindate") or _now(),
                "severity": "high",
                "tags":     ["attacker", "honeypot-observed"],
                "cached_at": _now(),
            })
    except Exception:
        pass
    return out


async def _fetch_urlhaus(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """URLhaus recent malware URLs."""
    r = await c.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=30)
    r.raise_for_status()
    out: List[Dict[str, Any]] = []
    for line in r.text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = [p.strip('"') for p in line.split(",")]
        if len(parts) < 6:
            continue
        # id,dateadded,url,url_status,threat,tags,link,reporter
        url    = parts[2]
        threat = parts[4] if len(parts) > 4 else ""
        tags   = parts[5] if len(parts) > 5 else ""
        if not url.startswith("http"):
            continue
        out.append({
            "value":     url,
            "type":      "url",
            "source":    "urlhaus",
            "threat":    threat,
            "tags":      [t for t in (tags or "").split("|") if t] + ["malware-download"],
            "severity":  "high",
            "first_seen": parts[1] if len(parts) > 1 else _now(),
            "cached_at": _now(),
        })
        if len(out) >= 500:
            break
    return out


async def _fetch_feodo(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """Feodo Tracker active botnet C2 IPs."""
    r = await c.get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt", timeout=20)
    r.raise_for_status()
    out: List[Dict[str, Any]] = []
    for line in r.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Basic IPv4 sanity
        if line.count(".") == 3 and all(p.isdigit() for p in line.split(".")):
            out.append({
                "value":     line,
                "type":      "ip",
                "source":    "feodo_tracker",
                "tags":      ["botnet-c2", "active"],
                "severity":  "critical",
                "cached_at": _now(),
            })
    return out


async def _fetch_cisa_kev(c: httpx.AsyncClient) -> List[Dict[str, Any]]:
    """CISA Known Exploited Vulnerabilities catalog."""
    r = await c.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=30)
    r.raise_for_status()
    data = r.json()
    out: List[Dict[str, Any]] = []
    for v in (data.get("vulnerabilities") or [])[:200]:
        cve = v.get("cveID")
        if not cve:
            continue
        out.append({
            "value":       cve,
            "type":        "cve",
            "source":      "cisa_kev",
            "vendor":      v.get("vendorProject"),
            "product":     v.get("product"),
            "name":        v.get("vulnerabilityName"),
            "ransomware":  v.get("knownRansomwareCampaignUse") == "Known",
            "date_added":  v.get("dateAdded"),
            "severity":    "critical" if v.get("knownRansomwareCampaignUse") == "Known" else "high",
            "tags":        ["kev", "actively-exploited"],
            "cached_at":   _now(),
        })
    return out


@router.post("/threat-intel/feeds/sync")
async def sync_public_feeds(user=Depends(get_current_user)):
    """Pull latest IOCs from all 4 free public feeds and upsert into local cache."""
    stats = {"dshield": 0, "urlhaus": 0, "feodo": 0, "cisa_kev": 0, "errors": []}
    async with httpx.AsyncClient(follow_redirects=True,
                                  headers={"User-Agent": "NivXRay/1.3 (+public-feed-sync)"}) as c:
        for name, fn in (("dshield", _fetch_dshield),
                         ("urlhaus", _fetch_urlhaus),
                         ("feodo",   _fetch_feodo),
                         ("cisa_kev", _fetch_cisa_kev)):
            try:
                rows = await fn(c)
                for row in rows:
                    _iocs.update_one(
                        {"value": row["value"], "source": row["source"]},
                        {"$set": row},
                        upsert=True,
                    )
                stats[name] = len(rows)
            except Exception as e:
                stats["errors"].append(f"{name}: {type(e).__name__}: {str(e)[:120]}")
    stats["total_upserted"] = stats["dshield"] + stats["urlhaus"] + stats["feodo"] + stats["cisa_kev"]
    stats["synced_at"] = _now()
    return stats


@router.get("/threat-intel/feeds/status")
async def feeds_status(user=Depends(get_current_user)):
    """Show current count per source in local cache."""
    pipeline = [{"$group": {"_id": "$source", "count": {"$sum": 1},
                             "last_cached": {"$max": "$cached_at"}}}]
    rows = list(_iocs.aggregate(pipeline))
    return {"sources": rows, "total": _iocs.count_documents({})}
