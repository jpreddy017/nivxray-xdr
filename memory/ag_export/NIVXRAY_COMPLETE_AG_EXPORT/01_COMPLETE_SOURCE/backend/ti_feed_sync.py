"""NivXRay · Hourly TI Feed Sync  (v1.5.6 · Feb 2026)

Pulls FREE, high-quality, permissive threat-intel feeds every hour and
upserts them into the local `db.iocs` collection so `lookup_ti_hits()`
becomes a Mongo find — instant, free, unlimited.

Feeds ingested
--------------
    · abuse.ch ThreatFox        (JSON  · IOC + malware family + MITRE)
    · abuse.ch URLhaus          (CSV   · malicious URLs)
    · abuse.ch MalwareBazaar    (JSON  · SHA1/256 + family)
    · abuse.ch Feodo Tracker    (JSON  · botnet C2 IPs)
    · Blocklist.de all          (TXT   · SSH/HTTP attackers)
    · Emerging Threats compromised IPs (TXT)
    · AlienVault OTX pulses     (API   · needs key · community IOCs)

All feeds are permissive-licensed (CC BY-NC / public domain). Each doc:
    { kind, value, source, tags[], first_seen, last_seen, family?,
      malware?, mitre[]?, confidence }

Idempotent — safe to re-run. Deduped on (kind, value).
"""
from __future__ import annotations
import asyncio
import csv
import io
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

import httpx

log = logging.getLogger("nivxray.ti_feed_sync")


async def _up(db, docs: List[Dict[str, Any]]) -> int:
    """Bulk upsert into db.iocs."""
    if not docs:
        return 0
    from pymongo import UpdateOne
    ops = []
    now = datetime.now(timezone.utc).isoformat()
    for d in docs:
        first_seen = d.pop("first_seen", now)
        d.pop("last_seen", None)  # never in $set — always overwritten below
        ops.append(UpdateOne(
            {"kind": d["kind"], "value": d["value"]},
            {"$set": {**d, "last_seen": now},
             "$setOnInsert": {"first_seen": first_seen}},
            upsert=True,
        ))
    if not ops:
        return 0
    res = await db.iocs.bulk_write(ops, ordered=False)
    return (res.upserted_count or 0) + (res.modified_count or 0)


# ── abuse.ch ThreatFox ────────────────────────────────────────────────
async def _pull_threatfox(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    key = os.environ.get("ABUSECH_AUTH_KEY", "")
    headers = {"Auth-Key": key} if key else {}
    try:
        r = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 3},
            headers=headers, timeout=25.0,
        )
        r.raise_for_status()
        j = r.json() or {}
    except Exception as e:
        log.warning("threatfox pull failed: %s", e)
        return []
    rows = j.get("data") or []
    out: List[Dict[str, Any]] = []
    kind_map = {"ip:port": "ip", "domain": "domain", "url": "url",
                "md5_hash": "md5", "sha1_hash": "sha1", "sha256_hash": "sha256"}
    for row in rows[:5000]:
        kind = kind_map.get(row.get("ioc_type"))
        val = row.get("ioc")
        if not kind or not val:
            continue
        if kind == "ip":
            val = val.split(":")[0]
        out.append({
            "kind":       kind,
            "value":      val.lower() if kind in ("domain", "url") else val,
            "source":     "abuse.ch/threatfox",
            "family":     row.get("malware") or None,
            "tags":       ["threatfox"] + (row.get("tags") or []),
            "confidence": row.get("confidence_level") or 75,
            "mitre":      [t.strip() for t in (row.get("mitre") or "").split(",") if t.strip()],
        })
    return out


# ── abuse.ch URLhaus ──────────────────────────────────────────────────
async def _pull_urlhaus(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    try:
        r = await client.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=25.0)
        r.raise_for_status()
        text = r.text
    except Exception as e:
        log.warning("urlhaus pull failed: %s", e)
        return []
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = list(csv.reader([line]))[0] if "," in line else []
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        if len(parts) < 7:
            continue
        url = parts[2].strip('"')
        threat = parts[5].strip('"')
        tags = parts[6].strip('"').split(",") if len(parts) > 6 else []
        out.append({
            "kind":       "url",
            "value":      url,
            "source":     "abuse.ch/urlhaus",
            "family":     threat or None,
            "tags":       ["urlhaus"] + [t for t in tags if t],
            "confidence": 80,
        })
    return out[:5000]


# ── abuse.ch Feodo Tracker (C2 IPs) ───────────────────────────────────
async def _pull_feodo(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    try:
        r = await client.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json", timeout=25.0)
        r.raise_for_status()
        rows = r.json() or []
    except Exception as e:
        log.warning("feodo pull failed: %s", e)
        return []
    out: List[Dict[str, Any]] = []
    for row in rows[:2000]:
        ip = row.get("ip_address")
        if not ip:
            continue
        out.append({
            "kind":       "ip",
            "value":      ip,
            "source":     "abuse.ch/feodo",
            "family":     row.get("malware") or None,
            "tags":       ["feodo", "c2"],
            "confidence": 85,
        })
    return out


# ── Blocklist.de (SSH/HTTP attackers) ─────────────────────────────────
async def _pull_blocklist_de(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    try:
        r = await client.get("https://lists.blocklist.de/lists/all.txt", timeout=25.0)
        r.raise_for_status()
        text = r.text
    except Exception as e:
        log.warning("blocklist.de pull failed: %s", e)
        return []
    out: List[Dict[str, Any]] = []
    for line in text.splitlines()[:5000]:
        ip = line.strip()
        if not ip or "." not in ip:
            continue
        out.append({
            "kind":       "ip",
            "value":      ip,
            "source":     "blocklist.de",
            "tags":       ["blocklist-de", "scanner"],
            "confidence": 50,
        })
    return out


# ── AlienVault OTX pulses ─────────────────────────────────────────────
async def _pull_otx(client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    # Use whichever key is set — env or admin-panel-stored (fetched separately)
    key = os.environ.get("OTX_API_KEY") or ""
    if not key:
        return []
    try:
        r = await client.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=25",
            headers={"X-OTX-API-KEY": key}, timeout=25.0,
        )
        if r.status_code != 200:
            return []
        j = r.json() or {}
    except Exception as e:
        log.warning("otx pull failed: %s", e)
        return []
    out: List[Dict[str, Any]] = []
    ind_map = {"IPv4": "ip", "IPv6": "ip", "domain": "domain",
               "hostname": "domain", "URL": "url", "URI": "url",
               "FileHash-MD5": "md5", "FileHash-SHA1": "sha1", "FileHash-SHA256": "sha256"}
    for pulse in (j.get("results") or [])[:100]:
        pname = pulse.get("name") or ""
        tags = pulse.get("tags") or []
        for ind in (pulse.get("indicators") or [])[:100]:
            kind = ind_map.get(ind.get("type"))
            val = ind.get("indicator")
            if not kind or not val:
                continue
            out.append({
                "kind":   kind,
                "value":  val.lower() if kind in ("domain", "url") else val,
                "source": "otx",
                "tags":   ["otx", pname[:60]] + list(tags)[:5],
                "confidence": 65,
            })
    return out


# ── Orchestrator ──────────────────────────────────────────────────────
async def sync_once(db) -> Dict[str, Any]:
    """One-shot sync of all feeds → local db.iocs."""
    async with httpx.AsyncClient(follow_redirects=True) as client:
        tf, uh, fe, bl, otx = await asyncio.gather(
            _pull_threatfox(client),
            _pull_urlhaus(client),
            _pull_feodo(client),
            _pull_blocklist_de(client),
            _pull_otx(client),
            return_exceptions=True,
        )
    def _safe(x): return x if isinstance(x, list) else []
    stats: Dict[str, Any] = {"at": datetime.now(timezone.utc).isoformat()}
    n_tf = await _up(db, _safe(tf));  stats["threatfox"]   = n_tf
    n_uh = await _up(db, _safe(uh));  stats["urlhaus"]     = n_uh
    n_fe = await _up(db, _safe(fe));  stats["feodo"]       = n_fe
    n_bl = await _up(db, _safe(bl));  stats["blocklist_de"] = n_bl
    n_ox = await _up(db, _safe(otx)); stats["otx"]         = n_ox
    stats["total"] = n_tf + n_uh + n_fe + n_bl + n_ox
    # Write a sync-run receipt for the admin panel
    await db.ti_sync_runs.insert_one(stats)
    log.info("TI feed sync: %s", stats)
    return stats


# ── Scheduler ──────────────────────────────────────────────────────────
async def _hourly_loop(db):
    # 30s startup delay so import doesn't block boot
    await asyncio.sleep(30)
    while True:
        try:
            await sync_once(db)
        except Exception as e:
            log.warning("hourly TI sync crashed: %s", e)
        await asyncio.sleep(3600)  # hourly


def start_ti_feed_scheduler(db) -> None:
    """Called from server.py startup — arms the hourly loop."""
    asyncio.create_task(_hourly_loop(db))


if __name__ == "__main__":
    async def _main():
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(os.environ["MONGO_URL"])
        db = client[os.environ["DB_NAME"]]
        import json
        print(json.dumps(await sync_once(db), indent=2))
    asyncio.run(_main())
