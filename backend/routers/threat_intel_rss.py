"""Threat-Intel RSS Crawler — P1 (Feb 2026)

Periodically crawls a curated list of CTI feeds (BleepingComputer, Unit42,
The DFIR Report, Talos, Google Cloud/Mandiant, etc.), keyword-filters for
obfuscation / detection-engineering relevance, condenses each hit into a
directive-form draft (reusing `training_notes_sync.sync_training_note_url`),
and stages the result in `db.pending_training_notes` for admin review.

Endpoints (all under /api):
  GET   /threat-intel/rss/feeds                — configured feeds + last-crawl meta
  POST  /threat-intel/rss/crawl                — manual crawl (admin only)
  GET   /threat-intel/rss/pending              — inbox list (admin only)
  POST  /threat-intel/rss/pending/{id}/promote — save into admin_models as training_note
  POST  /threat-intel/rss/pending/{id}/dismiss — mark dismissed
  DELETE /threat-intel/rss/pending/{id}        — hard delete

The crawler runs at server startup (deferred by 30 s) and then every 6 h.
Set `CTI_RSS_INTERVAL_HOURS` in env to change cadence; set to 0 to disable.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import feedparser
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin

router = APIRouter()


# ─── Curated feeds ─────────────────────────────────────────────────────
# Each entry: id (stable), name, url, tags (auto-applied to promoted notes)
FEEDS: List[Dict[str, Any]] = [
    {
        "id": "bleepingcomputer",
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "tags": ["cti", "news"],
    },
    {
        "id": "unit42",
        "name": "Palo Alto Unit 42",
        "url": "https://unit42.paloaltonetworks.com/feed/",
        "tags": ["cti", "malware-research"],
    },
    {
        "id": "dfir_report",
        "name": "The DFIR Report",
        "url": "https://thedfirreport.com/feed/",
        "tags": ["cti", "dfir", "attack-chain"],
    },
    {
        "id": "talos",
        "name": "Cisco Talos Intelligence",
        "url": "https://blog.talosintelligence.com/feeds/posts/default",
        "tags": ["cti", "vulns"],
    },
    {
        "id": "mandiant",
        "name": "Google Cloud / Mandiant Threat Intel",
        "url": "https://cloud.google.com/blog/topics/threat-intelligence/rss",
        "tags": ["cti", "apt"],
    },
    {
        "id": "microsoft_security",
        "name": "Microsoft Security Blog",
        "url": "https://www.microsoft.com/en-us/security/blog/feed/",
        "tags": ["cti", "windows"],
    },
    {
        "id": "checkpoint",
        "name": "Check Point Research",
        "url": "https://research.checkpoint.com/feed/",
        "tags": ["cti", "malware-research"],
    },
    {
        "id": "sans_isc",
        "name": "SANS Internet Storm Center",
        "url": "https://isc.sans.edu/rssfeed_full.xml",
        "tags": ["cti", "handler-diaries"],
    },
]

# Keyword-relevance filter — an article is only worth condensing if its
# title+summary hit at least ONE of these terms (case-insensitive).
KEYWORDS: List[str] = [
    "obfuscat", "powershell", "cmd.exe", "wscript", "cscript", "vbscript",
    "base64", "encoded", "encoding", "hex-encoded", "hexstring",
    "malware", "ransomware", "loader", "stealer", "backdoor", "webshell",
    "web shell", "rootkit", "wiper", "cradle", "downloader", "dropper",
    "c2", "c&c", "command and control", "beacon",
    "mitre", "att&ck", "t10", "t11", "t12", "t13", "t14", "t15", "t16",
    "lolbin", "lolbas", "living off the land", "living-off-the-land",
    "evasion", "amsi", "etw", "bypass", "unhook", "process injection",
    "ioc", "yara", "regex", "detection rule",
    "certutil", "bitsadmin", "mshta", "regsvr32", "rundll32",
    "vssadmin", "wevtutil", "sc.exe", "schtasks",
    "office macro", "vba", "excel", "onenote", "hta",
    "cobalt strike", "brute ratel", "sliver", "metasploit",
    "emotet", "qakbot", "trickbot", "icedid", "bumblebee",
    "lockbit", "blackcat", "alphv", "royal", "black basta",
    "apt29", "apt28", "apt41", "lazarus", "kimsuky", "fin7", "fin8",
]

_MAX_ARTICLES_PER_FEED = 15
_HTTP_UA = "NivXRay/1.0 (+cti-rss-crawler)"


# ─── Pydantic models ───────────────────────────────────────────────────
class CrawlIn(BaseModel):
    feed_ids: Optional[List[str]] = Field(default=None,
        description="If given, crawl only these feeds. Otherwise crawl all.")
    condense_with_llm: bool = Field(default=True,
        description="Set false for a fast keyword-only crawl (no LLM cost).")


class PromoteIn(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    tags: Optional[List[str]] = None


# ─── Helpers ───────────────────────────────────────────────────────────
def _keyword_score(title: str, summary: str) -> tuple[int, List[str]]:
    """Return (hit_count, matched_keywords) for the article haystack."""
    hay = f"{title}\n{summary}".lower()
    hits = [kw for kw in KEYWORDS if kw in hay]
    return len(hits), hits


def _canon_url(url: str) -> str:
    """Drop query string + fragment so refeeds don't create duplicates."""
    return re.sub(r"[?#].*$", "", (url or "").strip())


async def _existing_urls(canon_urls: List[str]) -> set[str]:
    """Return the subset of canon_urls already in pending_training_notes
    (any status). Used to skip re-processing on refeed."""
    if not canon_urls:
        return set()
    cur = db.pending_training_notes.find(
        {"canon_url": {"$in": canon_urls}}, {"canon_url": 1}
    )
    return {d["canon_url"] async for d in cur if d.get("canon_url")}


async def _record_feed_meta(feed_id: str, status: str, new_count: int,
                            skipped: int, error: Optional[str] = None) -> None:
    await db.cti_rss_meta.update_one(
        {"_id": feed_id},
        {"$set": {
            "last_sync":    datetime.now(timezone.utc).isoformat(),
            "last_status":  status,
            "last_new":     int(new_count),
            "last_skipped": int(skipped),
            "last_error":   error,
        }},
        upsert=True,
    )


async def _condense_llm(url: str, title_fallback: str, summary_fallback: str
                        ) -> Dict[str, Any]:
    """Try the LLM-powered URL condenser; fall back to a raw draft."""
    try:
        from routers.training_notes_sync import (
            sync_training_note_url, SyncIn,
        )
        # sync_training_note_url is an async endpoint fn that requires admin;
        # invoke its inner logic bypassing the auth dependency by calling
        # it as an ordinary coroutine with a dummy admin user.
        result = await sync_training_note_url(SyncIn(url=url),
                                               user={"role": "admin",
                                                     "email": "rss-crawler@internal"})
        return {
            "title":     result.get("title") or title_fallback[:120],
            "body":      result.get("body")  or summary_fallback,
            "tags":      result.get("tags") or [],
            "condensed": True,
            "model":     result.get("model"),
        }
    except Exception as e:  # noqa: BLE001
        return {
            "title":         title_fallback[:120],
            "body":          f"{summary_fallback}\n\n— Source: {url}",
            "tags":          [],
            "condensed":     False,
            "condense_error": str(e)[:200],
        }


async def _crawl_one_feed(feed: Dict[str, Any], condense: bool
                          ) -> Dict[str, Any]:
    """Fetch + filter + stage a single feed. Returns per-feed stats."""
    loop = asyncio.get_running_loop()
    # feedparser is sync — run in an executor so we don't block the loop
    def _fetch() -> "feedparser.FeedParserDict":
        return feedparser.parse(
            feed["url"],
            agent=_HTTP_UA,
            request_headers={"User-Agent": _HTTP_UA},
        )
    try:
        parsed = await loop.run_in_executor(None, _fetch)
    except Exception as e:  # noqa: BLE001
        await _record_feed_meta(feed["id"], "error", 0, 0, str(e)[:200])
        return {"feed_id": feed["id"], "status": "error", "error": str(e)[:200],
                "new": 0, "skipped": 0}

    entries = (parsed.entries or [])[:_MAX_ARTICLES_PER_FEED]
    if not entries:
        await _record_feed_meta(feed["id"], "empty", 0, 0)
        return {"feed_id": feed["id"], "status": "empty", "new": 0, "skipped": 0}

    canon = [_canon_url(e.get("link") or "") for e in entries]
    already = await _existing_urls([c for c in canon if c])

    new_notes: List[Dict[str, Any]] = []
    skipped = 0
    now_iso = datetime.now(timezone.utc).isoformat()

    for entry in entries:
        url = _canon_url(entry.get("link") or "")
        if not url or url in already:
            skipped += 1
            continue
        title   = (entry.get("title") or "").strip()
        summary = (entry.get("summary") or entry.get("description") or "").strip()
        # Strip HTML from RSS summaries so keyword match is accurate.
        summary_txt = re.sub(r"<[^>]+>", " ", summary)
        summary_txt = re.sub(r"\s+", " ", summary_txt).strip()

        hit_count, hits = _keyword_score(title, summary_txt)
        if hit_count < 1:
            skipped += 1
            continue

        published = (
            entry.get("published") or entry.get("updated") or now_iso
        )

        # Optional LLM condensation for the highest-signal drafts.
        if condense:
            drafted = await _condense_llm(url, title, summary_txt)
        else:
            drafted = {
                "title": title[:120],
                "body":  (summary_txt[:1400] + (
                    "\n\n… (crawler-only draft — expand via 'Re-fetch with LLM')"
                    if len(summary_txt) > 1400 else ""
                )) + f"\n\n— Source: {url}",
                "tags":  [],
                "condensed": False,
            }

        record = {
            "_id":           str(uuid4()),
            "feed_id":       feed["id"],
            "feed_name":     feed["name"],
            "source_url":    url,
            "canon_url":     url,
            "article_title": title[:200],
            "published_at":  published,
            "keywords_hit":  hits[:12],
            "keyword_score": hit_count,
            "draft_title":   drafted["title"],
            "draft_body":    drafted["body"],
            "draft_tags":    sorted({*feed["tags"], *drafted.get("tags", [])})[:12],
            "condensed":     drafted.get("condensed", False),
            "condense_error": drafted.get("condense_error"),
            "status":        "pending",   # pending | promoted | dismissed
            "created_at":    now_iso,
            "updated_at":    now_iso,
        }
        await db.pending_training_notes.insert_one(record)
        new_notes.append({
            "id": record["_id"],
            "title": record["article_title"],
            "url": url,
            "kw_hits": hits[:5],
            "condensed": record["condensed"],
        })

    await _record_feed_meta(feed["id"], "ok", len(new_notes), skipped)
    return {
        "feed_id":  feed["id"],
        "status":   "ok",
        "new":      len(new_notes),
        "skipped":  skipped,
        "articles": new_notes,
    }


# ─── Public endpoints ─────────────────────────────────────────────────
@router.get("/threat-intel/rss/feeds")
async def list_feeds(user=Depends(get_current_user)):
    """Return the curated feed list with last-crawl meta."""
    meta_docs = {m["_id"]: m async for m in db.cti_rss_meta.find({})}
    out = []
    for f in FEEDS:
        m = meta_docs.get(f["id"]) or {}
        out.append({
            **f,
            "last_sync":    m.get("last_sync"),
            "last_status":  m.get("last_status"),
            "last_new":     m.get("last_new", 0),
            "last_skipped": m.get("last_skipped", 0),
            "last_error":   m.get("last_error"),
        })
    return {"feeds": out, "keywords_count": len(KEYWORDS),
            "interval_hours": _interval_hours()}


@router.post("/threat-intel/rss/crawl")
async def crawl_now(body: CrawlIn, user=Depends(require_admin)):
    """Trigger a crawl NOW. Blocks until all requested feeds are processed."""
    target = FEEDS
    if body.feed_ids:
        target = [f for f in FEEDS if f["id"] in set(body.feed_ids)]
        if not target:
            raise HTTPException(status_code=404, detail="no matching feed_ids")
    results = []
    for f in target:
        results.append(await _crawl_one_feed(f, condense=body.condense_with_llm))
    total_new = sum(r.get("new", 0) for r in results)
    return {"total_new": total_new, "results": results}


@router.get("/threat-intel/rss/pending")
async def list_pending(status: str = "pending", limit: int = 50, skip: int = 0,
                        user=Depends(require_admin)):
    if status not in ("pending", "promoted", "dismissed", "all"):
        raise HTTPException(status_code=422, detail="invalid status filter")
    q = {} if status == "all" else {"status": status}
    total = await db.pending_training_notes.count_documents(q)
    cur = db.pending_training_notes.find(q).sort(
        [("keyword_score", -1), ("created_at", -1)]
    ).skip(max(0, skip)).limit(max(1, min(100, limit)))
    items = [d async for d in cur]
    for d in items:
        # keep the response JSON-clean
        d["id"] = d.pop("_id")
    return {"total": total, "items": items,
            "counts": {
                "pending":   await db.pending_training_notes.count_documents({"status": "pending"}),
                "promoted":  await db.pending_training_notes.count_documents({"status": "promoted"}),
                "dismissed": await db.pending_training_notes.count_documents({"status": "dismissed"}),
            }}


@router.post("/threat-intel/rss/pending/{note_id}/promote")
async def promote_pending(note_id: str, body: PromoteIn,
                          user=Depends(require_admin)):
    """Save a pending draft into `admin_models` as an active training_note.

    Admin may pass title/body/tags to override the auto-generated draft
    before promotion. Once promoted, the pending row is marked so it
    doesn't re-appear in the inbox but stays around as a source-of-truth."""
    doc = await db.pending_training_notes.find_one({"_id": note_id})
    if not doc:
        raise HTTPException(status_code=404, detail="pending note not found")
    if doc.get("status") == "promoted":
        raise HTTPException(status_code=409, detail="already promoted")

    title = (body.title or doc.get("draft_title") or "").strip()[:120]
    text  = (body.body  or doc.get("draft_body")  or "").strip()
    tags  = body.tags if body.tags is not None else doc.get("draft_tags") or []
    if len(text) < 40:
        raise HTTPException(status_code=422, detail="body too short (<40 chars)")

    now_iso = datetime.now(timezone.utc).isoformat()
    admin_model_doc = {
        "kind":            "training_note",
        "name":            title or f"CTI · {doc.get('feed_name')}",
        "enabled":         True,
        "config":          {"body": text, "ref_url": doc.get("source_url"),
                             "ref_source": doc.get("feed_name")},
        "tags":            tags,
        "feedback_pos":    0,
        "feedback_neg":    0,
        "feedback_weight": 0,
        "usage_count":     0,
        "created_at":      now_iso,
        "updated_at":      now_iso,
        "origin":          {"channel": "cti-rss-crawler",
                             "feed_id": doc.get("feed_id"),
                             "pending_id": note_id},
    }
    ins = await db.admin_models.insert_one(admin_model_doc)
    await db.pending_training_notes.update_one(
        {"_id": note_id},
        {"$set": {"status": "promoted", "promoted_at": now_iso,
                   "promoted_admin_model_id": str(ins.inserted_id),
                   "updated_at": now_iso}},
    )
    return {"ok": True, "promoted_id": str(ins.inserted_id),
            "pending_id": note_id, "title": title}


@router.post("/threat-intel/rss/pending/{note_id}/dismiss")
async def dismiss_pending(note_id: str, user=Depends(require_admin)):
    r = await db.pending_training_notes.update_one(
        {"_id": note_id},
        {"$set": {"status": "dismissed",
                   "updated_at": datetime.now(timezone.utc).isoformat()}},
    )
    if r.matched_count == 0:
        raise HTTPException(status_code=404, detail="pending note not found")
    return {"ok": True, "pending_id": note_id, "status": "dismissed"}


@router.delete("/threat-intel/rss/pending/{note_id}")
async def delete_pending(note_id: str, user=Depends(require_admin)):
    r = await db.pending_training_notes.delete_one({"_id": note_id})
    if r.deleted_count == 0:
        raise HTTPException(status_code=404, detail="pending note not found")
    return {"ok": True, "pending_id": note_id, "status": "deleted"}


# ─── Background scheduler ─────────────────────────────────────────────
def _interval_hours() -> int:
    try:
        return max(0, int(os.environ.get("CTI_RSS_INTERVAL_HOURS", "6")))
    except ValueError:
        return 6


_crawler_task: Optional[asyncio.Task] = None


async def _scheduler_loop() -> None:
    """Sleep 30 s at startup then crawl every _interval_hours()."""
    interval = _interval_hours()
    if interval <= 0:
        return
    await asyncio.sleep(30)
    while True:
        try:
            for f in FEEDS:
                await _crawl_one_feed(f, condense=False)  # keyword-only auto crawl
        except Exception as e:  # noqa: BLE001
            # Never let the loop die — log to feed_meta and keep going.
            try:
                await db.cti_rss_meta.update_one(
                    {"_id": "_scheduler"},
                    {"$set": {"last_error": str(e)[:200],
                               "last_sync": datetime.now(timezone.utc).isoformat()}},
                    upsert=True,
                )
            except Exception:
                pass
        await asyncio.sleep(interval * 3600)


def start_scheduler() -> None:
    """Called from server.py startup event."""
    global _crawler_task
    if _crawler_task is not None and not _crawler_task.done():
        return
    try:
        _crawler_task = asyncio.create_task(_scheduler_loop())
    except RuntimeError:
        # Called outside a running loop (rare) — the FastAPI startup
        # hook wraps us so this should always find a loop.
        pass
