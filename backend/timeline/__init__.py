"""NivXRay Investigation Timeline (Feb-2026 roadmap #5).

Chronological event log per investigation. Every meaningful action —
decode, correction, promote to corpus, benchmark run, TAXII push, threat
intel enrichment — gets an entry.

Data model
----------

`investigation_events`
    {
        _id, investigation_id (str | "adhoc"),
        created_at (ISO), kind, actor,
        title, summary, metadata (dict), severity ("info"|"success"|"warn"|"fail")
    }

`kind` is a stable enum:
    decode, correction, corpus-promote, benchmark, gate-block, taxii-push,
    threat-intel, sample-library-promote, error, note
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId


COLLECTION = "investigation_events"

VALID_KINDS = {
    "decode", "correction", "corpus-promote", "benchmark", "gate-block",
    "taxii-push", "threat-intel", "sample-library-promote", "error", "note",
    "promote", "enrichment",
}

VALID_SEVERITY = {"info", "success", "warn", "fail"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def investigation_id_for(input_text: Optional[str]) -> str:
    """Return the stable 16-hex investigation ID for a given input, or
    "adhoc" when no input was provided."""
    if not input_text:
        return "adhoc"
    return hashlib.sha256(
        input_text.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


async def record(
    db,
    *,
    kind: str,
    title: str,
    investigation_id: Optional[str] = None,
    input_text: Optional[str] = None,
    actor: Optional[str] = None,
    summary: str = "",
    metadata: Optional[Dict[str, Any]] = None,
    severity: str = "info",
) -> Dict[str, Any]:
    """Insert one investigation-timeline event.

    Investigation ID resolution priority:
        1. explicit ``investigation_id`` argument
        2. ``sha256(input_text)[:16]`` when ``input_text`` is provided
        3. ``"adhoc"`` fallback
    """
    if kind not in VALID_KINDS:
        kind = "note"
    if severity not in VALID_SEVERITY:
        severity = "info"
    resolved_iid = (
        investigation_id
        or investigation_id_for(input_text)
    )
    doc: Dict[str, Any] = {
        "investigation_id": resolved_iid,
        "created_at": _now(),
        "kind": kind,
        "actor": actor,
        "title": title[:200],
        "summary": (summary or "")[:800],
        "metadata": metadata or {},
        "severity": severity,
    }
    try:
        r = await db[COLLECTION].insert_one(doc)
        doc["_id"] = str(r.inserted_id)
    except Exception as e:
        doc["_id"] = None
        doc["_error"] = str(e)
    return doc


async def list_events(
    db, investigation_id: str = "adhoc", limit: int = 100,
) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 100), 500))
    cursor = db[COLLECTION].find(
        {"investigation_id": investigation_id}
    ).sort("created_at", -1).limit(limit)
    events: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        events.append(doc)
    return events


async def list_recent(db, limit: int = 100) -> List[Dict[str, Any]]:
    """Global recent-events feed across ALL investigations."""
    limit = max(1, min(int(limit or 100), 500))
    cursor = db[COLLECTION].find({}).sort("created_at", -1).limit(limit)
    events: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        events.append(doc)
    return events


async def list_investigations(db, limit: int = 50) -> List[Dict[str, Any]]:
    """List DISTINCT investigation IDs with their event counts + latest event.

    Used by the workspace UI to show a "recent investigations" panel.
    """
    limit = max(1, min(int(limit or 50), 500))
    pipeline = [
        {"$match": {"investigation_id": {"$ne": "adhoc"}}},
        {"$sort": {"created_at": -1}},
        {"$group": {
            "_id": "$investigation_id",
            "event_count": {"$sum": 1},
            "last_event_at": {"$first": "$created_at"},
            "last_kind": {"$first": "$kind"},
            "last_title": {"$first": "$title"},
            "kinds": {"$addToSet": "$kind"},
            "actors": {"$addToSet": "$actor"},
        }},
        {"$sort": {"last_event_at": -1}},
        {"$limit": limit},
    ]
    cursor = db[COLLECTION].aggregate(pipeline)
    items: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["investigation_id"] = doc.pop("_id")
        items.append(doc)
    return items


async def clear(db, investigation_id: str) -> int:
    """Delete all events for an investigation. Returns count removed."""
    r = await db[COLLECTION].delete_many({"investigation_id": investigation_id})
    return r.deleted_count
