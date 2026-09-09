"""NivXRay Learning Framework (Feb-2026 roadmap — P1).

When an analyst corrects a decoding (e.g. the engine picked ROT-N but the
truth was single-byte XOR), record the input characteristics + confidence
deltas so we can tune the reasoning engine's heuristics over time.

Storage schema (MongoDB collection `learning_events`):
    {
        _id:                 ObjectId,
        created_at:          ISO-8601 UTC,
        input_snippet:       str[:500],
        input_profile:       dict (from characterize.as_dict()),
        input_linguistic_score: float,
        engine_output:       str[:500],
        engine_chain:        [{op, args}, ...],
        engine_confidence:   float,
        engine_reasoning:    dict | None,
        corrected_output:    str[:500],
        corrected_chain:     [{op, args}, ...],
        corrected_confidence: float | None,
        confidence_delta:    float,       # corrected - engine
        analyst_id:          str | None,
        notes:               str | None,
    }

The learning framework is READ-heavy in the future ("what samples still
have low confidence?") and WRITE-cheap ("one insert per correction").
No aggregation, no ML training at ingest time — that's a separate
offline pipeline that can run on demand.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


COLLECTION_NAME = "learning_events"


def _clip(text: Optional[str], limit: int = 500) -> Optional[str]:
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + f"…[+{len(text) - limit} chars]"


def build_event(
    *,
    input_text: str,
    engine_output: str,
    engine_chain: List[Dict[str, Any]],
    engine_confidence: Optional[float] = None,
    engine_reasoning: Optional[Dict[str, Any]] = None,
    corrected_output: str,
    corrected_chain: Optional[List[Dict[str, Any]]] = None,
    corrected_confidence: Optional[float] = None,
    analyst_id: Optional[str] = None,
    notes: Optional[str] = None,
) -> Dict[str, Any]:
    """Compose a learning-event document ready to insert."""
    # Import lazily so this module doesn't force reasoning.* eager loading
    from .characterize import characterize
    from .scorer import linguistic_score

    profile = characterize(input_text).as_dict()
    input_score = linguistic_score(input_text)

    corrected_conf = corrected_confidence
    if corrected_conf is None and corrected_output:
        try:
            from .confidence_engine import compute_confidence
            corrected_conf = compute_confidence(
                corrected_output, input_text=input_text,
            ).confidence
        except Exception:
            corrected_conf = None

    engine_conf = engine_confidence
    if engine_conf is None:
        try:
            from .confidence_engine import compute_confidence
            engine_conf = compute_confidence(
                engine_output, input_text=input_text,
            ).confidence
        except Exception:
            engine_conf = None

    delta = None
    if engine_conf is not None and corrected_conf is not None:
        delta = round(corrected_conf - engine_conf, 4)

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "input_snippet": _clip(input_text),
        "input_profile": profile,
        "input_linguistic_score": round(input_score, 4),
        "engine_output": _clip(engine_output),
        "engine_chain": engine_chain or [],
        "engine_confidence": engine_conf,
        "engine_reasoning": engine_reasoning,
        "corrected_output": _clip(corrected_output),
        "corrected_chain": corrected_chain or [],
        "corrected_confidence": corrected_conf,
        "confidence_delta": delta,
        "analyst_id": analyst_id,
        "notes": _clip(notes, limit=1000),
    }


async def record_correction(db, **kwargs) -> Dict[str, Any]:
    """Insert a learning event into MongoDB.

    Returns the inserted document (with `_id` as str).
    """
    event = build_event(**kwargs)
    result = await db[COLLECTION_NAME].insert_one(event)
    event["_id"] = str(result.inserted_id)
    return event


async def list_recent(db, limit: int = 50) -> List[Dict[str, Any]]:
    """Return the most recent `limit` learning events (newest first)."""
    cursor = db[COLLECTION_NAME].find({}).sort("created_at", -1).limit(limit)
    events = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        events.append(doc)
    return events


async def summary(db) -> Dict[str, Any]:
    """Cheap aggregation: total events, mean confidence_delta, top-3
    op-substitution pairs (engine_op → corrected_op).

    Callable from an admin panel — no side effects.
    """
    total = await db[COLLECTION_NAME].count_documents({})
    if total == 0:
        return {
            "total_events": 0, "mean_confidence_delta": None,
            "top_substitutions": [],
        }
    pipeline_delta = [
        {"$match": {"confidence_delta": {"$ne": None}}},
        {"$group": {"_id": None, "avg": {"$avg": "$confidence_delta"}}},
    ]
    delta_docs = await db[COLLECTION_NAME].aggregate(pipeline_delta).to_list(length=1)
    mean_delta = round(delta_docs[0]["avg"], 4) if delta_docs else None

    pipeline_subs = [
        {"$match": {"engine_chain.0": {"$exists": True},
                    "corrected_chain.0": {"$exists": True}}},
        {"$project": {
            "engine_first": {"$arrayElemAt": ["$engine_chain.op", 0]},
            "corrected_first": {"$arrayElemAt": ["$corrected_chain.op", 0]},
        }},
        {"$match": {"$expr": {"$ne": ["$engine_first", "$corrected_first"]}}},
        {"$group": {
            "_id": {"engine": "$engine_first", "corrected": "$corrected_first"},
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1}},
        {"$limit": 3},
    ]
    sub_docs = await db[COLLECTION_NAME].aggregate(pipeline_subs).to_list(length=3)
    top_subs = [
        {"engine_op": d["_id"].get("engine"),
         "corrected_op": d["_id"].get("corrected"),
         "count": d["count"]}
        for d in sub_docs
    ]
    return {
        "total_events": total,
        "mean_confidence_delta": mean_delta,
        "top_substitutions": top_subs,
    }
