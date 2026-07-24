"""NivXRay Decoded Artifact Store — P0.2

Content-addressed cache of every command that has ever passed through the
deterministic Orchestrator. Purpose:

  1. Performance — never re-decode the same script twice. Enterprise
     incidents often contain identical loaders across dozens of hosts.
  2. Evidence Provenance — every finding produced by the pipeline can
     be traced back to a stable, hash-identified artifact that other
     tools (Timeline, Evidence Graph, Report Writer) consume the SAME
     way, guaranteeing "show your work" reproducibility.

Key       :  SHA-256(command_line)
Collection:  v2_decoded_payloads

Schema:
  {
    "_id":            <sha256>,          # content address (also `sha256`)
    "sha256":         <sha256>,
    "command_binary": str,               # e.g. "powershell"
    "command_line":   str (≤ 2 KB preview + full length in report),
    "command_bytes":  int,
    "report":         <AnalystReport dict>,     # full deterministic report
    "iocs_summary":   {ips[], urls[], domains[], sha256[], sha1[], md5[]},
    "mitre_ids":      [str, …],
    "verdict":        str,
    "risk_score":     int,
    "trace_layers":   int,
    "elapsed_ms_first": int,
    "provenance": {
        "first_seen":    ISO-8601,
        "last_seen":     ISO-8601,
        "hit_count":     int,          # every REUSE increments this
        "seen_in_jobs":  [job_id, …],  # capped at 50 (most recent)
        "sources":       [str, …],     # e.g. "AUTO_INVESTIGATE"
    },
    "created_at":     ISO-8601,
  }
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from deps import db

COLL = "v2_decoded_payloads"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _report_summary(report_dict: dict) -> dict:
    """Extract the fast-lookup fields from a full AnalystReport dict."""
    findings = report_dict.get("findings") or {}
    iocs = findings.get("iocs") or {}
    ioc_summary = {}
    for k in ("ips", "urls", "domains", "sha256", "sha1", "md5"):
        v = iocs.get(k)
        if isinstance(v, list) and v:
            ioc_summary[k] = list(dict.fromkeys(v))[:32]
    mitre = findings.get("mitre_techniques") or []
    mitre_ids = list(dict.fromkeys([m.get("id") for m in mitre if m.get("id")]))
    return {
        "iocs_summary": ioc_summary,
        "mitre_ids":    mitre_ids,
        "verdict":      findings.get("verdict") or "unknown",
        "risk_score":   int(findings.get("risk_score") or 0),
        "trace_layers": len(report_dict.get("trace") or []),
        "elapsed_ms_first": int(report_dict.get("elapsed_ms") or 0),
    }


async def get_artifact(sha256: str) -> dict | None:
    return await db[COLL].find_one({"_id": sha256}, {"_id": 0})


async def upsert_artifact(
    *,
    command_binary: str,
    command_line: str,
    report_dict: dict,
    job_id: str | None = None,
    source: str = "AUTO_INVESTIGATE",
    pipeline_version: str = "",
) -> tuple[str, bool]:
    """Insert (or refresh) an artifact keyed by SHA-256 of the command
    line. Returns `(sha256, was_new)`. `was_new` is False for a cache hit
    — the artifact already existed and provenance was updated.
    """
    h = sha256_of(command_line)
    now = _now()
    existing = await db[COLL].find_one({"_id": h}, {"_id": 1})
    if existing:
        # Cache hit — bump provenance only, never mutate report.
        push_job = job_id and job_id or None
        set_ops = {
            "provenance.last_seen": now,
        }
        inc_ops = {"provenance.hit_count": 1}
        push_ops: dict[str, Any] = {}
        if push_job:
            push_ops["provenance.seen_in_jobs"] = {"$each": [push_job], "$slice": -50}
        push_ops["provenance.sources"] = {"$each": [source], "$slice": -20}
        update: dict[str, Any] = {"$set": set_ops, "$inc": inc_ops}
        if push_ops:
            update["$push"] = push_ops
        await db[COLL].update_one({"_id": h}, update)
        return h, False

    doc = {
        "_id":            h,
        "sha256":         h,
        "command_binary": command_binary,
        "command_line":   command_line[:2048],
        "command_full_bytes": len(command_line.encode("utf-8", errors="ignore")),
        "report":         report_dict,
        "pipeline_version": pipeline_version,
        **_report_summary(report_dict),
        "provenance": {
            "first_seen":   now,
            "last_seen":    now,
            "hit_count":    0,           # only reuses bump this; first insert is 0
            "seen_in_jobs": [job_id] if job_id else [],
            "sources":      [source],
        },
        "created_at": now,
    }
    try:
        await db[COLL].insert_one(doc)
    except Exception:
        # Race condition: another worker inserted the same hash. Treat as
        # a hit — bump provenance and move on.
        await db[COLL].update_one(
            {"_id": h},
            {"$set": {"provenance.last_seen": now},
             "$inc": {"provenance.hit_count": 1}},
        )
        return h, False
    return h, True


async def stats() -> dict:
    """Return aggregate cache metrics for the dashboard."""
    coll = db[COLL]
    total = await coll.count_documents({})
    hits_pipeline = [
        {"$group": {
            "_id": None,
            "total_hits": {"$sum": {"$ifNull": ["$provenance.hit_count", 0]}},
            "avg_layers": {"$avg": "$trace_layers"},
        }},
    ]
    agg = await coll.aggregate(hits_pipeline).to_list(1)
    top_pipeline = [
        {"$sort": {"provenance.hit_count": -1}},
        {"$limit": 8},
        {"$project": {
            "_id": 0, "sha256": 1, "command_binary": 1,
            "verdict": 1, "risk_score": 1, "trace_layers": 1,
            "hit_count": "$provenance.hit_count",
            "last_seen": "$provenance.last_seen",
            "mitre_ids": 1, "command_line": 1,
        }},
    ]
    top = await coll.aggregate(top_pipeline).to_list(8)
    return {
        "total_artifacts": total,
        "total_reuses":    (agg[0]["total_hits"] if agg else 0),
        "avg_trace_layers": round((agg[0]["avg_layers"] if agg else 0.0) or 0.0, 2),
        "top_artifacts":   top,
    }


async def list_recent(limit: int = 25) -> list[dict]:
    cur = db[COLL].find({}, {"_id": 0, "report": 0}).sort("provenance.last_seen", -1).limit(limit)
    return await cur.to_list(limit)


async def ensure_indexes() -> None:
    await db[COLL].create_index("provenance.last_seen")
    await db[COLL].create_index("verdict")
    await db[COLL].create_index("mitre_ids")
