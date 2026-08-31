"""
/api/admin/content-supply-chain/* · Detection Content Supply Chain
compatibility report + inventory summary endpoints.

Read-only.  Serves the authoritative `detection_content` collection
that the SigmaHQ (and future) ingestion pipeline writes into.  If
the collection is empty (nothing has been ingested yet) the
endpoint returns an honest zero-report — no fabricated numbers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from deps import db, require_admin
from detection_content.model import COLLECTION, LifecycleState


router = APIRouter(prefix="/admin/content-supply-chain",
                     tags=["content-supply-chain"])


@router.get("/report")
async def compatibility_report(user=Depends(require_admin)):
    """
    Return the full-corpus compatibility report shape defined in
    the P0 spec: per-milestone counts + per-source rollup + per-
    product rollup + `unsupported_reasons`.
    """
    coll = db[COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return _empty_report()

    # Milestone counts (each is a distinct set of state_history entries).
    milestones = {}
    for s in LifecycleState:
        milestones[s.value] = await coll.count_documents(
            {"state_history": s.value}
        )

    # Source rollup
    sources: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$source", "n": {"$sum": 1}}}
    ]):
        sources[r["_id"]] = r["n"]

    # Product rollup (top 15)
    products: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$unwind": {"path": "$platform", "preserveNullAndEmptyArrays": True}},
        {"$group":  {"_id": "$platform", "n": {"$sum": 1}}},
        {"$sort":   {"n": -1}},
        {"$limit":  15},
    ]):
        products[r["_id"] or "unknown"] = r["n"]

    return {
        "total_content":       total,
        "milestones":          milestones,
        "sources":             sources,
        "products":            products,
        "guardrails": {
            "active_content_requires":  list(sorted(
                s.value for s in {LifecycleState.PARSED,
                                     LifecycleState.VALID,
                                     LifecycleState.SUPPORTED,
                                     LifecycleState.EXECUTION_READY,
                                     LifecycleState.ENABLED})),
            "supply_chain_phase":       "phase-1-inventory",
            "notes":                   "Engine binding + execution testing are subsequent slices. No document is ACTIVE until every required milestone is recorded.",
        },
    }


@router.get("/samples")
async def content_samples(limit: int = 20, user=Depends(require_admin)):
    """Small sample of the collection for spot-checks."""
    coll = db[COLLECTION]
    if await coll.count_documents({}) == 0:
        return {"samples": [], "message": "No content ingested yet."}
    items = []
    async for d in coll.find(
        {}, {"_id": 0, "raw_body": 0, "field_mappings": 0}
    ).limit(min(limit, 100)):
        items.append(d)
    return {"samples": items, "count": len(items)}


def _empty_report():
    return {
        "total_content":  0,
        "milestones":     {s.value: 0 for s in LifecycleState},
        "sources":        {},
        "products":       {},
        "guardrails": {
            "supply_chain_phase":  "not-yet-ingested",
            "notes":              "Detection Content Supply Chain has not run yet. Run `python -m detection_content.sigma_ingest` after cloning SigmaHQ under /var/nivxray/content/sigma to populate the authoritative content store.",
        },
    }
