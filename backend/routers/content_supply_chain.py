"""
/api/admin/content-supply-chain/* · Detection Content Supply Chain
compatibility report + inventory summary endpoints.
Also exposes the Engine Registry inventory.

Read-only.  Serves the authoritative `detection_content` and
`xdr_engines` collections.  If a collection is empty, returns an
honest zero-report — no fabricated numbers.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from deps import db, require_admin
from detection_content.model import COLLECTION, LifecycleState
from detection_content.engine_registry import (
    COLLECTION as ENGINES_COLLECTION,
    EngineRole, EngineState,
)
from detection_content.capability_contract import (
    COLLECTION as CONTRACTS_COLLECTION,
    ContractStatus,
)
from detection_content.contract_registry import (
    declare_all_contracts, contract_report,
)


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


# ── Engine Registry ─────────────────────────────────────────────

@router.get("/engines/report")
async def engines_report(user=Depends(require_admin)):
    """
    Return the Engine Registry inventory — real classified roles
    from the codebase.  When empty, returns honest zeros with
    instructions rather than fabricated data.
    """
    coll = db[ENGINES_COLLECTION]
    total = await coll.count_documents({})
    if total == 0:
        return {
            "total_engines":     0,
            "roles":             {r.value: 0 for r in EngineRole},
            "states":            {s.value: 0 for s in EngineState},
            "notes":             "Engine Registry has not been populated. Run detection_content.engine_classifier.discover_engines() to inventory the real codebase.",
        }
    roles: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$role", "n": {"$sum": 1}}}
    ]):
        roles[r["_id"]] = r["n"]
    states: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$state", "n": {"$sum": 1}}}
    ]):
        states[r["_id"]] = r["n"]
    scopes: dict[str, int] = {}
    async for r in coll.aggregate([
        {"$group": {"_id": "$scope", "n": {"$sum": 1}}}
    ]):
        scopes[r["_id"]] = r["n"]
    return {
        "total_engines":     total,
        "roles":             roles,
        "states":            states,
        "scopes":            scopes,
        "guardrails": {
            "notes":         "Roles are classified from source-code paths and inspection. READY/CONNECTED require dependency resolution + runtime invocation — these transitions are subsequent slices.",
        },
    }


@router.get("/engines/list")
async def engines_list(role: str = None, scope: str = None,
                             limit: int = 200,
                             user=Depends(require_admin)):
    q = {}
    if role:  q["role"]  = role.upper()
    if scope: q["scope"] = scope
    items = []
    async for d in db[ENGINES_COLLECTION].find(
        q, {"_id": 0, "state_history": 0, "provenance": 0}
    ).limit(min(limit, 500)):
        items.append(d)
    return {"count": len(items), "items": items}


# ── P0.2c · Implementation Capability Contracts ─────────────────

@router.get("/contracts/report")
async def contracts_report(user=Depends(require_admin)):
    """
    Authoritative Implementation Capability Contract report.
    Contracts are DECLARED, never auto-promoted; the report is
    the honest state of the ladder at this moment.
    """
    return await contract_report(db)


@router.post("/contracts/declare")
async def contracts_declare(user=Depends(require_admin)):
    """
    (Re-)declare CONTRACT_DECLARED records for every engine in
    `xdr_engines`.  Contracts already at RUNTIME_VERIFIED or
    EXECUTION_VERIFIED are frozen — this pass will not touch them.
    """
    return await declare_all_contracts(db)


@router.get("/contracts")
async def contracts_list(classification: str = None,
                              status: str = None,
                              detection: bool | None = None,
                              limit: int = 200,
                              user=Depends(require_admin)):
    q: dict = {}
    if classification: q["classification"]  = classification.upper()
    if status:         q["contract_status"] = status.upper()
    if detection is not None:
        q["execution.detection"] = bool(detection)
    items = []
    async for d in db[CONTRACTS_COLLECTION].find(
        q, {"_id": 0, "status_history": 0}
    ).limit(min(limit, 500)):
        items.append(d)
    return {"count": len(items), "items": items}


@router.get("/contracts/{engine_id:path}")
async def contract_one(engine_id: str, user=Depends(require_admin)):
    doc = await db[CONTRACTS_COLLECTION].find_one(
        {"engine_id": engine_id}, {"_id": 0})
    if not doc:
        return {"engine_id": engine_id, "found": False,
                    "note": "No contract declared for this engine yet."}
    return {"engine_id": engine_id, "found": True, "contract": doc}
