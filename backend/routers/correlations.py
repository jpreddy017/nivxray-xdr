"""Correlations router — /api/correlations/*.

Phase 4 · P1 · Cross-Artifact Correlation. Owner directive (2026-02-15):
    "An Investigation is a first-class entity, not a collection of linked
    cases. Cases remain atomic records; the Investigation becomes the
    analyst's primary working object."

Backend surface (analyst-facing UI label is "Investigations"):

    POST   /api/correlations                     create — from a seed case
    GET    /api/correlations                     list — user-scoped
    GET    /api/correlations/{cid}               full detail (nodes, edges, cases)
    PATCH  /api/correlations/{cid}               rename / describe / tag
    DELETE /api/correlations/{cid}               delete (cases detached, not deleted)
    POST   /api/correlations/{cid}/link          manual link a case
    POST   /api/correlations/{cid}/unlink        detach a case
    GET    /api/correlations/{cid}/chain         linear attack chain
    GET    /api/correlations/{cid}/graph         evidence graph (nodes + edges)
    GET    /api/correlations/{cid}/timeline      unified timeline
    GET    /api/correlations/{cid}/summary       consolidated threat summary
    GET    /api/correlations/{cid}/suggestions   pending cross-case suggestions
    POST   /api/correlations/{cid}/suggestions/{case_id}/confirm
    POST   /api/correlations/{cid}/suggestions/{case_id}/dismiss

    POST   /api/correlations/scan                one-off scan for a case
                                                 → suggestions across all
                                                 existing correlations + None
                                                 (candidate for new one)

Deterministic — no LLM. All correlations are backed by concrete shared
evidence.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field

from deps import db, get_current_user
from services.correlation_engine import (
    new_correlation_doc,
    merge_case_into_correlation,
    attach_inline_children,
    build_attack_chain,
    build_evidence_graph,
    build_unified_timeline,
    build_investigation_threat_summary,
    scan_correlations,
    build_evidence_signature,
    compute_correlation,
    score_to_confidence,
    SUGGESTION_MIN_SCORE,
    declare_inline_children_from_routed_analysis,
)

logger = logging.getLogger("nivxray.correlations")
router = APIRouter()

_INDEX_READY = False


async def _ensure_indexes():
    global _INDEX_READY
    if _INDEX_READY:
        return
    try:
        coll = db.correlations
        await coll.create_index([("user_email", 1), ("updated_at", -1)],
                                name="user_updated")
        await coll.create_index("case_ids", name="case_ids_lookup")
        await coll.create_index("root_case_id", name="root_case_lookup")
        _INDEX_READY = True
    except Exception as e:
        logger.warning("correlation index setup: %s", e)
        _INDEX_READY = True


def _oid(v) -> Optional[ObjectId]:
    try:
        return ObjectId(str(v))
    except Exception:
        return None


def _serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    out = dict(doc)
    if "_id" in out:
        out["id"] = str(out.pop("_id"))
    for k in ("created_at", "updated_at", "ts"):
        v = out.get(k)
        if isinstance(v, datetime):
            out[k] = v.isoformat()
    return out


async def _load_case(user_email: str, case_id: str) -> Optional[Dict[str, Any]]:
    oid = _oid(case_id)
    if not oid:
        return None
    doc = await db.investigations.find_one({"_id": oid, "user_email": user_email})
    if not doc:
        return None
    doc["id"] = str(doc.pop("_id"))
    return doc


async def _load_correlation(user_email: str, cid: str) -> Optional[Dict[str, Any]]:
    """Internal loader — returns raw Mongo doc for further mutation.
    Callers MUST pass through `_serialize()` before returning to clients.
    Never returned directly from any endpoint."""
    oid = _oid(cid)
    if not oid:
        return None
    doc = await db.correlations.find_one({"_id": oid, "user_email": user_email})
    if doc is None:
        return None
    # This helper intentionally keeps `_id` as an ObjectId for downstream
    # mutations and $set updates. It is NEVER returned to a client directly.
    return dict(doc)


async def _persist_correlation(corr: Dict[str, Any]) -> Dict[str, Any]:
    """Insert or replace. Returns serialized doc with id."""
    if "_id" in corr:
        oid = corr["_id"]
        await db.correlations.replace_one({"_id": oid}, corr)
    else:
        r = await db.correlations.insert_one(corr)
        corr["_id"] = r.inserted_id
    return _serialize(corr)


async def _write_back_correlation_id(user_email: str, case_ids: List[str], cid: str):
    """Set correlation_id on each member case (atomic per case)."""
    if not case_ids:
        return
    oids = [_oid(c) for c in case_ids if _oid(c)]
    if not oids:
        return
    await db.investigations.update_many(
        {"_id": {"$in": oids}, "user_email": user_email},
        {"$set": {"correlation_id": str(cid)}},
    )


# ============================================================================
# Schemas
# ============================================================================
class CreateIn(BaseModel):
    root_case_id: str
    name: Optional[str] = None
    description: Optional[str] = ""
    tags: List[str] = Field(default_factory=list)


class PatchIn(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class LinkIn(BaseModel):
    case_id: str
    parent_node_id: Optional[str] = None
    shared_evidence: Optional[Dict[str, Any]] = None
    source: str = "manual"        # manual | auto_correlated | inline_recursive


class ScanIn(BaseModel):
    case_id: str
    limit: int = 50


# ============================================================================
# Endpoints — CRUD
# ============================================================================
@router.post("/correlations", tags=["correlations"])
async def create_correlation(body: CreateIn, user=Depends(get_current_user)):
    await _ensure_indexes()
    seed = await _load_case(user["email"], body.root_case_id)
    if not seed:
        raise HTTPException(status_code=404, detail="root_case_not_found")

    # If this case is already part of a correlation, return it (idempotent)
    if seed.get("correlation_id"):
        existing = await _load_correlation(user["email"], seed["correlation_id"])
        if existing:
            return {"correlation": _serialize(existing), "created": False}

    corr = new_correlation_doc(user["email"], seed, name=body.name)
    if body.description:
        corr["description"] = body.description[:1000]
    if body.tags:
        corr["tags"] = [t.strip() for t in body.tags if t.strip()][:16]

    # Recursive inline chaining — surface child artifacts declared by the
    # analyzer for the seed case.
    routed = ((seed.get("iedde") or {}).get("binary_artifact") or {}).get("routed_analysis")
    children = declare_inline_children_from_routed_analysis(routed or {})
    if children:
        attach_inline_children(corr, seed["id"], children)

    saved = await _persist_correlation(corr)
    await _write_back_correlation_id(user["email"], [seed["id"]], saved["id"])
    return {"correlation": saved, "created": True}


@router.get("/correlations", tags=["correlations"])
async def list_correlations(limit: int = 100, user=Depends(get_current_user)):
    await _ensure_indexes()
    cursor = db.correlations.find({"user_email": user["email"]}) \
        .sort("updated_at", -1).limit(limit)
    items: List[Dict[str, Any]] = []
    async for doc in cursor:
        # Summary shape for the list — no giant edge/node arrays
        d = _serialize(doc)
        d["case_count"] = len(d.get("case_ids") or [])
        d["node_count"] = len(d.get("artifact_nodes") or [])
        d["edge_count"] = len(d.get("edges") or [])
        # Trim heavy arrays out of the list view
        d.pop("artifact_nodes", None)
        d.pop("edges", None)
        items.append(d)
    return {"correlations": items, "count": len(items)}


@router.get("/correlations/{cid}", tags=["correlations"])
async def get_correlation(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    return {"correlation": _serialize(corr)}


@router.patch("/correlations/{cid}", tags=["correlations"])
async def patch_correlation(cid: str, body: PatchIn, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    updates: Dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if body.name is not None:
        updates["name"] = body.name[:200]
    if body.description is not None:
        updates["description"] = body.description[:1000]
    if body.tags is not None:
        updates["tags"] = [t.strip() for t in body.tags if t.strip()][:16]
    await db.correlations.update_one({"_id": corr["_id"]}, {"$set": updates})
    fresh = await db.correlations.find_one({"_id": corr["_id"]})
    return {"correlation": _serialize(fresh)}


@router.delete("/correlations/{cid}", tags=["correlations"])
async def delete_correlation(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    await db.correlations.delete_one({"_id": corr["_id"]})
    # Detach member cases — never delete underlying History rows.
    await db.investigations.update_many(
        {"user_email": user["email"], "correlation_id": str(corr["_id"])},
        {"$unset": {"correlation_id": ""}},
    )
    return {"ok": True, "detached_cases": len(corr.get("case_ids") or [])}


# ============================================================================
# Linking
# ============================================================================
@router.post("/correlations/{cid}/link", tags=["correlations"])
async def link_case(cid: str, body: LinkIn, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    case = await _load_case(user["email"], body.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    if body.case_id in corr.get("case_ids", []):
        return {"correlation": _serialize(corr), "already_linked": True}

    # Compute shared evidence if not supplied
    shared = body.shared_evidence
    if shared is None:
        root_case = await _load_case(user["email"], corr["root_case_id"])
        if root_case:
            _, shared = compute_correlation(
                build_evidence_signature(root_case),
                build_evidence_signature(case),
            )

    merge_case_into_correlation(corr, case,
                                source=body.source,
                                parent_node_id=body.parent_node_id,
                                shared_evidence=shared or {})

    # Also attach inline children of this case's routed_analysis
    routed = ((case.get("iedde") or {}).get("binary_artifact") or {}).get("routed_analysis")
    children = declare_inline_children_from_routed_analysis(routed or {})
    if children:
        attach_inline_children(corr, case["id"], children)

    saved = await _persist_correlation(corr)
    await _write_back_correlation_id(user["email"], [case["id"]], saved["id"])

    # Clear any lingering "dismissed" state for this case in this correlation
    if body.case_id in corr.get("dismissed_case_ids", []):
        await db.correlations.update_one(
            {"_id": corr["_id"]},
            {"$pull": {"dismissed_case_ids": body.case_id}},
        )
    return {"correlation": saved, "linked": True}


@router.post("/correlations/{cid}/unlink", tags=["correlations"])
async def unlink_case(cid: str, body: LinkIn, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    if body.case_id == corr.get("root_case_id"):
        raise HTTPException(status_code=400, detail="cannot_unlink_root")
    case_ids = [c for c in corr.get("case_ids", []) if c != body.case_id]
    node_id = f"case:{body.case_id}"
    nodes = [n for n in corr.get("artifact_nodes", []) if n.get("node_id") != node_id]
    edges = [e for e in corr.get("edges", [])
             if e.get("to") != node_id and e.get("from") != node_id]
    now = datetime.now(timezone.utc)
    await db.correlations.update_one(
        {"_id": corr["_id"]},
        {"$set": {"case_ids": case_ids, "artifact_nodes": nodes,
                  "edges": edges, "updated_at": now}},
    )
    await db.investigations.update_one(
        {"_id": _oid(body.case_id), "user_email": user["email"]},
        {"$unset": {"correlation_id": ""}},
    )
    fresh = await db.correlations.find_one({"_id": corr["_id"]})
    return {"correlation": _serialize(fresh), "unlinked": True}


# ============================================================================
# Views
# ============================================================================
@router.get("/correlations/{cid}/chain", tags=["correlations"])
async def get_chain(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    return build_attack_chain(corr)


@router.get("/correlations/{cid}/graph", tags=["correlations"])
async def get_graph(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    return build_evidence_graph(corr)


@router.get("/correlations/{cid}/timeline", tags=["correlations"])
async def get_timeline(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    cases = await _load_member_cases(user["email"], corr)
    return build_unified_timeline(corr, cases)


@router.get("/correlations/{cid}/summary", tags=["correlations"])
async def get_summary(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    cases = await _load_member_cases(user["email"], corr)
    return {
        "correlation_id": str(corr["_id"]),
        "name": corr.get("name"),
        "summary": build_investigation_threat_summary(corr, cases),
    }


async def _load_member_cases(user_email: str, corr: Dict[str, Any]) -> List[Dict[str, Any]]:
    ids = corr.get("case_ids") or []
    oids = [_oid(x) for x in ids if _oid(x)]
    if not oids:
        return []
    cursor = db.investigations.find(
        {"_id": {"$in": oids}, "user_email": user_email},
    )
    cases = []
    async for c in cursor:
        c["id"] = str(c.pop("_id"))
        cases.append(c)
    return cases


# ============================================================================
# Suggestions (auto-correlation)
# ============================================================================
@router.get("/correlations/{cid}/suggestions", tags=["correlations"])
async def list_suggestions(cid: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    # Aggregate suggestions from EVERY member case, dedupe by candidate id
    seen: Dict[str, Dict[str, Any]] = {}
    dismissed = set(corr.get("dismissed_case_ids") or [])
    member_ids = set(corr.get("case_ids") or [])
    member_cases = await _load_member_cases(user["email"], corr)
    for seed in member_cases:
        candidates = await scan_correlations(db, user["email"], seed, limit_candidates=200)
        for s in candidates:
            cid_candidate = s["case_id"]
            if cid_candidate in member_ids or cid_candidate in dismissed:
                continue
            # Keep the strongest suggestion per candidate
            prev = seen.get(cid_candidate)
            if not prev or s["score"] > prev["score"]:
                s["seed_case_id"] = str(seed.get("id") or seed.get("_id"))
                seen[cid_candidate] = s
    ranked = sorted(seen.values(), key=lambda x: x["score"], reverse=True)
    return {"suggestions": ranked, "count": len(ranked)}


@router.post("/correlations/{cid}/suggestions/{case_id}/confirm", tags=["correlations"])
async def confirm_suggestion(cid: str, case_id: str, user=Depends(get_current_user)):
    """Analyst approves an auto-correlation suggestion → link the case."""
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    case = await _load_case(user["email"], case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    root_case = await _load_case(user["email"], corr["root_case_id"])
    _, shared = compute_correlation(
        build_evidence_signature(root_case) if root_case else {},
        build_evidence_signature(case),
    ) if root_case else (0, {})
    merge_case_into_correlation(corr, case,
                                source="auto_correlated",
                                shared_evidence=shared or {})
    routed = ((case.get("iedde") or {}).get("binary_artifact") or {}).get("routed_analysis")
    children = declare_inline_children_from_routed_analysis(routed or {})
    if children:
        attach_inline_children(corr, case["id"], children)
    saved = await _persist_correlation(corr)
    await _write_back_correlation_id(user["email"], [case["id"]], saved["id"])
    return {"correlation": saved, "confirmed": True}


@router.post("/correlations/{cid}/suggestions/{case_id}/dismiss", tags=["correlations"])
async def dismiss_suggestion(cid: str, case_id: str, user=Depends(get_current_user)):
    corr = await _load_correlation(user["email"], cid)
    if not corr:
        raise HTTPException(status_code=404, detail="correlation_not_found")
    await db.correlations.update_one(
        {"_id": corr["_id"]},
        {"$addToSet": {"dismissed_case_ids": case_id},
         "$set": {"updated_at": datetime.now(timezone.utc)}},
    )
    return {"ok": True, "dismissed": case_id}


# ============================================================================
# One-off scan (used by "Find related cases" button on a lone case)
# ============================================================================
@router.post("/correlations/scan", tags=["correlations"])
async def scan(body: ScanIn, user=Depends(get_current_user)):
    case = await _load_case(user["email"], body.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    suggestions = await scan_correlations(db, user["email"], case,
                                          limit_candidates=max(50, body.limit))
    return {
        "case_id":    body.case_id,
        "suggestions": suggestions[:body.limit],
        "count":      len(suggestions[:body.limit]),
        "min_score":  SUGGESTION_MIN_SCORE,
    }


# ============================================================================
# Find Related — one-stop endpoint for the Workspace + History "Find Related
# Cases" action. Returns: (a) the case's existing investigation if any,
# (b) any cached auto-scan suggestions, (c) a fresh live scan.
# ============================================================================
class FindRelatedIn(BaseModel):
    case_id: str
    limit: int = 25
    refresh: bool = False   # skip cache and re-scan


@router.post("/correlations/find-related", tags=["correlations"])
async def find_related(body: FindRelatedIn, user=Depends(get_current_user)):
    case = await _load_case(user["email"], body.case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")

    existing_investigation = None
    if case.get("correlation_id"):
        corr = await _load_correlation(user["email"], case["correlation_id"])
        if corr:
            existing_investigation = {
                "id":         str(corr["_id"]),
                "name":       corr.get("name"),
                "case_count": len(corr.get("case_ids") or []),
                "updated_at": _serialize(corr).get("updated_at"),
            }

    cached = case.get("pending_correlations") if not body.refresh else None
    if cached:
        suggestions = list(cached)
        source = "cache"
    else:
        suggestions = await scan_correlations(db, user["email"], case,
                                              limit_candidates=max(50, body.limit))
        source = "live"

    return {
        "case_id":                body.case_id,
        "existing_investigation": existing_investigation,
        "suggestions":            suggestions[:body.limit],
        "count":                  len(suggestions[:body.limit]),
        "source":                 source,
        "min_score":              SUGGESTION_MIN_SCORE,
    }


# ============================================================================
# CEM — Canonical Event Model view for a single case (master architecture §5)
# ============================================================================
@router.get("/correlations/cem/{case_id}", tags=["correlations"])
async def get_cem(case_id: str, user=Depends(get_current_user)):
    """Return the Canonical Event Model view of a recorded case.

    Prefers the cached `case.cem` field emitted by the post-record hook;
    falls back to a fresh emission if the case predates the CEM layer.
    """
    case = await _load_case(user["email"], case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    if case.get("cem"):
        return {"case_id": case_id, "cem": case["cem"], "source": "cached"}
    from services.cem import emit_cem
    return {"case_id": case_id, "cem": emit_cem(case), "source": "computed"}


# ============================================================================
# Attack Fingerprint (Attack DNA) — Phase A · first Analytical Consumer
# ============================================================================
@router.get("/correlations/fingerprint/{case_id}", tags=["correlations"])
async def get_fingerprint(case_id: str, user=Depends(get_current_user)):
    """Return the deterministic Attack Fingerprint for a recorded case.

    Read-only analytical consumer of the Investigation SSOT (§7).
    Never mutates the case, CEM, verdict, or evidence. Pre-convergence
    cases return a stub with `hash=None` and a `reason` field.
    """
    case = await _load_case(user["email"], case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case_not_found")
    from services.attack_fingerprint import emit_fingerprint
    fp = emit_fingerprint(case)
    return {"case_id": case_id, "fingerprint": fp}


# ============================================================================
# Compare Cases — Phase A · item 2 · fingerprint-powered side-by-side diff
# ============================================================================
class CompareBody(BaseModel):
    case_a_id: str
    case_b_id: str


@router.post("/correlations/compare", tags=["correlations"])
async def compare_two_cases(body: CompareBody, user=Depends(get_current_user)):
    """Return a deterministic diff of two cases.

    Read-only consumer of the Investigation SSOT + Attack Fingerprint
    (§7). Never mutates either case. Symmetrical up to provenance
    labels: `compare(a, b)` and `compare(b, a)` produce mirrored diffs.
    """
    a = await _load_case(user["email"], body.case_a_id)
    if not a:
        raise HTTPException(status_code=404, detail="case_a_not_found")
    b = await _load_case(user["email"], body.case_b_id)
    if not b:
        raise HTTPException(status_code=404, detail="case_b_not_found")
    from services.case_compare import compare_cases
    return compare_cases(a, b)
