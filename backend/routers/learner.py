"""Auto-Archetype Learner router — Feb 2026.

Endpoints powering the /learner UI (Inbox · Clusters · Proposals · Approved
· History). All routes require an authenticated user; the `approve` and
`rollback` mutating routes additionally require role == "admin".
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from pymongo import MongoClient

from deps import get_current_user
import learner_engine as eng


router = APIRouter()

_client = MongoClient(os.environ.get("MONGO_URL"))
_db     = _client[os.environ.get("DB_NAME")]

_col_payloads = _db.learner_payloads
_col_versions = _db.learner_versions


# ─── models ─────────────────────────────────────────────────────────────

class SubmitIn(BaseModel):
    raw_payload:     str
    expected_output: Optional[str] = ""
    notes:           Optional[str] = ""
    tags:            List[str]     = Field(default_factory=list)
    dataset_source:  Optional[str] = None


class ApproveIn(BaseModel):
    approval_notes: Optional[str] = ""


class RejectIn(BaseModel):
    reason: Optional[str] = ""


# ─── helpers ────────────────────────────────────────────────────────────

def _email(user: Any) -> Optional[str]:
    return getattr(user, "email", None) or (user.get("email") if isinstance(user, dict) else None)


def _role(user: Any) -> Optional[str]:
    return getattr(user, "role", None) or (user.get("role") if isinstance(user, dict) else None)


def _admin(user: Any):
    if _role(user) != "admin":
        raise HTTPException(status_code=403, detail="admin role required")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc.pop("_id", None)
    return doc


# ─── SUBMIT ─────────────────────────────────────────────────────────────

@router.post("/learner/submit")
async def submit(body: SubmitIn, user=Depends(get_current_user)):
    raw = (body.raw_payload or "").strip()
    if not raw:
        raise HTTPException(status_code=400, detail="raw_payload required")

    # Compute features + proposal upfront so duplicate-detect is meaningful.
    features = eng.extract_features(raw)
    ck = eng.cluster_key(features)

    # Duplicate detection against existing payloads
    dupes = []
    for other in _col_payloads.find(
        {"cluster_key": ck}, {"_id": 0, "id": 1, "cluster_key": 1,
                              "features": 1, "raw_payload": 1, "status": 1}
    ).limit(20):
        score = eng.similarity(features, other.get("features") or {})
        if score >= 60:
            dupes.append({
                "id":         other["id"],
                "similarity": score,
                "status":     other.get("status"),
                "preview":    (other.get("raw_payload") or "")[:60],
            })

    doc = {
        "id":              str(uuid.uuid4()),
        "created_at":      _now(),
        "created_by":      _email(user),
        "raw_payload":     raw,
        "expected_output": body.expected_output or "",
        "notes":           body.notes or "",
        "tags":            body.tags,
        "dataset_source":  body.dataset_source or "manual",
        "features":        features,
        "cluster_key":     ck,
        "status":          "inbox",  # inbox → proposed → approved → merged (or rejected)
        "proposal":        None,
        "regression":      None,
        "approved_by":     None,
        "approved_at":     None,
        "approval_notes":  None,
        "rejected_by":     None,
        "rejected_at":     None,
        "reject_reason":   None,
        "dupes":           dupes,
    }
    _col_payloads.insert_one(doc)
    return {"id": doc["id"], "cluster_key": ck, "dupes": dupes}


# ─── INBOX ──────────────────────────────────────────────────────────────

@router.get("/learner/inbox")
async def inbox(status: str = "inbox", limit: int = 100, user=Depends(get_current_user)):
    """List submissions filtered by status. Default is `inbox`."""
    q = {} if status == "all" else {"status": status}
    cur = _col_payloads.find(q, {
        "_id": 0, "id": 1, "created_at": 1, "created_by": 1,
        "cluster_key": 1, "status": 1, "notes": 1, "tags": 1,
        "features": 1,
        "raw_payload": 1,
        "dataset_source": 1,
        "source_feedback_id": 1,
        "ai_suggested_recipe": 1,
    }).sort("created_at", -1).limit(min(int(limit), 500))
    rows = []
    for d in cur:
        d["preview"] = (d.pop("raw_payload", "") or "")[:120]
        rows.append(d)
    return {"count": len(rows), "rows": rows}


# ─── CLUSTERS ───────────────────────────────────────────────────────────

@router.get("/learner/clusters")
async def clusters(user=Depends(get_current_user)):
    """Group all payloads by cluster_key and return counts + status split."""
    pipeline = [
        {"$group": {
            "_id":     "$cluster_key",
            "count":   {"$sum": 1},
            "statuses": {"$push": "$status"},
            "last":    {"$max": "$created_at"},
        }},
        {"$sort": {"count": -1}},
    ]
    out = []
    for g in _col_payloads.aggregate(pipeline):
        stats: Dict[str, int] = {}
        for s in g.get("statuses") or []:
            stats[s] = stats.get(s, 0) + 1
        out.append({
            "cluster_key": g["_id"],
            "count":       g["count"],
            "stats":       stats,
            "last":        g.get("last"),
        })
    return {"clusters": out}


@router.get("/learner/cluster/{cluster_key}")
async def cluster_detail(cluster_key: str, user=Depends(get_current_user)):
    cur = _col_payloads.find(
        {"cluster_key": cluster_key},
        {"_id": 0, "id": 1, "created_at": 1, "status": 1, "notes": 1,
         "features": 1, "raw_payload": 1}
    ).sort("created_at", -1)
    rows = []
    for d in cur:
        d["preview"] = (d.pop("raw_payload", "") or "")[:200]
        rows.append(d)
    return {"cluster_key": cluster_key, "count": len(rows), "rows": rows}


# ─── ANALYZE (generate proposal) ────────────────────────────────────────

@router.post("/learner/analyze/{payload_id}")
async def analyze(payload_id: str, user=Depends(get_current_user)):
    doc = _col_payloads.find_one({"id": payload_id})
    if not doc:
        raise HTTPException(status_code=404, detail="payload not found")
    proposal = eng.propose_archetype(doc["raw_payload"], doc.get("expected_output") or "")
    _col_payloads.update_one(
        {"id": payload_id},
        {"$set": {"proposal": proposal, "status": "proposed",
                  "analyzed_at": _now(), "analyzed_by": _email(user)}}
    )
    return {"id": payload_id, "proposal": proposal}


# ─── DETAIL ─────────────────────────────────────────────────────────────

@router.get("/learner/payload/{payload_id}")
async def payload_detail(payload_id: str, user=Depends(get_current_user)):
    doc = _col_payloads.find_one({"id": payload_id})
    if not doc:
        raise HTTPException(status_code=404, detail="payload not found")
    return _redact(doc)


# ─── PROPOSALS ──────────────────────────────────────────────────────────

@router.get("/learner/proposals")
async def list_proposals(limit: int = 100, user=Depends(get_current_user)):
    cur = _col_payloads.find(
        {"status": "proposed"},
        {"_id": 0, "id": 1, "created_at": 1, "cluster_key": 1,
         "proposal.archetype_id": 1, "proposal.confidence": 1,
         "proposal.decode_chain": 1, "notes": 1}
    ).sort("created_at", -1).limit(min(int(limit), 200))
    return {"rows": list(cur)}


# ─── APPROVE (regression gate + staging write) ──────────────────────────

@router.post("/learner/approve/{payload_id}")
async def approve(payload_id: str, body: ApproveIn, user=Depends(get_current_user)):
    _admin(user)
    doc = _col_payloads.find_one({"id": payload_id})
    if not doc:
        raise HTTPException(status_code=404, detail="payload not found")
    proposal = doc.get("proposal")
    if not proposal:
        raise HTTPException(status_code=400, detail="run /analyze first")

    baseline = _last_regression()
    reg = eng.run_regression()

    if not reg.get("ok"):
        _col_payloads.update_one(
            {"id": payload_id},
            {"$set": {"regression": reg, "status": "proposed",
                      "last_gate_at": _now()}}
        )
        return {
            "ok":         False,
            "reason":     "regression FAILED — merge blocked",
            "regression": reg,
        }

    # Compute impact vs previous baseline
    impact = _impact(baseline, reg)

    # Write to staging file
    write = eng.append_to_staging(proposal.get("code") or "")
    if not write.get("ok"):
        raise HTTPException(status_code=500, detail=f"staging write failed: {write}")

    # Version stamp
    version = {
        "id":            str(uuid.uuid4()),
        "created_at":    _now(),
        "archetype_id":  proposal["archetype_id"],
        "payload_id":    payload_id,
        "approved_by":   _email(user),
        "approval_notes": body.approval_notes or "",
        "code":          proposal.get("code"),
        "regression":    reg,
        "impact":        impact,
        "rolled_back":   False,
    }
    _col_versions.insert_one(dict(version))

    _col_payloads.update_one(
        {"id": payload_id},
        {"$set": {
            "status":         "merged",
            "regression":     reg,
            "impact":         impact,
            "approved_by":    _email(user),
            "approved_at":    _now(),
            "approval_notes": body.approval_notes or "",
            "version_id":     version["id"],
        }}
    )
    return {"ok": True, "regression": reg, "impact": impact,
            "version_id": version["id"], "staging": write}


def _last_regression() -> Optional[Dict[str, Any]]:
    doc = _col_versions.find_one(
        {"rolled_back": False},
        sort=[("created_at", -1)],
        projection={"_id": 0, "regression": 1}
    )
    return (doc or {}).get("regression")


def _impact(prev: Optional[Dict[str, Any]], now: Dict[str, Any]) -> Dict[str, Any]:
    prev_p = (prev or {}).get("passed") or 0
    prev_f = (prev or {}).get("failed") or 0
    now_p  = now.get("passed") or 0
    now_f  = now.get("failed") or 0
    return {
        "passed":         now_p,
        "failed":         now_f,
        "passed_delta":   now_p - prev_p,
        "failed_delta":   now_f - prev_f,
        "coverage_delta": (now_p + now_f) - (prev_p + prev_f),
    }


# ─── REJECT ─────────────────────────────────────────────────────────────

@router.post("/learner/reject/{payload_id}")
async def reject(payload_id: str, body: RejectIn, user=Depends(get_current_user)):
    _admin(user)
    r = _col_payloads.update_one(
        {"id": payload_id},
        {"$set": {"status":        "rejected",
                  "rejected_by":   _email(user),
                  "rejected_at":   _now(),
                  "reject_reason": body.reason or ""}}
    )
    if not r.matched_count:
        raise HTTPException(status_code=404, detail="payload not found")
    return {"ok": True}


# ─── APPROVED / HISTORY / ROLLBACK ──────────────────────────────────────

@router.get("/learner/approved")
async def approved(limit: int = 100, user=Depends(get_current_user)):
    cur = _col_payloads.find(
        {"status": "merged"},
        {"_id": 0, "id": 1, "created_at": 1, "approved_at": 1,
         "approved_by": 1, "cluster_key": 1, "version_id": 1,
         "proposal.archetype_id": 1, "impact": 1}
    ).sort("approved_at", -1).limit(min(int(limit), 200))
    return {"rows": list(cur)}


@router.get("/learner/history")
async def history(limit: int = 200, user=Depends(get_current_user)):
    cur = _col_versions.find(
        {}, {"_id": 0, "id": 1, "created_at": 1, "archetype_id": 1,
             "approved_by": 1, "approval_notes": 1, "regression.passed": 1,
             "regression.failed": 1, "impact": 1, "rolled_back": 1,
             "rolled_back_at": 1, "rolled_back_by": 1}
    ).sort("created_at", -1).limit(min(int(limit), 500))
    return {"rows": list(cur)}


@router.post("/learner/rollback/{version_id}")
async def rollback(version_id: str, user=Depends(get_current_user)):
    _admin(user)
    v = _col_versions.find_one({"id": version_id})
    if not v:
        raise HTTPException(status_code=404, detail="version not found")
    if v.get("rolled_back"):
        return {"ok": True, "already": True}
    res = eng.remove_from_staging(v["archetype_id"])
    if not res.get("ok"):
        raise HTTPException(status_code=500, detail=f"remove failed: {res}")
    _col_versions.update_one(
        {"id": version_id},
        {"$set": {"rolled_back":    True,
                  "rolled_back_at": _now(),
                  "rolled_back_by": _email(user)}}
    )
    _col_payloads.update_one(
        {"version_id": version_id},
        {"$set": {"status": "rolled_back"}}
    )
    return {"ok": True}


# ─── DUPLICATE-CHECK (pre-submit) ───────────────────────────────────────

class DupCheckIn(BaseModel):
    raw_payload: str


@router.post("/learner/duplicate-check")
async def duplicate_check(body: DupCheckIn, user=Depends(get_current_user)):
    raw = (body.raw_payload or "").strip()
    if not raw:
        return {"dupes": []}
    features = eng.extract_features(raw)
    ck = eng.cluster_key(features)
    dupes = []
    for other in _col_payloads.find(
        {"cluster_key": ck}, {"_id": 0, "id": 1, "features": 1,
                              "raw_payload": 1, "status": 1,
                              "proposal.archetype_id": 1}
    ).limit(20):
        score = eng.similarity(features, other.get("features") or {})
        if score >= 60:
            dupes.append({
                "id":           other["id"],
                "similarity":   score,
                "status":       other.get("status"),
                "archetype_id": (other.get("proposal") or {}).get("archetype_id"),
                "preview":      (other.get("raw_payload") or "")[:100],
            })
    dupes.sort(key=lambda x: -x["similarity"])
    return {"cluster_key": ck, "dupes": dupes}



# ─── FEEDBACK INGESTION (v1.4.3) ────────────────────────────────────────
# Pull user-reported "bad decode / undecoded" records from the
# `decode_feedback` collection into the learner inbox. Deduped by SHA1 of
# raw_input so re-runs are safe. Auto-tags with the AI-suggested recipe
# ops from the Claude diagnosis so cluster grouping is more meaningful.
_col_feedback = _db.decode_feedback


@router.post("/learner/ingest-feedback")
async def ingest_feedback(user=Depends(get_current_user)):
    """Admin-only: ingest all decode_feedback records into the learner inbox."""
    _admin(user)
    import hashlib

    cursor = _col_feedback.find({"ingested_to_learner": {"$ne": True}})
    ingested = 0
    skipped_dupes = 0
    created_ids: List[str] = []

    for fb in cursor:
        raw = (fb.get("raw_input") or "").strip()
        if not raw:
            continue
        # SHA1 dedupe against already-ingested payloads
        sha1 = hashlib.sha1(raw.encode("utf-8")).hexdigest()
        if _col_payloads.find_one({"source_sha1": sha1}, {"id": 1}):
            _col_feedback.update_one({"id": fb["id"]}, {"$set": {"ingested_to_learner": True, "ingest_dup": True}})
            skipped_dupes += 1
            continue

        features = eng.extract_features(raw)
        ck = eng.cluster_key(features)

        diagnosis = fb.get("diagnosis") or {}
        suggested_recipe = diagnosis.get("suggested_recipe") or []
        missing_heuristic = diagnosis.get("missing_heuristic") or ""
        root_cause = diagnosis.get("root_cause") or ""
        why = diagnosis.get("ai_explanation") or ""

        notes_parts = []
        if fb.get("reason"):
            notes_parts.append(f"Analyst reason: {fb['reason']}")
        if root_cause:
            notes_parts.append(f"Root cause (AI): {root_cause}")
        if why:
            notes_parts.append(f"Why failed: {why[:400]}")
        if missing_heuristic:
            notes_parts.append(f"Missing heuristic: {missing_heuristic}")

        tags = list({t for t in [fb.get("kind") or "wrong_output", "decode_feedback"] + list(suggested_recipe) if t})

        doc = {
            "id":              str(uuid.uuid4()),
            "created_at":      _now(),
            "created_by":      fb.get("user") or _email(user),
            "raw_payload":     raw,
            "expected_output": fb.get("expected_output") or "",
            "notes":           "\n\n".join(notes_parts),
            "tags":            tags,
            "dataset_source":  "decode_feedback",
            "source_feedback_id": fb.get("id"),
            "source_sha1":     sha1,
            "features":        features,
            "cluster_key":     ck,
            "status":          "inbox",
            "proposal":        None,
            "regression":      None,
            "approved_by":     None,
            "approved_at":     None,
            "approval_notes":  None,
            "rejected_by":     None,
            "rejected_at":     None,
            "reject_reason":   None,
            "dupes":           [],
            # Carry the AI-suggested recipe forward — Learner UI can render it
            # as a starter template so the admin can approve without re-analysis.
            "ai_suggested_recipe": suggested_recipe,
        }
        # ── v1.5.0 · Auto-analyze the moment we ingest ─────────────────
        # Closes the novel-payload loop: analyst reports bad decode →
        # feedback ingested → proposal auto-generated → admin just reviews.
        # We only auto-analyze if there's SOMETHING to work with
        # (expected output OR AI suggested recipe) — otherwise skip and
        # let the admin click ANALYZE manually.
        if fb.get("expected_output") or suggested_recipe:
            try:
                doc["proposal"] = eng.propose_archetype(raw, fb.get("expected_output") or "")
                doc["status"] = "proposed"
                doc["analyzed_at"] = _now()
                doc["analyzed_by"] = "auto:ingest-feedback"
            except Exception as _e:
                doc["notes"] = (doc["notes"] or "") + f"\n\n[auto-analyze failed: {_e}]"
        _col_payloads.insert_one(doc)
        _col_feedback.update_one(
            {"id": fb["id"]},
            {"$set": {"ingested_to_learner": True, "learner_payload_id": doc["id"]}},
        )
        ingested += 1
        created_ids.append(doc["id"])

    return {
        "ok":             True,
        "ingested":       ingested,
        "skipped_dupes":  skipped_dupes,
        "created_ids":    created_ids,
    }


@router.get("/learner/feedback-source")
async def list_feedback_sourced(limit: int = 100, user=Depends(get_current_user)):
    """List learner_payloads that originated from decode_feedback."""
    cur = _col_payloads.find(
        {"dataset_source": "decode_feedback"},
        {"_id": 0}
    ).sort("created_at", -1).limit(min(int(limit), 500))
    return {"items": list(cur)}




# ─── BULK AUTO-ANALYZE (v1.5.0 · novel-payload loop closure) ─────────────
@router.post("/learner/auto-analyze-inbox")
async def auto_analyze_inbox(user=Depends(get_current_user)):
    """Admin: analyze every inbox row that hasn't been analyzed yet.

    Iterates every `status=inbox` payload, runs `propose_archetype`,
    and flips status to `proposed`. Skips rows with no `expected_output`
    AND no `ai_suggested_recipe` (nothing to work from).
    """
    _admin(user)
    cursor = _col_payloads.find({"status": "inbox"})
    analyzed = 0
    skipped = 0
    failed = 0
    for doc in cursor:
        has_signal = bool(doc.get("expected_output")) or bool(doc.get("ai_suggested_recipe"))
        if not has_signal:
            skipped += 1
            continue
        try:
            prop = eng.propose_archetype(doc["raw_payload"], doc.get("expected_output") or "")
            _col_payloads.update_one(
                {"id": doc["id"]},
                {"$set": {
                    "proposal":    prop,
                    "status":      "proposed",
                    "analyzed_at": _now(),
                    "analyzed_by": "auto:bulk-analyze",
                }},
            )
            analyzed += 1
        except Exception:
            failed += 1
    return {
        "ok":       True,
        "analyzed": analyzed,
        "skipped":  skipped,
        "failed":   failed,
    }
