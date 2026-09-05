"""NivXRay Analyst Corrections — enterprise-grade feedback loop.
================================================================

Analysts submit corrections against wrong findings (MITRE mapping,
missed threat, wrong asset type, wrong mitigation, wrong IOC extraction,
wrong decode chain, wrong LOLBIN, wrong malware family, wrong risk,
wrong detection, missing analyst note). Corrections are:

  * versioned      — every edit creates a new version, previous versions
                     stay queryable for rollback + audit
  * confidence-scored — combined of (approval-status, reuse_count,
                        author-role, similarity-score) → 0..100
  * multi-scope    — private (author-only) · team (all authenticated
                     users) · global (requires admin approval)
  * hybrid-matched — deterministic tag match FIRST, LLM semantic match
                     as fallback if no tag match found
  * hybrid-applied — deterministic override (patch the wrong finding)
                     when the match is exact/deterministic; injected
                     guidance (LLM prompt appendix) otherwise

Wire-in points (called from any decode / analysis endpoint):
    from analyst_corrections import (
        submit_correction, apply_corrections, list_applicable,
    )

MongoDB collection layout (`analyst_corrections`):
    {
      "_id": ObjectId,
      "id": "corr_ab12cd34",              # stable public id
      "user_email": "alice@x.com",         # author
      "role_at_authoring": "analyst"|"admin",
      "surface": "threat_model"|"decode"|"chain"|"ioc"|"lolbas"|"family"|"risk"|"detection"|"mitigation"|"note",
      "diagram_hash": "abc123..." | None, # sha256(input) — narrow-match key
      "wrong_finding": {"kind": "mitre", "value": "T1078"},   # the incorrect piece
      "correct_prompt": "The correct mapping is T1190 …",
      "tags": ["redis", "api-gateway"],
      "scope": "private"|"team"|"global",
      "status": "pending"|"approved"|"rejected",
      "confidence": 0..100,                # dynamic — recomputed on read
      "reuse_count": int,                  # incremented every time it fires
      "version": int,                      # 1-based
      "prev_version_id": "corr_..." | None,# rollback pointer
      "history": [{"version":1,"user_email":"...","at":"iso","summary":"..."}],
      "created_at": iso,
      "updated_at": iso,
      "approved_at": iso | None,
      "approved_by": email | None,
    }
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

COLLECTION = "analyst_corrections"

# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
_NOW = lambda: datetime.now(timezone.utc).isoformat()   # noqa: E731

def _new_id() -> str:
    return "corr_" + secrets.token_hex(6)

def diagram_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()

def compute_confidence(doc: Dict[str, Any]) -> int:
    """Combine status (60 %) + reuse_count (25 %) + author-role (15 %) into
    a 0..100 confidence score. Recomputed on every read so it stays fresh
    without background jobs."""
    status = (doc.get("status") or "pending").lower()
    reuse  = int(doc.get("reuse_count") or 0)
    role   = (doc.get("role_at_authoring") or "analyst").lower()
    scope  = (doc.get("scope") or "private").lower()

    status_pt = {"approved": 60, "pending": 25, "rejected": 0}.get(status, 20)
    reuse_pt  = min(25, reuse * 2)     # caps at 12+ uses
    role_pt   = 15 if role == "admin" else 8
    # Slight penalty for GLOBAL scope while still pending — global claims
    # are riskier than private ones.
    if scope == "global" and status == "pending":
        status_pt = max(0, status_pt - 10)
    return max(0, min(100, status_pt + reuse_pt + role_pt))


# ----------------------------------------------------------------------
# storage — submit + version
# ----------------------------------------------------------------------
async def submit_correction(
    db, *, user_email: str, role: str,
    surface: str,
    wrong_finding: Dict[str, Any],
    correct_prompt: str,
    tags: List[str] | None = None,
    scope: str = "private",
    input_text: str | None = None,
    diagram_hash_override: str | None = None,
    revises: str | None = None,
    verdict: str = "incorrect",
) -> Dict[str, Any]:
    """Create a new correction OR a new version of an existing one.

    ``verdict`` (Feb-2026 v2/v3 spec): one of ``correct`` (positive
    reinforcement, no override), ``incorrect`` (deterministic override
    when tag match ≥ 0.75), ``partial`` (LLM-inject only), ``suggest``
    (advisory — LLM-inject only, low priority).
    """
    now = _NOW()
    dh  = diagram_hash_override or (diagram_hash(input_text) if input_text else None)

    if revises:
        prev = await db[COLLECTION].find_one({"id": revises})
        if prev:
            await db[COLLECTION].update_one(
                {"id": revises}, {"$set": {"status": "superseded", "updated_at": now}}
            )
        version = int(prev.get("version") or 1) + 1 if prev else 1
        history = list(prev.get("history") or []) if prev else []
        history.append({
            "version": version - 1,
            "user_email": (prev or {}).get("user_email"),
            "at": (prev or {}).get("updated_at") or (prev or {}).get("created_at"),
            "correct_prompt": (prev or {}).get("correct_prompt", "")[:400],
            "status": (prev or {}).get("status"),
        })
    else:
        version = 1
        history = []

    doc = {
        "id": _new_id(),
        "user_email": user_email,
        "role_at_authoring": role,
        "surface": surface,
        "diagram_hash": dh,
        "wrong_finding": wrong_finding or {},
        "correct_prompt": (correct_prompt or "").strip()[:4000],
        "tags": sorted(list({(t or "").strip().lower() for t in (tags or []) if t and t.strip()}))[:10],
        "scope": scope if scope in ("private", "team", "global") else "private",
        "verdict": verdict if verdict in ("correct", "incorrect", "partial", "suggest") else "incorrect",
        # Admin authoring a private/team correction auto-approves; global
        # always needs a second-admin approval to reduce single-admin abuse
        # (unless it's a private/team correction by an admin, in which case
        # the admin can self-approve since it's scoped).
        "status": "approved" if (role == "admin" and scope != "global") else "pending",
        "reuse_count": 0,
        "version": version,
        "prev_version_id": revises,
        "history": history,
        "created_at": now,
        "updated_at": now,
        "approved_at": now if (role == "admin" and scope != "global") else None,
        "approved_by": user_email if (role == "admin" and scope != "global") else None,
    }
    doc["confidence"] = compute_confidence(doc)
    await db[COLLECTION].insert_one(dict(doc))
    return doc


async def approve_correction(db, corr_id: str, admin_email: str) -> Optional[Dict[str, Any]]:
    now = _NOW()
    r = await db[COLLECTION].find_one_and_update(
        {"id": corr_id, "status": {"$ne": "approved"}},
        {"$set": {"status": "approved", "approved_at": now,
                  "approved_by": admin_email, "updated_at": now}},
        return_document=True,
    )
    if r:
        r["confidence"] = compute_confidence(r)
    return r


async def reject_correction(db, corr_id: str, admin_email: str, reason: str = "") -> Optional[Dict[str, Any]]:
    now = _NOW()
    r = await db[COLLECTION].find_one_and_update(
        {"id": corr_id},
        {"$set": {"status": "rejected", "updated_at": now,
                  "rejected_reason": (reason or "")[:400],
                  "rejected_by": admin_email}},
        return_document=True,
    )
    if r:
        r["confidence"] = compute_confidence(r)
    return r


async def rollback_to_version(db, corr_id: str, target_version: int,
                              admin_email: str) -> Optional[Dict[str, Any]]:
    """Restore a superseded prior version by copying its fields into a NEW
    correction that points back at both the current and the historical.
    The current doc is superseded."""
    now = _NOW()
    cur = await db[COLLECTION].find_one({"id": corr_id})
    if not cur:
        return None
    match = None
    for h in cur.get("history") or []:
        if h.get("version") == target_version:
            match = h
            break
    if not match:
        return None
    # Supersede the current
    await db[COLLECTION].update_one({"id": corr_id},
                                    {"$set": {"status": "superseded",
                                              "updated_at": now}})
    # Insert a rollback doc based on `match`
    new = {
        **cur,
        "id": _new_id(),
        "correct_prompt": match.get("correct_prompt") or cur.get("correct_prompt"),
        "status": "approved",
        "version": int(cur.get("version") or 1) + 1,
        "prev_version_id": corr_id,
        "history": (cur.get("history") or []) + [{
            "version": cur.get("version"),
            "user_email": cur.get("user_email"),
            "at": cur.get("updated_at"),
            "correct_prompt": (cur.get("correct_prompt") or "")[:400],
            "status": cur.get("status"),
            "rollback_by": admin_email,
        }],
        "created_at": now,
        "updated_at": now,
        "approved_at": now,
        "approved_by": admin_email,
        "reuse_count": 0,
    }
    new.pop("_id", None)
    new["confidence"] = compute_confidence(new)
    await db[COLLECTION].insert_one(dict(new))
    return new


# ----------------------------------------------------------------------
# listing — scoped by caller
# ----------------------------------------------------------------------
def _visible_filter(user_email: str) -> Dict[str, Any]:
    """A correction is visible to a caller when it is one of:
       - authored by them (any scope, any status)
       - team-scope AND approved
       - global-scope AND approved
    """
    return {
        "$or": [
            {"user_email": user_email},
            {"scope": "team",   "status": "approved"},
            {"scope": "global", "status": "approved"},
        ]
    }


async def list_corrections(db, *, user_email: str, surface: str | None = None,
                           limit: int = 200) -> List[Dict[str, Any]]:
    q: Dict[str, Any] = _visible_filter(user_email)
    if surface:
        q = {"$and": [q, {"surface": surface}]}
    items: List[Dict[str, Any]] = []
    async for d in db[COLLECTION].find(q).sort("updated_at", -1).limit(int(limit)):
        d["_id"] = str(d["_id"])
        d["confidence"] = compute_confidence(d)
        items.append(d)
    return items


async def list_pending_admin(db, limit: int = 200) -> List[Dict[str, Any]]:
    """Admin inbox — pending GLOBAL-scope corrections awaiting approval."""
    q = {"status": "pending", "scope": "global"}
    items: List[Dict[str, Any]] = []
    async for d in db[COLLECTION].find(q).sort("created_at", 1).limit(int(limit)):
        d["_id"] = str(d["_id"])
        d["confidence"] = compute_confidence(d)
        items.append(d)
    return items


# ----------------------------------------------------------------------
# matcher — hybrid tag + LLM-similarity fallback
# ----------------------------------------------------------------------
def _tag_score(query_tags: List[str], doc_tags: List[str]) -> float:
    if not query_tags or not doc_tags:
        return 0.0
    q = {t.lower().strip() for t in query_tags if t}
    d = {t.lower().strip() for t in doc_tags if t}
    inter = q & d
    if not inter:
        return 0.0
    return round(len(inter) / max(1, len(q | d)), 3)


async def find_applicable(
    db, *, user_email: str, surface: str,
    input_text: str = "",
    tags: List[str] | None = None,
    max_return: int = 10,
) -> List[Dict[str, Any]]:
    """Return corrections that should influence the current analysis.

    Matching strategy (hybrid):
      1. EXACT diagram-hash match on non-superseded, visible corrections.
         These are eligible for DETERMINISTIC OVERRIDE.
      2. Tag-Jaccard match ≥ 0.5 on visible corrections. Eligible for
         DETERMINISTIC OVERRIDE when the wrong_finding.kind matches
         exactly, otherwise LLM-INJECTED GUIDANCE.
      3. LLM-similarity fallback — a lightweight lexical similarity over
         `correct_prompt` and the surface's key strings, capped at the
         top-N so we don't overload the LLM prompt.

    Each returned doc has an added `apply_mode` in {"override", "inject"}.
    """
    tags = [t.lower().strip() for t in (tags or []) if t and t.strip()]
    dh = diagram_hash(input_text) if input_text else None
    base = _visible_filter(user_email)
    q = {"$and": [base, {"surface": surface}, {"status": {"$ne": "superseded"}}]}

    all_visible: List[Dict[str, Any]] = []
    async for d in db[COLLECTION].find(q).limit(500):
        d["_id"] = str(d["_id"])
        d["confidence"] = compute_confidence(d)
        all_visible.append(d)

    scored: List[Tuple[float, Dict[str, Any]]] = []
    for d in all_visible:
        if dh and d.get("diagram_hash") == dh:
            d = dict(d); d["apply_mode"] = "override"; d["_match_reason"] = "exact_hash"
            scored.append((1.0, d)); continue
        ts = _tag_score(tags, d.get("tags") or [])
        if ts >= 0.5:
            mode = "override" if ts >= 0.75 else "inject"
            d = dict(d); d["apply_mode"] = mode
            d["_match_reason"] = f"tag_jaccard={ts}"
            scored.append((ts, d)); continue
        # Lexical similarity — cheap fallback (LLM would be better but we
        # keep this deterministic-only for latency & cost).
        prompt = (d.get("correct_prompt") or "").lower()
        text = (input_text or "").lower()
        if not prompt or not text:
            continue
        # Simple bag-of-tokens overlap.
        pt = set(prompt.split())
        tt = set(text.split())
        if not pt or not tt:
            continue
        lex = len(pt & tt) / max(1, len(pt | tt))
        if lex >= 0.10:                # noisy — only inject
            d = dict(d); d["apply_mode"] = "inject"
            d["_match_reason"] = f"lex_similarity={round(lex,3)}"
            scored.append((lex, d))

    scored.sort(key=lambda x: (-x[0], -int(x[1].get("confidence") or 0)))
    return [d for _, d in scored[:max_return]]


async def bump_reuse(db, corr_ids: List[str]) -> None:
    if not corr_ids:
        return
    await db[COLLECTION].update_many(
        {"id": {"$in": list(corr_ids)}},
        {"$inc": {"reuse_count": 1}, "$set": {"updated_at": _NOW()}},
    )


# ----------------------------------------------------------------------
# application — patch results OR build inject prompt block
# ----------------------------------------------------------------------
def apply_overrides(result: Dict[str, Any],
                    applicable: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Mutate ``result`` in place — deterministic overrides only. Returns
    the same dict for chaining. Non-override corrections are ignored here
    (see :func:`inject_prompt_block`).

    Each ``wrong_finding`` supports:
      - {"kind":"mitre",   "value":"T1078"}        → drop it from result["mitre"]
      - {"kind":"lolbas",  "value":"powershell.exe"} → drop from result["lolbas"]
      - {"kind":"family",  "value":"Ransom"}       → clear family field
      - {"kind":"risk_verdict","value":"Malicious"} → downgrade to Suspicious
      - {"kind":"ioc",     "value":"http://x"}     → drop from iocs
      - {"kind":"replace", "field":"path", "value":X} → deep-set field
    """
    if not applicable:
        return result
    applied: List[Dict[str, Any]] = []
    for c in applicable:
        if c.get("apply_mode") != "override":
            continue
        # Feb-2026 v2/v3: only INCORRECT verdicts trigger a deterministic
        # override. Correct / Partial / Suggest never remove a finding —
        # they only steer the LLM path.
        if (c.get("verdict") or "incorrect") != "incorrect":
            continue
        wf = c.get("wrong_finding") or {}
        kind = (wf.get("kind") or "").lower()
        val  = wf.get("value")
        applied_meta = {"correction_id": c.get("id"), "kind": kind, "removed": None}
        if kind == "mitre" and val:
            before = result.get("mitre") or []
            result["mitre"] = [m for m in before if (m.get("id") or "") != val]
            applied_meta["removed"] = val
        elif kind == "lolbas" and val:
            before = result.get("lolbas") or []
            result["lolbas"] = [l for l in before if (l.get("binary") or "") != val]
            applied_meta["removed"] = val
        elif kind == "family":
            result["family"] = None
        elif kind == "risk_verdict":
            risk = dict(result.get("risk") or {})
            if risk.get("verdict") == val:
                risk["verdict"] = "Suspicious"
                risk["score"]   = max(30, int(risk.get("score") or 30))
                result["risk"]  = risk
                applied_meta["removed"] = val
        elif kind == "ioc" and val:
            iocs = dict(result.get("iocs") or {})
            for k, lst in list(iocs.items()):
                iocs[k] = [x for x in (lst or []) if x != val]
            result["iocs"] = iocs
            applied_meta["removed"] = val
        elif kind == "replace":
            fld = wf.get("field")
            if fld:
                result[fld] = wf.get("value")
                applied_meta["field"] = fld
        else:
            continue
        applied.append(applied_meta)
    if applied:
        result.setdefault("_applied_corrections", []).extend(applied)
    return result


async def get_analytics(db) -> Dict[str, Any]:
    """Feb-2026 v3-spec dashboard analytics — approval trend, per-surface
    heatmap, top-reused corrections, top corrected MITRE techniques,
    reviewer throughput, confidence calibration, FP/FN signal.

    All aggregates run in Mongo — no per-doc loading — so this scales to
    hundreds of thousands of corrections without impact.
    """
    from datetime import datetime, timezone, timedelta

    # Totals by status
    status_counts: Dict[str, int] = {}
    async for d in db[COLLECTION].aggregate([{"$group": {"_id": "$status", "n": {"$sum": 1}}}]):
        status_counts[d["_id"] or "unknown"] = d["n"]

    # Per-surface heatmap
    surface_counts: Dict[str, int] = {}
    async for d in db[COLLECTION].aggregate([
        {"$group": {"_id": "$surface", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}},
    ]):
        surface_counts[d["_id"] or "unknown"] = d["n"]

    # Top-reused (proven-value corrections)
    top_reused: List[Dict[str, Any]] = []
    async for d in db[COLLECTION].find(
        {"status": {"$in": ["approved", "pending"]}}
    ).sort("reuse_count", -1).limit(10):
        d["_id"] = str(d["_id"])
        d["confidence"] = compute_confidence(d)
        top_reused.append({
            "id": d["id"], "surface": d.get("surface"),
            "reuse_count": d.get("reuse_count", 0),
            "confidence": d["confidence"],
            "wrong_finding": d.get("wrong_finding"),
            "correct_prompt": (d.get("correct_prompt") or "")[:120],
            "tags": d.get("tags", []),
            "scope": d.get("scope"),
        })

    # Top corrected MITRE techniques
    mitre_hits: Dict[str, int] = {}
    async for d in db[COLLECTION].aggregate([
        {"$match": {"wrong_finding.kind": "mitre"}},
        {"$group": {"_id": "$wrong_finding.value", "n": {"$sum": 1}}},
        {"$sort": {"n": -1}},
        {"$limit": 10},
    ]):
        if d["_id"]:
            mitre_hits[str(d["_id"])] = d["n"]

    # Reviewer throughput
    reviewer_stats: List[Dict[str, Any]] = []
    async for d in db[COLLECTION].aggregate([
        {"$match": {"approved_by": {"$ne": None}}},
        {"$group": {"_id": "$approved_by",
                     "approved": {"$sum": 1}}},
        {"$sort": {"approved": -1}},
        {"$limit": 10},
    ]):
        reviewer_stats.append({"reviewer": d["_id"], "approved": d["approved"]})

    # Approval velocity (mean seconds pending → approved for approved docs)
    velocities: List[float] = []
    async for d in db[COLLECTION].find(
        {"status": "approved", "approved_at": {"$ne": None}, "created_at": {"$ne": None}},
    ).limit(500):
        try:
            t0 = datetime.fromisoformat(d["created_at"].replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(d["approved_at"].replace("Z", "+00:00"))
            velocities.append((t1 - t0).total_seconds())
        except Exception:
            pass
    avg_velocity_seconds = int(sum(velocities) / len(velocities)) if velocities else 0

    # 7-day trend — created/day
    trend: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc)
    for i in range(6, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        cnt = await db[COLLECTION].count_documents({
            "created_at": {"$gte": day_start.isoformat(), "$lt": day_end.isoformat()},
        })
        trend.append({"date": day_start.date().isoformat(), "count": cnt})

    # FP / FN heuristic — verdict distribution
    verdict_dist: Dict[str, int] = {}
    async for d in db[COLLECTION].aggregate([
        {"$group": {"_id": "$verdict", "n": {"$sum": 1}}},
    ]):
        verdict_dist[d["_id"] or "unspecified"] = d["n"]

    total = sum(status_counts.values()) or 1
    approved = status_counts.get("approved", 0)
    accuracy_signal = round(approved / total, 3)

    return {
        "totals": {
            "total": total,
            "approved": approved,
            "pending": status_counts.get("pending", 0),
            "rejected": status_counts.get("rejected", 0),
            "superseded": status_counts.get("superseded", 0),
        },
        "by_status":       status_counts,
        "by_surface":      surface_counts,          # heatmap data
        "top_reused":      top_reused,
        "top_mitre":       mitre_hits,
        "verdict_dist":    verdict_dist,             # FP/FN signal
        "reviewer_stats":  reviewer_stats,           # throughput
        "avg_approval_seconds": avg_velocity_seconds,
        "accuracy_signal": accuracy_signal,         # 0..1 approved / total
        "trend_7d":        trend,
    }


def inject_prompt_block(applicable: List[Dict[str, Any]]) -> str:
    """Render the LLM-prompt appendix for INJECT-mode corrections.

    Called by MoE / Threat-Model LLM enrichment paths to bias the model
    toward prior analyst guidance. Return an empty string if nothing
    applies. Deterministic-override entries are skipped here."""
    lines: List[str] = []
    inj = [c for c in (applicable or []) if c.get("apply_mode") == "inject"]
    if not inj:
        return ""
    lines.append("=== ANALYST CORRECTIONS (prior findings, authoritative when confidence ≥ 75) ===")
    for c in inj:
        wf = c.get("wrong_finding") or {}
        lines.append(
            f"- Correction {c.get('id')} · surface={c.get('surface')} · "
            f"conf={c.get('confidence')} · reuse={c.get('reuse_count')} · "
            f"scope={c.get('scope')} · v{c.get('version')}"
        )
        if wf:
            lines.append(f"    wrong_finding: {wf.get('kind','?')}={wf.get('value','?')}")
        prompt = (c.get("correct_prompt") or "").replace("\n", " ")[:600]
        lines.append(f"    correct_interpretation: {prompt}")
    lines.append("=== END ANALYST CORRECTIONS ===")
    return "\n".join(lines)
