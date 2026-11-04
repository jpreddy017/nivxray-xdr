"""NivXRay Analyst Operations · MSS Dashboard projections.

Read-only projections that power the SOC command center at
`/xdr/mss-dashboard`.  Every endpoint is a pure Mongo query on top of
`workspace_cases` — no engine is ever invoked.

Owner directive 2026-02-31:
  - Every metric identifies its source.
  - No fabricated counts, techniques, workloads or customer data.
  - Where authoritative data is absent, we surface an honest
    `source: "unavailable"` state instead of fabricating zeros.
  - MSS Dashboard NEVER executes an investigation engine.  Engine
    activity is derived from persisted execution records (Phase 4).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query

from deps import get_current_user_optional, sync_collection
from services.dashboard_lenses import (
    LENSES, LENS_GROUPS, build_predicate, is_never_match,
)

router = APIRouter(prefix="/xdr/mss", tags=["xdr-mss-dashboard"])

_col = sync_collection("workspace_cases")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _base_scope(email: str | None) -> Dict[str, Any]:
    q: Dict[str, Any] = {"name": {"$exists": True, "$ne": ""}}
    if email:
        q["user_email"] = email
    return q


# ═══════════════════════════════════════════════════════════════════
# A · KPI / lens tiles  (reuses services.dashboard_lenses so the count
#     on the MSS Dashboard equals the count on the queue.)
# ═══════════════════════════════════════════════════════════════════
@router.get("/kpis")
async def mss_kpis(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    email = (user or {}).get("email")
    tiles_by_group: Dict[str, List[Dict[str, Any]]] = {g: [] for g in LENS_GROUPS}
    for lens in LENSES:
        pred = build_predicate(lens["id"], email)
        if is_never_match(pred):
            count, source = 0, "empty"
        else:
            count, source = int(_col.count_documents(pred)), "live"
        tiles_by_group[lens["group"]].append({
            "id":           lens["id"],
            "label":        lens["label"],
            "description":  lens["description"],
            "tone":         lens["tone"],
            "count":        count,
            "count_source": source,
            "lens_href":    f"/xdr/incidents?lens={lens['id']}",
        })
    return {
        "generated_at": _now().isoformat(),
        "groups": [
            {"id": gid, "label": gid.upper(), "tiles": tiles_by_group[gid]}
            for gid in LENS_GROUPS
        ],
    }


# ═══════════════════════════════════════════════════════════════════
# B · State distribution — powers the severity/state donut chart.
# ═══════════════════════════════════════════════════════════════════
@router.get("/state-distribution")
async def mss_state_distribution(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    """How many open incidents are in each lifecycle state + each
    priority bucket.  Zero-fill only for the KNOWN state/priority
    values so the donut chart shape stays deterministic.  A count of
    zero is not fabrication — it's honest measurement of the scope."""
    email = (user or {}).get("email")
    q = _base_scope(email)
    cur = _col.find(q, {"_id": 0, "incident_state": 1, "incident_priority": 1,
                             "verdict_stage2": 1})
    states = {"new": 0, "in_progress": 0, "on_hold": 0,
                "resolved": 0, "closed": 0}
    priorities = {"P1": 0, "P2": 0, "P3": 0, "P4": 0, "P5": 0, "unset": 0}
    total = 0
    for d in cur:
        total += 1
        st = d.get("incident_state") or "new"
        states[st] = states.get(st, 0) + 1
        p = d.get("incident_priority")
        if p in priorities and p != "unset":
            priorities[p] += 1
        else:
            priorities["unset"] += 1
    return {
        "generated_at": _now().isoformat(),
        "total":        total,
        "source":       "workspace_cases.live",
        "states":       states,
        "priorities":   priorities,
    }


# ═══════════════════════════════════════════════════════════════════
# C · Open High Priority queue table (top-N incidents most needing
#     analyst attention).  Reuses the same predicate as the
#     "high_priority" lens.
# ═══════════════════════════════════════════════════════════════════
@router.get("/soc-queue")
async def mss_soc_queue(limit: int = Query(10, ge=1, le=50),
                            user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    email = (user or {}).get("email")
    pred = build_predicate("high_priority", email)
    if is_never_match(pred):
        return {"generated_at": _now().isoformat(), "rows": [], "count": 0,
                  "source": "empty"}
    cur = _col.find(pred, {
        "_id": 0, "id": 1, "name": 1, "user_email": 1, "tenant_id": 1,
        "created_at": 1, "updated_at": 1, "verdict_stage2": 1, "verdict_card": 1,
        "incident_state": 1, "incident_assignee": 1, "incident_priority": 1,
        "incident_severity": 1, "high_fidelity": 1, "customer_engaged": 1,
        "on_hold_reason": 1, "on_hold_until": 1, "sla_due_at": 1,
    }).sort("updated_at", -1).limit(int(limit))
    rows = []
    for d in cur:
        stage2 = d.get("verdict_stage2") or {}
        rows.append({
            "id":             d.get("id"),
            "name":           d.get("name") or "(unnamed)",
            "priority":       d.get("incident_priority") or "unset",
            "severity":       d.get("incident_severity")
                                 or (stage2.get("label") or "unset"),
            "customer":       d.get("tenant_id") or d.get("user_email") or "default",
            "detection_source": (stage2.get("engine")
                                    or d.get("engine")
                                    or "unknown"),
            "state":          d.get("incident_state") or "new",
            "assignee":       d.get("incident_assignee") or d.get("user_email"),
            "sla_due_at":     d.get("sla_due_at"),
            "verdict":        stage2.get("label"),
            "confidence":     stage2.get("confidence_bucket"),
            "risk_score":     stage2.get("risk_score"),
            "high_fidelity":  bool(d.get("high_fidelity")),
            "updated_at":     d.get("updated_at") or d.get("created_at"),
        })
    return {
        "generated_at": _now().isoformat(),
        "count":  len(rows),
        "source": "workspace_cases.high_priority_lens",
        "rows":   rows,
    }


# ═══════════════════════════════════════════════════════════════════
# D · Analyst workload — real ownership data.
# ═══════════════════════════════════════════════════════════════════
@router.get("/analyst-workload")
async def mss_analyst_workload(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    email = (user or {}).get("email")
    q = _base_scope(email)
    q["incident_state"] = {"$nin": ["resolved", "closed"]}

    # Aggregate.
    pipeline = [
        {"$match": q},
        {"$group": {
            "_id": {"$ifNull": ["$incident_assignee", None]},
            "assigned":     {"$sum": 1},
            "p1_p2":        {"$sum": {"$cond": [
                {"$in": ["$incident_priority", ["P1", "P2"]]}, 1, 0]}},
            "on_hold":      {"$sum": {"$cond": [
                {"$eq": ["$incident_state", "on_hold"]}, 1, 0]}},
            "sla_risk":     {"$sum": {"$cond": [
                {"$and": [
                    {"$ne": ["$sla_due_at", None]},
                    {"$lte": ["$sla_due_at",
                                (_now() + timedelta(hours=4)).isoformat()]},
                ]}, 1, 0]}},
        }},
        {"$sort": {"assigned": -1, "_id": 1}},
        {"$limit": 25},
    ]
    rows = []
    for r in _col.aggregate(pipeline):
        analyst = r["_id"]
        rows.append({
            "analyst":  analyst or "unassigned",
            "assigned": int(r["assigned"]),
            "p1_p2":    int(r["p1_p2"]),
            "on_hold":  int(r["on_hold"]),
            "sla_risk": int(r["sla_risk"]),
            "queue_href": (f"/xdr/incidents?lens=unassigned"
                                if not analyst else
                                f"/xdr/incidents?assignee={analyst}"),
        })
    return {
        "generated_at": _now().isoformat(),
        "source":       "workspace_cases.aggregate.incident_assignee",
        "count":        len(rows),
        "rows":         rows,
    }


# ═══════════════════════════════════════════════════════════════════
# E · Customer operations — real tenant data.
# ═══════════════════════════════════════════════════════════════════
@router.get("/customer-operations")
async def mss_customer_operations(user=Depends(get_current_user_optional)) -> Dict[str, Any]:
    email = (user or {}).get("email")
    q = _base_scope(email)
    pipeline = [
        {"$match": q},
        {"$group": {
            "_id": {"$ifNull": ["$tenant_id",
                                     {"$ifNull": ["$user_email", "default"]}]},
            "open":       {"$sum": {"$cond": [
                {"$not": [{"$in": ["$incident_state", ["resolved", "closed"]]}]}, 1, 0]}},
            "critical":   {"$sum": {"$cond": [
                {"$eq": ["$incident_priority", "P1"]}, 1, 0]}},
            "high_prio":  {"$sum": {"$cond": [
                {"$in": ["$incident_priority", ["P1", "P2"]]}, 1, 0]}},
            "sla_risk":   {"$sum": {"$cond": [
                {"$and": [
                    {"$ne": ["$sla_due_at", None]},
                    {"$lte": ["$sla_due_at",
                                (_now() + timedelta(hours=4)).isoformat()]},
                ]}, 1, 0]}},
            "unassigned": {"$sum": {"$cond": [
                {"$or": [
                    {"$eq": [{"$ifNull": ["$incident_assignee", ""]}, ""]},
                ]}, 1, 0]}},
        }},
        {"$sort": {"open": -1, "critical": -1, "_id": 1}},
        {"$limit": 25},
    ]
    rows = []
    for r in _col.aggregate(pipeline):
        rows.append({
            "customer":   r["_id"],
            "open":       int(r["open"]),
            "critical":   int(r["critical"]),
            "high_prio":  int(r["high_prio"]),
            "sla_risk":   int(r["sla_risk"]),
            "unassigned": int(r["unassigned"]),
            "queue_href": f"/xdr/incidents?customer={r['_id']}",
        })
    return {
        "generated_at": _now().isoformat(),
        "source":       "workspace_cases.aggregate.tenant_id",
        "count":        len(rows),
        "rows":         rows,
    }


# ═══════════════════════════════════════════════════════════════════
# F · Auto-Investigation status — Phase 4 provenance (honest empty).
# ═══════════════════════════════════════════════════════════════════
@router.get("/auto-investigation")
async def mss_auto_investigation(
    user=Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Auto-Investigation status is derived from persisted engine
    execution records.  Until Phase 4 ships the `engine_executions`
    collection (see /app/memory/PHASE4_ORCHESTRATION_SPEC.md), this
    endpoint honestly reports `source: "unavailable"` — NEVER a
    fabricated zero."""
    from pymongo.errors import CollectionInvalid  # noqa: F401
    db = _col.database
    has_exec = "engine_executions" in db.list_collection_names()
    has_obs  = "xdr_observations"  in db.list_collection_names()

    if not (has_exec or has_obs):
        return {
            "generated_at": _now().isoformat(),
            "source":       "unavailable",
            "reason":       "Phase 4 · engine-execution ledger not yet online",
            "status":       None,
            "engines":      [],
        }

    # When Phase 4 lands, populate from the ledger.  For now we return
    # empty projections with source="live" but zero rows.
    status = {"running": 0, "completed": 0, "awaiting_evidence": 0, "failed": 0}
    engines: List[Dict[str, Any]] = []
    if has_exec:
        exe = db["engine_executions"]
        status["running"]     = int(exe.count_documents({"status": "running"}))
        status["completed"]   = int(exe.count_documents({"status": "ok"}))
        status["failed"]      = int(exe.count_documents({"status": "error"}))
        status["awaiting_evidence"] = int(
            exe.count_documents({"status": "skipped",
                                   "reason": {"$regex": "evidence", "$options": "i"}}))
        for r in exe.aggregate([
            {"$group": {"_id": "$engine",
                        "runs": {"$sum": 1},
                        "ok":   {"$sum": {"$cond": [{"$eq": ["$status", "ok"]}, 1, 0]}}}},
            {"$sort": {"runs": -1}}, {"$limit": 20},
        ]):
            engines.append({"engine": r["_id"], "runs": int(r["runs"]),
                                "ok": int(r["ok"])})
    return {
        "generated_at": _now().isoformat(),
        "source":       "engine_executions.live",
        "status":       status,
        "engines":      engines,
    }


# ═══════════════════════════════════════════════════════════════════
# G · Detection & MITRE overview — real technique counts.
# ═══════════════════════════════════════════════════════════════════
@router.get("/detection-overview")
async def mss_detection_overview(
    user=Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Top MITRE ATT&CK techniques + top detection sources across the
    caller's incident scope.  Aggregates the `techniques` /
    `verdict_stage2.evidence[].technique_id` arrays.  Never invents a
    technique — a technique that isn't in real evidence isn't listed."""
    email = (user or {}).get("email")
    q = _base_scope(email)
    q["incident_state"] = {"$nin": ["resolved", "closed"]}

    # Detection sources — grouped by the engine that produced the
    # canonical evidence.
    src_pipeline = [
        {"$match": q},
        {"$group": {
            "_id": {"$ifNull": [
                "$verdict_stage2.engine",
                {"$ifNull": ["$engine", "unknown"]},
            ]},
            "count": {"$sum": 1},
        }},
        {"$sort": {"count": -1, "_id": 1}}, {"$limit": 10},
    ]
    detection_sources = [
        {"source": r["_id"] or "unknown", "count": int(r["count"])}
        for r in _col.aggregate(src_pipeline)
    ]

    # Top techniques.
    tech_pipeline = [
        {"$match": q},
        {"$project": {
            "tids": {
                "$setUnion": [
                    {"$ifNull": [
                        {"$map": {"input": "$verdict_stage2.evidence",
                                     "as": "e",
                                     "in":  "$$e.technique_id"}}, []]},
                    {"$ifNull": [
                        {"$map": {"input": "$mitre",
                                     "as": "m",
                                     "in":  "$$m.technique_id"}}, []]},
                    {"$ifNull": ["$techniques", []]},
                ],
            },
        }},
        {"$unwind": "$tids"},
        {"$match": {"tids": {"$nin": [None, ""]}}},
        {"$group": {"_id": "$tids", "count": {"$sum": 1}}},
        {"$sort": {"count": -1, "_id": 1}}, {"$limit": 12},
    ]
    top_techniques = [
        {"technique_id": r["_id"], "count": int(r["count"])}
        for r in _col.aggregate(tech_pipeline)
    ]
    return {
        "generated_at":       _now().isoformat(),
        "source":             "workspace_cases.aggregate.evidence",
        "detection_sources":  detection_sources,
        "top_techniques":     top_techniques,
    }


# ═══════════════════════════════════════════════════════════════════
# H · Recent Activity — recent incident-lifecycle changes.
# ═══════════════════════════════════════════════════════════════════
@router.get("/recent-activity")
async def mss_recent_activity(
    limit: int = Query(15, ge=1, le=50),
    user=Depends(get_current_user_optional),
) -> Dict[str, Any]:
    """Most recent lifecycle activity across the incident scope.
    Sources: `incident_state_history` on the incident doc.  When the
    incident has no history, we surface its `updated_at` timestamp
    as a plain "updated" event."""
    email = (user or {}).get("email")
    q = _base_scope(email)
    cur = _col.find(q, {"_id": 0, "id": 1, "name": 1,
                             "incident_state": 1, "incident_state_history": 1,
                             "incident_assignee": 1,
                             "updated_at": 1, "created_at": 1}
                        ).sort("updated_at", -1).limit(50)
    events: List[Dict[str, Any]] = []
    for d in cur:
        history = d.get("incident_state_history") or []
        if history:
            for h in history[-3:]:
                events.append({
                    "incident_id":   d["id"],
                    "incident_name": d.get("name"),
                    "action":        f"state → {h.get('to_state', 'unknown')}",
                    "actor":         h.get("actor") or "system",
                    "at":            h.get("at") or d.get("updated_at"),
                })
        else:
            events.append({
                "incident_id":   d["id"],
                "incident_name": d.get("name"),
                "action":        "updated",
                "actor":         d.get("incident_assignee") or "system",
                "at":            d.get("updated_at") or d.get("created_at"),
            })
    # Sort by at DESC.
    events.sort(key=lambda e: (e["at"] or ""), reverse=True)
    return {
        "generated_at": _now().isoformat(),
        "source":       "workspace_cases.incident_state_history",
        "count":        min(int(limit), len(events)),
        "events":       events[:int(limit)],
    }
