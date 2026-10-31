"""RC5 · Phase 9 · Shadow-Run Admin API.

Endpoints:
  * `GET  /api/rc5/shadow/status`  — current toggle state + snapshot count.
  * `POST /api/rc5/shadow/toggle`  — admin flips `SEMANTIC_ENGINE_V2` shadow-emit ON/OFF at runtime (does NOT touch the analysis code path; only the shadow collection).
  * `POST /api/rc5/shadow/record`  — record a paired RC4↔RC5 analysis. Called by the shadow-collector wrapper on `/api/analyze` etc.
  * `GET  /api/rc5/shadow/report/daily?day=YYYY-MM-DD` — daily delta report.
  * `GET  /api/rc5/shadow/report/cumulative?since_days=30` — 30-day cumulative.

Deterministic. Admin-JWT-gated. AI-free.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from deps import require_admin, db
from engine.shadow import (
    ShadowSnapshot, ensure_shadow_indexes, record_snapshot,
    daily_report, cumulative_report, make_snapshot, COLLECTION,
)


router = APIRouter(prefix="/rc5/shadow", tags=["rc5-shadow"])


# ---------------------------------------------------------------------------
# Runtime toggle — in-memory (survives per-process; a persistent toggle
# would also mirror to the `settings` collection, added below).
# ---------------------------------------------------------------------------
_SHADOW_STATE = {
    "emit_enabled": os.environ.get("RC5_SHADOW_EMIT", "").lower() in
                    ("1", "true", "yes", "on"),
    "toggled_at": datetime.now(timezone.utc).isoformat(),
    "toggled_by": "env",
}


def _flag_enabled() -> bool:
    """Master flag — mirrors the /parse gate for consistency."""
    v = os.environ.get("SEMANTIC_ENGINE_V2", "").lower()
    return v in ("1", "true", "yes", "on")


@router.get("/status")
async def shadow_status(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    total = await db[COLLECTION].count_documents({})
    return {
        "flag_semantic_engine_v2": _flag_enabled(),
        "emit_enabled": _SHADOW_STATE["emit_enabled"],
        "toggled_at": _SHADOW_STATE["toggled_at"],
        "toggled_by": _SHADOW_STATE["toggled_by"],
        "snapshots_total": total,
        "collection": COLLECTION,
    }


class ToggleRequest(BaseModel):
    enabled: bool


@router.post("/toggle")
async def shadow_toggle(
    payload: ToggleRequest,
    admin: dict = Depends(require_admin),
) -> Dict[str, Any]:
    _SHADOW_STATE["emit_enabled"] = bool(payload.enabled)
    _SHADOW_STATE["toggled_at"] = datetime.now(timezone.utc).isoformat()
    _SHADOW_STATE["toggled_by"] = admin.get("email") or admin.get("sub") or "admin"
    # Also persist to `settings` so status survives worker restarts.
    await db["settings"].update_one(
        {"_id": "rc5_shadow"},
        {"$set": {
            "emit_enabled": _SHADOW_STATE["emit_enabled"],
            "toggled_at": _SHADOW_STATE["toggled_at"],
            "toggled_by": _SHADOW_STATE["toggled_by"],
        }},
        upsert=True,
    )
    await ensure_shadow_indexes(db)
    return await shadow_status(admin)


class RecordRequest(BaseModel):
    original_input: str
    language: str = "cmd"
    corpus_label: Optional[str] = Field(default=None,
                                        description="benign | malicious | None")
    rc4_verdict: Optional[str] = None
    rc4_mitre: Optional[List[str]] = None
    rc4_lolbas: Optional[List[str]] = None
    rc4_latency_ms: Optional[float] = None
    rc4_exception: Optional[str] = None
    rc5_response: Optional[Dict[str, Any]] = None
    rc5_latency_ms: Optional[float] = None
    rc5_exception: Optional[str] = None


@router.post("/record")
async def shadow_record(
    payload: RecordRequest,
    _: dict = Depends(require_admin),
) -> Dict[str, Any]:
    if not _SHADOW_STATE["emit_enabled"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Shadow emit disabled — toggle ON via POST /rc5/shadow/toggle first."
        )
    snap = make_snapshot(
        original_input=payload.original_input,
        language=payload.language,
        rc4_verdict=payload.rc4_verdict,
        rc4_mitre=payload.rc4_mitre,
        rc4_lolbas=payload.rc4_lolbas,
        rc4_latency_ms=payload.rc4_latency_ms,
        rc4_exception=payload.rc4_exception,
        rc5_response=payload.rc5_response,
        rc5_latency_ms=payload.rc5_latency_ms,
        rc5_exception=payload.rc5_exception,
        corpus_label=payload.corpus_label,
    )
    doc_id = await record_snapshot(db, snap)
    return {"recorded": True, "id": doc_id, "sample_hash": snap.sample_hash,
            "day": snap.day}


@router.get("/report/daily")
async def report_daily(
    day: Optional[str] = Query(default=None,
                               description="YYYY-MM-DD UTC, default today"),
    _: dict = Depends(require_admin),
) -> Dict[str, Any]:
    return await daily_report(db, day=day)


@router.get("/report/cumulative")
async def report_cumulative(
    since_days: int = Query(default=30, ge=1, le=365),
    _: dict = Depends(require_admin),
) -> Dict[str, Any]:
    return await cumulative_report(db, since_days=since_days)


@router.get("/gate")
async def cutover_gate(_: dict = Depends(require_admin)) -> Dict[str, Any]:
    """Cutover gate. Returns `ready: true` when ALL success criteria met.

    Success criteria (locked per user directive, Feb 21 2026):

      A. Shadow-run stats (30-day window):
        * ≥ 200 snapshots aggregated
        * Crash rate  < 0.5 / 1000
        * FP change   ≤ 5
        * FN change   ≤ 5
        * Dangling refs = 0
        * Latency p95 regression ratio ≤ 1.30

      B. Golden Corpus health:
        * pass_rate ≥ 95 %
        * regression_count == 0 on the latest run

      C. Production health (self-reported):
        * `settings.prod_health.ok == true` — set by ops after health checks
          (5xx rate < 0.5 % · 4xx rate < 5 % · error budget green).

    If any block fails, the gate returns `ready_for_cutover: false` and
    Phase 10 cutover script refuses to run.
    """
    from engine.golden_corpus import latest_run as _golden_latest

    rpt = await cumulative_report(db, since_days=30)
    total = rpt.get("total", 0)
    parser = rpt.get("parser", {}) or {}
    latency = rpt.get("latency_ms", {}) or {}
    golden = await _golden_latest(db)
    golden_pass = float(golden.pass_rate) if golden else 0.0
    golden_regr = int(golden.regression_count) if golden else 999
    golden_total = int(golden.total) if golden else 0
    prod_health = await db["settings"].find_one({"_id": "prod_health"}) or {}
    prod_ok = bool(prod_health.get("ok", False))

    checks: Dict[str, Any] = {
        # A. shadow
        "shadow_min_snapshots":  total >= 200,
        "shadow_crash_rate":     (parser.get("crash_delta_per_1000") or 0) < 0.5,
        "shadow_fp_change":      rpt.get("fp_change", 0) <= 5,
        "shadow_fn_change":      rpt.get("fn_change", 0) <= 5,
        "shadow_dangling_refs":  (rpt.get("graph_completeness", {}) or {}).get("total_dangling_refs", 0) == 0,
        "shadow_latency_reg":    ((latency.get("rc5_regression_ratio_p95") or 0) <= 1.30),
        # B. golden corpus
        "golden_pass_rate_95":   golden_pass >= 95.0 and golden_total > 0,
        "golden_no_regression":  golden_regr == 0,
        # C. production health
        "prod_health_ok":        prod_ok,
    }
    ready = all(checks.values())
    return {
        "ready_for_cutover": ready,
        "checks": checks,
        "total_snapshots": total,
        "golden": {"pass_rate": golden_pass, "regression_count": golden_regr,
                   "total": golden_total,
                   "run_id": (golden.run_id if golden else None),
                   "ts": (golden.ts.isoformat() if golden else None)},
        "prod_health": {"ok": prod_ok, "reported_at": prod_health.get("reported_at")},
        "summary": rpt,
    }


class ProdHealthReport(BaseModel):
    ok: bool
    reason: Optional[str] = None
    metrics: Optional[Dict[str, Any]] = None


@router.post("/prod-health")
async def report_prod_health(
    payload: ProdHealthReport,
    admin: dict = Depends(require_admin),
) -> Dict[str, Any]:
    """Ops-reported production health flag consumed by the cutover gate."""
    await db["settings"].update_one(
        {"_id": "prod_health"},
        {"$set": {
            "ok": bool(payload.ok),
            "reason": payload.reason,
            "metrics": payload.metrics,
            "reported_at": datetime.now(timezone.utc).isoformat(),
            "reported_by": admin.get("email") or admin.get("sub") or "admin",
        }},
        upsert=True,
    )
    return {"ok": payload.ok}


__all__ = ["router"]
