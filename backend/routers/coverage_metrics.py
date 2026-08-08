"""Coverage Metrics API · read-only observability surface.

Consumes the latest + previous corpus reports (produced by
``scripts.corpus_validation``) and computes trend deltas, targets,
and the Reachable-Behaviors KPI the user asked for in P0.12.

    · GET /api/investigation/coverage/summary  → full report
    · GET /api/investigation/coverage/consumer_matrix → per-behavior matrix

No recomputation — everything is derived from the JSON reports the
harness has already written.
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query

from services.ida.behavior_registry import build_registry


COVERAGE_SCHEMA_VERSION = "1.0"

# Coverage regression thresholds — CI can fail on breach.
_TARGETS: Dict[str, float] = {
    "evidence_to_behavior_pct":           95.0,
    "behavior_to_projection_pct":         95.0,
    "projection_to_recommendation_pct":   70.0,
}

# Resolve relative to the backend root so the endpoint works
# regardless of the process CWD (uvicorn, pytest, ad-hoc scripts).
_REPORTS_DIR = (pathlib.Path(__file__).resolve().parents[1]
                / "corpus" / "reports")


router = APIRouter(tags=["coverage"])


def _load(name: str) -> Optional[Dict[str, Any]]:
    p = _REPORTS_DIR / name
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _coverage_with_deltas(latest: Dict[str, Any],
                              previous: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    lcov = (latest or {}).get("coverage") or {}
    pcov = (previous or {}).get("coverage") or {}
    for k, target in _TARGETS.items():
        cur = float(lcov.get(k, 0.0))
        prv = float(pcov.get(k, cur))
        out[k.replace("_pct", "")] = {
            "current":     cur,
            "previous":    prv,
            "delta":       round(cur - prv, 2),
            "target":      target,
            "meets_target": cur >= target,
        }
    return out


def _reachable_behavior_kpi(latest: Dict[str, Any]) -> Dict[str, Any]:
    """Reachable Behaviors KPI · replaces raw dead-rule count.

        reachable   = behaviors observed in the corpus
        consumed    = subset that produced at least one fired
                        recommendation (i.e. a complete chain)
        percent     = 100 * consumed / reachable
    """
    if not latest:
        return {"reachable": 0, "consumed_by_recommendations": 0,
                  "percent":   0.0}
    trace = latest.get("traceability_aggregate") or {}
    reachable = int(trace.get("total_behaviors")   or 0)
    consumed  = int(trace.get("complete_chains")   or 0)
    percent   = round(consumed / reachable * 100, 1) if reachable else 0.0
    return {"reachable": reachable,
              "consumed_by_recommendations": consumed,
              "percent": percent}


@router.get("/investigation/coverage/summary")
def coverage_summary(previous: str = Query(default="",
                                                     description="Optional previous report filename"),
                        latest:   str = Query(default="latest.json",
                                                     description="Latest report filename")) -> Dict[str, Any]:
    latest_r = _load(latest)
    if latest_r is None:
        raise HTTPException(status_code=404,
                                detail=f"report not found: {latest}")
    prev_r = _load(previous) if previous else None
    return {
        "schema_version":       COVERAGE_SCHEMA_VERSION,
        "generated_at":         latest_r.get("generated_at"),
        "corpus_size":          latest_r.get("corpus_size"),
        "coverage":             _coverage_with_deltas(latest_r, prev_r),
        "reachable_behaviors":  _reachable_behavior_kpi(latest_r),
        "dead_rule_classification": latest_r.get(
                                          "dead_rule_classification") or {},
        "traceability_aggregate":   latest_r.get(
                                          "traceability_aggregate") or {},
        "latency_ms":               latest_r.get("latency_ms") or {},
    }


@router.get("/investigation/coverage/consumer_matrix")
def consumer_matrix() -> Dict[str, Any]:
    """Per-behavior consumer reachability matrix — derived from the
    Behavior Registry.  Rows are behaviors, columns are downstream
    consumers.  Analyst dashboard uses this to spot behaviors that
    are known to the registry but not read by every consumer."""
    reg = build_registry()
    # Compute the union of consumer keys across the registry so the
    # matrix is dense.
    all_consumers: List[str] = []
    for spec in reg.values():
        for c in spec.consumer_reach.keys():
            if c not in all_consumers:
                all_consumers.append(c)
    matrix: List[Dict[str, Any]] = []
    per_consumer_hits: Dict[str, int] = {c: 0 for c in all_consumers}
    for btype, spec in reg.items():
        row: Dict[str, Any] = {"behavior_type": btype}
        for c in all_consumers:
            hit = bool(spec.consumer_reach.get(c))
            row[c] = hit
            if hit:
                per_consumer_hits[c] += 1
        matrix.append(row)
    total = len(reg) or 1
    per_consumer_pct = {
        c: round(per_consumer_hits[c] / total * 100, 1)
        for c in all_consumers
    }
    return {
        "schema_version":     COVERAGE_SCHEMA_VERSION,
        "consumers":          all_consumers,
        "matrix":             matrix,
        "per_consumer_pct":   per_consumer_pct,
        "total_behaviors":    len(reg),
    }


__all__ = ["router", "COVERAGE_SCHEMA_VERSION"]
