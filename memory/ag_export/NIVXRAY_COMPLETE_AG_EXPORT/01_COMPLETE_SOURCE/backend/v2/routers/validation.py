"""v2/routers/validation.py · Validation Pack API.

Endpoints:
  GET  /api/v2/validation/datasets  — list every Golden Corpus dataset + category
  GET  /api/v2/validation/run       — run the FULL suite (34 datasets)
  GET  /api/v2/validation/run/{id}  — run a single dataset

Flag-gated on VERDICT_ENGINE_V3.
"""
from __future__ import annotations
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from deps import require_admin
from v2.flags import get as get_flag
from v2.validation import run_all, run_dataset
from v2.ingestion.golden_corpus import GOLDEN_CORPUS

router = APIRouter(prefix="/v2/validation", tags=["v2-validation"])


def _guard() -> None:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")


@router.get("/datasets")
async def list_all(_: dict = Depends(require_admin)) -> dict[str, Any]:
    _guard()
    return {
        "ok": True,
        "datasets": [{
            "id": d.id, "label": d.label, "description": d.description,
            "category": d.category,
            "expected_verdict": d.expected_verdict,
            "event_count": len(d.records()),
            "assertions": {
                "verdict": d.expectations.verdict or None,
                "device_score_min": d.expectations.device_score_min if d.expectations.device_score_min >= 0 else None,
                "device_score_max": d.expectations.device_score_max if d.expectations.device_score_max >= 0 else None,
                "expected_mitre": list(d.expectations.expected_mitre),
                "expected_story_sequence": list(d.expectations.expected_story_sequence),
                "expected_processes": list(d.expectations.expected_processes),
                "expected_parent_child": [list(pc) for pc in d.expectations.expected_parent_child],
                "expected_iocs": list(d.expectations.expected_iocs),
                "expected_false_positive": d.expectations.expected_false_positive,
            },
        } for d in GOLDEN_CORPUS.values()],
    }


@router.get("/run")
async def run_suite(_: dict = Depends(require_admin)) -> dict[str, Any]:
    _guard()
    summary = run_all()
    payload = summary.to_dict()
    payload["ok"] = True
    return payload


@router.get("/run/{dataset_id}")
async def run_one(dataset_id: str, _: dict = Depends(require_admin)) -> dict[str, Any]:
    _guard()
    try:
        r = run_dataset(dataset_id)
    except KeyError:
        raise HTTPException(status_code=404, detail=f"unknown dataset {dataset_id!r}")
    return {"ok": True, "result": r.to_dict()}
