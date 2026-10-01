"""v2/routers/ingestion.py · Investigation Ingestion Engine API.

Endpoints (all prefixed with `/api/v2/ingestion`):

  POST /upload              Upload one file → CES → shadow_observations.
  POST /golden/{dataset_id} Seed one Golden Corpus dataset into a fresh case.
  GET  /golden              List the Golden Corpus datasets.
  GET  /formats             List supported formats and sources (for the UI).

Every response returns an IngestionResult so the UI can render the
Ingestion Quality Metrics panel immediately.

Feature-flag gated on VERDICT_ENGINE_V3 (same as the rest of the v2
investigation stack).
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile

from deps import require_admin, db as _db
from v2.flags import get as get_flag
from v2.ingestion import ingest_bytes
from v2.ingestion.pipeline import _persist_case, _persist_events
from v2.ingestion.metrics import IngestionMetrics
from v2.ingestion.golden_corpus import list_datasets, get_dataset

router = APIRouter(prefix="/v2/ingestion", tags=["v2-ingestion"])


def _guard() -> None:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")


# ─── POST /upload ─────────────────────────────────────────────────────
@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    case_id: str | None = Form(None),
    case_name: str | None = Form(None),
    _: dict = Depends(require_admin),
) -> dict[str, Any]:
    """Ingest one uploaded file. Multi-file uploads are handled client-side
    by calling this endpoint once per file (keeps the pipeline atomic).
    """
    _guard()
    filename = file.filename or "upload"
    try:
        data = await file.read()
    finally:
        await file.close()
    if not data:
        raise HTTPException(status_code=400, detail="empty upload")
    if len(data) > 200 * 1024 * 1024:                        # 200 MB hard cap
        raise HTTPException(status_code=413, detail="file too large (>200MB)")

    result = await ingest_bytes(_db, data, filename,
                                 case_id=case_id, case_name=case_name)
    return result.to_dict()


# ─── GET /formats ─────────────────────────────────────────────────────
@router.get("/formats")
async def list_supported(_: dict = Depends(require_admin)) -> dict[str, Any]:
    """Static capability description for the drag-drop UI."""
    _guard()
    return {
        "ok": True,
        "formats": [
            {"id": "sysmon_xml",         "label": "Sysmon XML",
             "extensions": [".xml"],
             "fidelity": "high"},
            {"id": "windows_security",   "label": "Windows Security XML",
             "extensions": [".xml"],
             "fidelity": "high"},
            {"id": "json_canonical",     "label": "JSON (canonical CES)",
             "extensions": [".json", ".ndjson"],
             "fidelity": "high"},
            {"id": "csv_generic",        "label": "CSV",
             "extensions": [".csv"],
             "fidelity": "medium"},
            {"id": "zip_bundle",         "label": "ZIP bundle (mixed evidence)",
             "extensions": [".zip"],
             "fidelity": "high"},
        ],
        "roadmap": {
            "phase_4_2": ["Microsoft Defender for Endpoint", "CrowdStrike Falcon",
                          "SentinelOne", "Cisco Secure Endpoint",
                          "Splunk exports", "QRadar exports"],
            "phase_4_3": ["Custom CSV / JSON via field-mapping UI",
                          "EVTX native", "NDJSON generic",
                          "TXT / LOG generic"],
        },
    }


# ─── GET /golden ──────────────────────────────────────────────────────
@router.get("/golden")
async def list_golden(_: dict = Depends(require_admin)) -> dict[str, Any]:
    """List every Golden Investigation Corpus dataset."""
    _guard()
    return {"ok": True, "datasets": list_datasets()}


# ─── POST /golden/{dataset_id} ────────────────────────────────────────
@router.post("/golden/{dataset_id}")
async def seed_golden(dataset_id: str,
                       case_id: str | None = Form(None),
                       _: dict = Depends(require_admin)) -> dict[str, Any]:
    """Materialise one Golden Corpus dataset into a fresh case so the
    workspace can be opened against it. Uses the CES → CEM writer
    directly (no file parsing needed).
    """
    _guard()
    ds = get_dataset(dataset_id)
    if ds is None:
        raise HTTPException(status_code=404, detail=f"unknown dataset {dataset_id!r}")

    job_id = f"golden_{uuid.uuid4().hex[:12]}"
    cid = case_id or f"case_golden_{dataset_id}_{uuid.uuid4().hex[:8]}"

    metrics = IngestionMetrics(ingest_job_id=job_id, case_id=cid)
    metrics.files_uploaded = 1
    metrics.file_names.append(f"golden-corpus/{dataset_id}")
    metrics.detected_formats["golden"] = 1
    metrics.detected_sources["sysmon"] = 1

    records = ds.records()
    metrics.events_parsed = len(records)
    metrics.events_normalized = len(records)

    await _persist_case(_db, cid, name=f"Golden · {ds.label}")
    inserted = await _persist_events(_db, cid, records, ingest_job_id=job_id)
    metrics.events_persisted = inserted
    metrics.finish()

    return {
        "ok": True,
        "dataset": ds.id,
        "case_id": cid,
        "ingest_job_id": job_id,
        "workspace_url": f"/v2/case/{cid}",
        "expected_verdict": ds.expected_verdict,
        "metrics": metrics.to_dict(),
    }
