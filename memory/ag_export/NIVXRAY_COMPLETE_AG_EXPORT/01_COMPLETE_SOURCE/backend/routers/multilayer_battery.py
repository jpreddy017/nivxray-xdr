"""Multi-Layer Battery — public report endpoint.

Serves the JSON report produced by
`backend/tests/test_multilayer_battery.py` at:
  GET /api/benchmark/multilayer

If the report doesn't exist yet (fresh install), triggers a one-shot
in-process regeneration by invoking pytest on that single file.
"""
from __future__ import annotations
import json
import subprocess
from pathlib import Path

from fastapi import APIRouter

router = APIRouter(prefix="/benchmark", tags=["benchmark"])

REPORT_PATH = Path("/app/backend/tests/reports/multilayer_battery.json")


def _regenerate() -> None:
    try:
        subprocess.run(
            ["pytest", "-q", "backend/tests/test_multilayer_battery.py"],
            cwd="/app", capture_output=True, timeout=180,
        )
    except Exception:
        pass


@router.get("/multilayer")
async def multilayer_report():
    """Return the latest Multi-Layer Battery run summary."""
    if not REPORT_PATH.exists():
        _regenerate()
    if REPORT_PATH.exists():
        try:
            return json.loads(REPORT_PATH.read_text())
        except Exception as e:
            return {"error": f"report unreadable: {e}", "path": str(REPORT_PATH)}
    return {"error": "report not generated yet", "path": str(REPORT_PATH)}


@router.post("/multilayer/rerun")
async def multilayer_rerun():
    """Force-regenerate the report."""
    _regenerate()
    if REPORT_PATH.exists():
        return json.loads(REPORT_PATH.read_text())
    return {"error": "regenerate failed"}
