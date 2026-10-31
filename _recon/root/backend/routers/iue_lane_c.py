"""Lane-C analyze router — POST /api/iue/lane-c/analyze.

Feature-flag-gated (`IUE_ARTIFACT_LANE=on`) endpoint that accepts a
file/artifact upload (multipart or base64) and returns the T2 wire
contract emitted by ``services.iue.lanes.file_lane.analyze_file``.

Independent feature flag from Lane A/B so Lane C can be rolled out
in isolation (owner directive).

STAGE-1 rules:
  - Static analysis only.  No execution, no sandbox, no network.
  - Artifact-first: identify via the existing
    ``services.artifact_intelligence`` dispatcher, then surface the
    static-analysis result as a LogicalEvent(lane="file", …).
"""
from __future__ import annotations

import base64
import os
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from deps import get_current_user


router = APIRouter(prefix="/iue/lane-c", tags=["iue-lane-c"])


def _flag_on() -> bool:
    return os.environ.get("IUE_ARTIFACT_LANE", "off").lower() == "on"


@router.get("/status")
def status():
    """Return whether Lane C is currently enabled and its caps."""
    from services.iue import security as sec
    return {
        "enabled": _flag_on(),
        "flag":    os.environ.get("IUE_ARTIFACT_LANE", "off"),
        "caps": {
            "max_raw_bytes":    sec.MAX_RAW_BYTES,
            "max_record_count": sec.MAX_RECORD_COUNT,
            "max_record_bytes": sec.MAX_RECORD_BYTES,
        },
    }


class ArtifactB64Body(BaseModel):
    """Base64-encoded artifact upload (alternative to multipart)."""
    bytes_b64: str = Field(..., description="Base64-encoded raw bytes")
    filename: str = Field("", description="Original filename hint")
    mime: Optional[str] = Field(default=None,
                                   description="Optional MIME hint")


@router.post("/analyze")
async def analyze(
    # Multipart path
    file: Optional[UploadFile] = File(default=None),
    filename: Optional[str] = Form(default=None),
    mime: Optional[str] = Form(default=None),
    user=Depends(get_current_user),
):
    """Analyse an uploaded artifact via multipart file upload.

    For base64-only clients, use ``/analyze-b64`` instead.
    """
    if not _flag_on():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "iue_artifact_lane_disabled",
                "hint":  "Set IUE_ARTIFACT_LANE=on to enable Lane C.",
            },
        )

    if file is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_file",
                     "hint": "Provide multipart 'file' or use /analyze-b64 for JSON base64."},
        )

    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400,
                              detail={"error": "empty_payload"})

    fname = filename or file.filename or ""
    resolved_mime = mime or file.content_type or "application/octet-stream"

    from services.iue.lanes.file_lane import analyze_file
    session_ctx = {"tenant_id": (user or {}).get("tenant_id")
                                    or (user or {}).get("email")
                                    or (user or {}).get("sub")}
    return analyze_file(payload,
                          filename=fname,
                          mime=resolved_mime,
                          session_ctx=session_ctx,
                          allow_prev_fallback=False)


@router.post("/analyze-b64")
async def analyze_b64(body: ArtifactB64Body,
                        user=Depends(get_current_user)):
    """Analyse an uploaded artifact via JSON base64 payload."""
    if not _flag_on():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "iue_artifact_lane_disabled",
                "hint":  "Set IUE_ARTIFACT_LANE=on to enable Lane C.",
            },
        )
    if not body.bytes_b64:
        raise HTTPException(status_code=400,
                              detail={"error": "missing_bytes_b64"})
    try:
        payload = base64.b64decode(body.bytes_b64, validate=False)
    except Exception:
        raise HTTPException(status_code=400,
                              detail={"error": "invalid_base64"})
    if not payload:
        raise HTTPException(status_code=400,
                              detail={"error": "empty_payload"})

    from services.iue.lanes.file_lane import analyze_file
    session_ctx = {"tenant_id": (user or {}).get("tenant_id")
                                    or (user or {}).get("email")
                                    or (user or {}).get("sub")}
    return analyze_file(payload,
                          filename=body.filename or "",
                          mime=body.mime or "application/octet-stream",
                          session_ctx=session_ctx,
                          allow_prev_fallback=False)
