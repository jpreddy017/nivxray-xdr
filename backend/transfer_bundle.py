"""Temporary, token-gated download route for the Stage 2B Part 2 evidence bundle."""
import os
import secrets
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

transfer_router = APIRouter(prefix="/transfer", tags=["transfer"])

BUNDLE = Path("/app/rocket-evidence/e3/nivxray-e3-stage2b-part2.bundle")


@transfer_router.get("/stage2b-part2")
async def download_stage2b_part2(token: str = Query(...)):
    expected = os.environ.get("STAGE2B_TRANSFER_TOKEN")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=404, detail="Not found")
    if not BUNDLE.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(
        BUNDLE,
        media_type="application/octet-stream",
        filename=BUNDLE.name,
    )
