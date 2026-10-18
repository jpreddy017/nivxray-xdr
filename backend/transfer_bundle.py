"""Temporary, token-gated download route for Stage 2B evidence bundles."""
import os
import secrets
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

transfer_router = APIRouter(prefix="/transfer", tags=["transfer"])

EVIDENCE = Path("/app/rocket-evidence/e3")
BUNDLES = {
    "stage2b-part2": EVIDENCE / "nivxray-e3-stage2b-part2.bundle",
    "stage2b-part3": EVIDENCE / "nivxray-e3-stage2b-part3.bundle",
    # S1 publication package for N-3A (patches + thin git bundle + manifest).
    "n3a-s1-package": Path("/app/SECURE_EXPORT/n3a-s1-publication-package.tar.gz"),
}


@transfer_router.get("/{name}")
async def download_bundle(name: str, token: str = Query(...)):
    expected = os.environ.get("STAGE2B_TRANSFER_TOKEN")
    if not expected or not secrets.compare_digest(token, expected):
        raise HTTPException(status_code=404, detail="Not found")
    bundle = BUNDLES.get(name)
    if bundle is None:
        raise HTTPException(status_code=404, detail="Not found")
    path = Path(bundle)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(path, media_type="application/octet-stream",
                        filename=path.name)
