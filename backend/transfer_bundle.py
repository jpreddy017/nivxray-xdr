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
    # EDR access-loop repair · publication candidates A and B.
    "edr-access-loop": Path("/app/SECURE_EXPORT/edr-access-loop-package.tar.gz"),
    # Windows re-enrolment recovery · source + CI only, NO artifact.
    "win-reenrol": Path("/app/SECURE_EXPORT/win-reenrol-recovery-package.tar.gz"),
    # Gate 4 payload-context repair · source + CI only, NO artifact.
    "gate4": Path("/app/SECURE_EXPORT/gate4-payload-context-package.tar.gz"),
    # EDR "Recheck access" permanent repair · frontend only, on PR #17.
    "edr-denial": Path("/app/SECURE_EXPORT/edr-denial-recoverable-package.tar.gz"),
    # Windows recovery handoff · procedure + placement fix, NO artifact.
    "win-recovery": Path("/app/SECURE_EXPORT/win-recovery-handoff-package.tar.gz"),
    # B3 publication · placement fix + its CI gate, ready to push.
    "b3": Path("/app/SECURE_EXPORT/b3-placement-publication-package.tar.gz"),
    # Pre-deletion mongodump archive · created on demand under /tmp (only
    # ~1.3 GB free on /app, 64 GB on the overlay). Download it before
    # anything is armed; this pod is ephemeral.
    "edr-predelete": Path("/tmp/edr-predelete.archive.gz"),
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
