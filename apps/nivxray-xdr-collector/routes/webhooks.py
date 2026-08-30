"""
Generic inbound webhook framework · Phase A skeleton.

Phase A intentionally does NOT accept traffic — it just exposes a
route so Admin can display `Not Configured` honestly.  Real signature
verification / replay protection / tenant-mapping arrives in Phase B
alongside the first vendor that pushes events (e.g. Defender graph
webhooks).
"""
from fastapi import APIRouter, HTTPException

router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/{source_type}/{secret_id}")
async def inbound_webhook(source_type: str, secret_id: str):
    raise HTTPException(
        status_code=501,
        detail={"error": "not_implemented",
                  "phase": "A",
                  "note": "Inbound webhook framework lands in Phase B · "
                          "tenant-mapped signature-verified receiver."},
    )
