"""v2/routers/ikb.py · Investigation Knowledge Base endpoints."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException
from deps import require_admin
from v2.flags import get as get_flag
from v2.ikb import all_entries, lookup

router = APIRouter(prefix="/v2/ikb", tags=["v2-ikb"])


@router.get("")
async def list_kb(_: dict = Depends(require_admin)) -> dict:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")
    return {
        "ok": True,
        "count": len(all_entries()),
        "entries": [e.to_dict() for e in all_entries()],
    }


@router.get("/{entry_id:path}")
async def get_kb(entry_id: str, _: dict = Depends(require_admin)) -> dict:
    if not get_flag("VERDICT_ENGINE_V3").observable():
        raise HTTPException(status_code=503, detail="verdict engine v3 disabled")
    e = lookup(entry_id)
    if not e:
        raise HTTPException(status_code=404, detail=f"kb entry not found: {entry_id}")
    return {"ok": True, "entry": e.to_dict()}
