"""Regression Corpus + Auto-Benchmark router — /api/regression/*.

Endpoints
    GET    /api/regression/corpus/entries          list corpus samples
    POST   /api/regression/corpus/entries          direct create
    DELETE /api/regression/corpus/entries/{id}     remove a sample (admin only)
    POST   /api/regression/run                     execute the benchmark now
    GET    /api/regression/latest                  most recent run summary
    GET    /api/regression/history?limit=N         run history (light)
    GET    /api/regression/runs/{id}               full run detail
    GET    /api/regression/gate                    current gate status
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from deps import db, get_current_user, require_admin
from regression import (
    add_corpus_entry, list_corpus_entries, delete_corpus_entry, corpus_count,
    run_benchmark, list_runs, get_run, get_latest_run,
    get_gate, gate_permits_promotion,
)


router = APIRouter()


class CorpusEntryIn(BaseModel):
    name: str = Field(..., description="Human-readable label")
    input: str
    expected_output: str
    expected_chain: List[Dict[str, Any]] = Field(default_factory=list)
    source: str = Field("direct", description="analyst-correction | direct | seed")
    notes: Optional[str] = None


@router.get("/regression/corpus/entries", tags=["regression"])
async def list_corpus(
    limit: int = 200, source: Optional[str] = None,
    user=Depends(get_current_user),
):
    entries = await list_corpus_entries(db, limit=limit, source=source)
    return {"entries": entries, "count": len(entries)}


@router.post("/regression/corpus/entries", tags=["regression"])
async def create_corpus_entry(body: CorpusEntryIn, user=Depends(get_current_user)):
    doc = await add_corpus_entry(
        db,
        name=body.name,
        input_text=body.input,
        expected_output=body.expected_output,
        expected_chain=body.expected_chain,
        source=body.source,
        created_by=user.get("email"),
        notes=body.notes,
    )
    return {"ok": True, "entry": doc}


@router.delete("/regression/corpus/entries/{entry_id}", tags=["regression"])
async def delete_corpus(entry_id: str, user=Depends(require_admin)):
    ok = await delete_corpus_entry(db, entry_id)
    if not ok:
        raise HTTPException(404, detail="entry not found")
    return {"ok": True}


@router.post("/regression/run", tags=["regression"])
async def trigger_run(user=Depends(get_current_user)):
    """Execute the full regression corpus now (synchronous — corpus is small)."""
    run = await run_benchmark(
        db, trigger="manual", triggered_by=user.get("email"),
    )
    return {"ok": True, "run": _light(run)}


@router.get("/regression/latest", tags=["regression"])
async def latest_run(user=Depends(get_current_user)):
    doc = await get_latest_run(db)
    if not doc:
        gate = await get_gate(db)
        n = await corpus_count(db)
        return {
            "run": None,
            "gate": gate,
            "corpus_size": n,
            "message": "no regression runs recorded yet",
        }
    from bson import ObjectId
    doc["_id"] = str(doc["_id"])
    if doc.get("previous_run_id") is not None:
        doc["previous_run_id"] = str(doc["previous_run_id"])
    return {
        "run": doc,
        "gate": await get_gate(db),
        "corpus_size": await corpus_count(db),
    }


@router.get("/regression/history", tags=["regression"])
async def history(limit: int = 30, user=Depends(get_current_user)):
    runs = await list_runs(db, limit=limit)
    return {"runs": runs, "count": len(runs)}


@router.get("/regression/runs/{run_id}", tags=["regression"])
async def run_detail(run_id: str, user=Depends(get_current_user)):
    doc = await get_run(db, run_id)
    if not doc:
        raise HTTPException(404, detail="run not found")
    return doc


@router.get("/regression/gate", tags=["regression"])
async def gate_status(user=Depends(get_current_user)):
    permit = await gate_permits_promotion(db)
    return {
        "gate": permit["gate"],
        "permits_promotion": permit["ok"],
        "reason": permit["reason"],
    }


# ── helpers ────────────────────────────────────────────────────────
def _light(run: Dict[str, Any]) -> Dict[str, Any]:
    """Strip the heavy `results` array for list-view responses."""
    return {k: v for k, v in run.items() if k != "results"}
