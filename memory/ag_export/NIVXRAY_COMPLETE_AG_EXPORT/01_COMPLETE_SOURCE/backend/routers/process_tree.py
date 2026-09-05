"""Process-Tree router — /api/analyze/process-tree + /api/training/*.

Endpoints
---------
POST /api/analyze/process-tree
     body: {"raw": "...", "decoded": "..."}
     → Predict a validated ProcessTree from raw+decoded payload pair.

GET  /api/training/schema
     → Return the canonical schema (as JSON-Schema-ish dict) + prompt.

GET  /api/training/stats
     → Return dataset stats (total, per-platform, per-category).

GET  /api/training/archetypes
     → Return the list of seed archetype IDs / metadata (no full trees).

GET  /api/training/dataset?format=jsonl|openai|anthropic|csv|edge-list
     → Stream the entire seed dataset in the chosen format.

POST /api/training/render
     body: {"tree": <ProcessTree JSON>, "format": "ascii|edge-list|json"}
     → Convert a nested-JSON tree to another format.
"""
from __future__ import annotations
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from deps import get_current_user
from training.predictor import predict_process_tree
from training.schema import ProcessTree
from training.seed_dataset import all_archetypes, stats as _stats
from training.system_prompt import NIVXRAY_PROCESS_TREE_SYSTEM
from training.tree_formats import to_edge_list, to_ascii_tree, edge_list_to_tree
from training.exporter import FORMATS

router = APIRouter()


class ProcessTreeIn(BaseModel):
    raw: str = Field("", description="Raw (possibly obfuscated) command line")
    decoded: str = Field("", description="Deterministic-decoder output")


@router.post("/analyze/process-tree", tags=["process-tree"])
async def analyze_process_tree(body: ProcessTreeIn, user=Depends(get_current_user)) -> Dict[str, Any]:
    """Predict a validated process-execution tree for the given payload pair."""
    if not body.raw and not body.decoded:
        raise HTTPException(status_code=400, detail="raw and/or decoded required")
    tree = await predict_process_tree(body.raw, body.decoded)
    return {
        "tree": tree.model_dump(),
        "edge_list": to_edge_list(tree),
        "ascii": to_ascii_tree(tree),
    }


@router.get("/training/schema", tags=["training"])
async def training_schema(user=Depends(get_current_user)) -> Dict[str, Any]:
    """Return the canonical schema (as JSON schema) + system prompt."""
    return {
        "system_prompt": NIVXRAY_PROCESS_TREE_SYSTEM.strip(),
        "process_tree_schema": ProcessTree.model_json_schema(),
        "formats": list(FORMATS.keys()),
    }


@router.get("/training/stats", tags=["training"])
async def training_stats(user=Depends(get_current_user)) -> Dict[str, Any]:
    return _stats()


@router.get("/training/archetypes", tags=["training"])
async def list_archetypes(
    platform: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    user=Depends(get_current_user),
) -> Dict[str, Any]:
    records = all_archetypes()
    if platform:
        records = [r for r in records if r.platform == platform]
    if category:
        records = [r for r in records if r.category == category]
    return {
        "total": len(records),
        "archetypes": [{
            "training_id": r.training_id,
            "platform":    r.platform,
            "category":    r.category,
            "difficulty":  r.difficulty,
            "tags":        r.tags,
            "verdict":     r.predicted_process_tree.rationale.verdict,
            "severity":    r.predicted_process_tree.rationale.severity,
            "mitre_ids":   r.predicted_process_tree.rationale.mitre_ids,
            "root_process": r.predicted_process_tree.root.process,
        } for r in records],
    }


@router.get("/training/dataset", tags=["training"])
async def download_dataset(
    format: str = Query("jsonl", pattern="^(jsonl|openai|anthropic|csv|edge-list)$"),
    platform: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    user=Depends(get_current_user),
):
    """Stream the seed dataset in the chosen format for LLM fine-tuning."""
    records = all_archetypes()
    if platform:
        records = [r for r in records if r.platform == platform]
    if category:
        records = [r for r in records if r.category == category]

    if format not in FORMATS:
        raise HTTPException(status_code=400, detail=f"unknown format {format}")
    media_type, emitter = FORMATS[format]
    body = emitter(records)
    ext = "csv" if format == "csv" else "jsonl"
    filename = f"nivxray_process_trees_{format}.{ext}"
    return Response(
        content=body,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


class RenderIn(BaseModel):
    tree: Dict[str, Any]
    format: str = Field("ascii", pattern="^(ascii|edge-list|json)$")


@router.post("/training/render", tags=["training"])
async def render_tree(body: RenderIn, user=Depends(get_current_user)) -> Dict[str, Any]:
    """Convert a nested-JSON tree to another representation."""
    try:
        tree = ProcessTree(**body.tree)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"invalid tree JSON: {e}")
    if body.format == "ascii":
        return {"format": "ascii", "content": to_ascii_tree(tree)}
    if body.format == "edge-list":
        return {"format": "edge-list", "content": to_edge_list(tree)}
    return {"format": "json", "content": tree.model_dump()}
