"""Fine-tuning dataset export router — /api/admin/finetune/*.

Feb-2026 roadmap #8 — generates a JSONL corpus suitable for offline
fine-tuning of a small local model (Qwen/Llama/Mistral) on the NivXRay
decoder task.

Sources merged into the dataset:
    1. `regression_corpus` — versioned analyst-verified samples
    2. `sample_library`    — curated benign+malicious payloads
    3. `learning_events`   — analyst corrections (engine got it wrong)

Output schema (per line, JSONL):
    {
        "id": "rc-<mongo id>" | "sl-<name>" | "le-<id>",
        "source": "regression_corpus" | "sample_library" | "learning_events",
        "instruction": "Decode the following obfuscated input.",
        "input": "<raw obfuscated payload>",
        "expected_output": "<correct decoded plaintext>",
        "expected_chain": [{"op": ...}, ...],
        "notes": "<analyst commentary>",
        "created_at": "<ISO>",
    }

Endpoints
    GET /api/admin/finetune/dataset.jsonl        streamed download
    GET /api/admin/finetune/dataset/summary      counts + preview (json)
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from deps import db, require_admin


router = APIRouter()


def _line(obj: Dict[str, Any]) -> bytes:
    return (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")


async def _iter_regression_corpus() -> AsyncIterator[Dict[str, Any]]:
    async for doc in db["regression_corpus"].find({}):
        yield {
            "id": f"rc-{doc['_id']}",
            "source": "regression_corpus",
            "instruction": "Decode the following obfuscated input.",
            "input": doc.get("input", ""),
            "expected_output": doc.get("expected_output", ""),
            "expected_chain": doc.get("expected_chain", []),
            "notes": doc.get("notes"),
            "created_at": doc.get("created_at"),
        }


async def _iter_sample_library() -> AsyncIterator[Dict[str, Any]]:
    async for doc in db["sample_library"].find({}):
        expected = doc.get("expected_output") or doc.get("decoded") or ""
        if not expected:
            continue
        name = doc.get("name") or str(doc.get("_id"))
        yield {
            "id": f"sl-{name}",
            "source": "sample_library",
            "instruction": "Decode the following obfuscated input.",
            "input": doc.get("raw_input") or doc.get("input") or "",
            "expected_output": expected,
            "expected_chain": doc.get("chain") or doc.get("expected_chain") or [],
            "notes": doc.get("notes"),
            "created_at": doc.get("created_at"),
        }


async def _iter_learning_events() -> AsyncIterator[Dict[str, Any]]:
    async for doc in db["learning_events"].find({}):
        expected = doc.get("corrected_output") or ""
        if not expected:
            continue
        yield {
            "id": f"le-{doc['_id']}",
            "source": "learning_events",
            "instruction": "Decode the following obfuscated input.",
            "input": doc.get("input_snippet", ""),
            "expected_output": expected,
            "expected_chain": doc.get("corrected_chain") or [],
            "notes": doc.get("notes"),
            "created_at": doc.get("created_at"),
        }


async def _stream_jsonl(dedupe: bool = True):
    """Async generator yielding JSONL bytes."""
    seen_inputs = set()
    async def emit_row(row: Dict[str, Any]):
        inp = row.get("input") or ""
        if not inp:
            return
        if dedupe:
            if inp in seen_inputs:
                return
            seen_inputs.add(inp)
        yield _line(row)

    async for row in _iter_regression_corpus():
        async for chunk in emit_row(row): yield chunk
    async for row in _iter_sample_library():
        async for chunk in emit_row(row): yield chunk
    async for row in _iter_learning_events():
        async for chunk in emit_row(row): yield chunk


@router.get("/admin/finetune/dataset.jsonl", tags=["finetune"])
async def download_dataset(user=Depends(require_admin)):
    """Stream the merged fine-tuning dataset as JSONL."""
    return StreamingResponse(
        _stream_jsonl(),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": 'attachment; filename="nivxray_finetune.jsonl"',
        },
    )


@router.get("/admin/finetune/dataset/summary", tags=["finetune"])
async def summary(user=Depends(require_admin)):
    """Counts + a 3-row preview from each source."""
    counts = {
        "regression_corpus": await db["regression_corpus"].count_documents({}),
        "sample_library": await db["sample_library"].count_documents({}),
        "learning_events": await db["learning_events"].count_documents({}),
    }

    async def _first_n(iterator, n=3):
        out: List[Dict[str, Any]] = []
        async for row in iterator:
            out.append({
                "id": row["id"],
                "source": row["source"],
                "input_preview": (row.get("input") or "")[:80],
                "expected_output_preview": (row.get("expected_output") or "")[:80],
                "chain": [s.get("op") for s in (row.get("expected_chain") or [])],
            })
            if len(out) >= n:
                break
        return out

    preview = {
        "regression_corpus": await _first_n(_iter_regression_corpus()),
        "sample_library": await _first_n(_iter_sample_library()),
        "learning_events": await _first_n(_iter_learning_events()),
    }
    total = sum(counts.values())
    return {
        "counts": counts,
        "total_before_dedupe": total,
        "preview": preview,
        "schema": {
            "id": "string",
            "source": "regression_corpus | sample_library | learning_events",
            "instruction": "string",
            "input": "string",
            "expected_output": "string",
            "expected_chain": "[{op: string, args?: object}]",
            "notes": "string | null",
            "created_at": "ISO-8601",
        },
    }



# ─────────────────────────────────────────────────────────────
# Feb-2026 #8 — ChatML/Alpaca formatted export + Ollama tiebreaker
# ─────────────────────────────────────────────────────────────
from fastapi import Query
from finetune import stream_dataset, dataset_stats


@router.get("/admin/finetune/stats", tags=["finetune"])
async def finetune_stats(user=Depends(require_admin)):
    """Counts by source collection — sanity check before exporting."""
    return await dataset_stats(db)


@router.get("/admin/finetune/dataset", tags=["finetune"])
async def finetune_formatted_dataset(
    fmt: str = Query("chatml", pattern="^(chatml|alpaca)$"),
    include_corpus: bool = True,
    include_corrections: bool = True,
    limit: int = Query(10_000, ge=1, le=100_000),
    user=Depends(require_admin),
):
    """Stream a fine-tuning-ready dataset as JSONL in the analyst's chosen
    format (default ChatML — the format LLaMA-Factory, Axolotl, and Ollama
    all consume natively).

    curl -H "Authorization: Bearer <tok>" \\
         "$API/api/admin/finetune/dataset?fmt=chatml&limit=5000" \\
         > nivxray-train.jsonl
    """
    filename = f"nivxray-{fmt}.jsonl"
    return StreamingResponse(
        stream_dataset(
            db,
            include_corpus=include_corpus,
            include_corrections=include_corrections,
            fmt=fmt,
            limit=limit,
        ),
        media_type="application/jsonl",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/admin/finetune/test-offline-llm", tags=["finetune"])
async def finetune_test_offline_llm(user=Depends(require_admin)):
    """Ping the configured local Ollama endpoint to verify reachability
    of the offline LLM tiebreaker.
    """
    from reasoning.llm_tiebreaker import test_offline_llm as _test
    return await _test()
