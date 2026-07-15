"""NivXRay Fine-Tuning Dataset Export (Feb-2026 roadmap #8).

Exports the regression corpus and analyst-correction learning events as
JSONL suitable for fine-tuning a local Qwen/Ollama model. Two output
formats are supported:

    * `chatml`  — {"messages":[{"role":"system"|"user"|"assistant", "content":...}]}
                  (works with LLaMA-Factory, Axolotl, Ollama, most trainers)
    * `alpaca`  — {"instruction":..., "input":..., "output":...}
                  (works with older Stanford Alpaca-style trainers)

Sources
    * `regression_corpus`  — canonical (input → expected_output) pairs
    * `learning_events`    — analyst corrections (input → corrected_output)

Both are labelled with a `source` field in the output so callers can
filter or weight during training.
"""
from __future__ import annotations

import json
from typing import Any, AsyncIterator, Dict, List, Optional


SYSTEM_PROMPT = (
    "You are NivXRay, a CyberChef-style decoder. Given an obfuscated payload, "
    "reply with a JSON object exactly like "
    '{"decoded":"<plaintext>","chain":["op1","op2",...]}. '
    "Do not include any other text, markdown, or explanations."
)


def _extract_ops(chain: Optional[List[Dict[str, Any]]]) -> List[str]:
    if not chain:
        return []
    return [s.get("op") or "" for s in chain if isinstance(s, dict) and s.get("op")]


def _example_chatml(input_text: str, decoded: str, chain: List[str],
                     source: str) -> Dict[str, Any]:
    assistant = json.dumps(
        {"decoded": decoded, "chain": chain}, ensure_ascii=False,
    )
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": input_text},
            {"role": "assistant", "content": assistant},
        ],
        "source": source,
    }


def _example_alpaca(input_text: str, decoded: str, chain: List[str],
                     source: str) -> Dict[str, Any]:
    return {
        "instruction": SYSTEM_PROMPT,
        "input": input_text,
        "output": json.dumps({"decoded": decoded, "chain": chain},
                              ensure_ascii=False),
        "source": source,
    }


def format_example(input_text: str, decoded: str, chain: List[str],
                    source: str, fmt: str) -> Dict[str, Any]:
    if fmt == "alpaca":
        return _example_alpaca(input_text, decoded, chain, source)
    return _example_chatml(input_text, decoded, chain, source)


async def stream_dataset(
    db, *,
    include_corpus: bool = True,
    include_corrections: bool = True,
    fmt: str = "chatml",
    limit: int = 10_000,
) -> AsyncIterator[str]:
    """Yield JSONL lines (one per example, newline-terminated).

    Iterates the two source collections and produces training examples
    in the requested format. Silently skips corrupt / missing rows.
    """
    count = 0
    if include_corpus:
        cursor = db["regression_corpus"].find({}).sort("created_at", -1).limit(limit)
        async for doc in cursor:
            try:
                inp = doc.get("input") or ""
                out = doc.get("expected_output") or ""
                if not inp or not out:
                    continue
                ex = format_example(
                    inp, out, _extract_ops(doc.get("expected_chain")),
                    source=f"corpus:{doc.get('source') or 'direct'}",
                    fmt=fmt,
                )
                yield json.dumps(ex, ensure_ascii=False) + "\n"
                count += 1
                if count >= limit:
                    return
            except Exception:
                continue

    if include_corrections and count < limit:
        remaining = limit - count
        cursor = db["learning_events"].find({}).sort("created_at", -1).limit(remaining)
        async for doc in cursor:
            try:
                inp = doc.get("input_snippet") or ""
                corrected = doc.get("corrected_output") or ""
                if not inp or not corrected:
                    continue
                chain = _extract_ops(doc.get("corrected_chain"))
                ex = format_example(
                    inp, corrected, chain,
                    source="correction:analyst",
                    fmt=fmt,
                )
                yield json.dumps(ex, ensure_ascii=False) + "\n"
                count += 1
                if count >= limit:
                    return
            except Exception:
                continue


async def dataset_stats(db) -> Dict[str, Any]:
    """Return counts for the two source collections."""
    corpus = await db["regression_corpus"].count_documents({})
    corrections = await db["learning_events"].count_documents({
        "corrected_output": {"$nin": ["", None]},
    })
    corpus_by_source: List[Dict[str, Any]] = []
    async for row in db["regression_corpus"].aggregate([
        {"$group": {"_id": "$source", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]):
        corpus_by_source.append({"source": row["_id"], "count": row["count"]})
    return {
        "regression_corpus": corpus,
        "learning_events_with_correction": corrections,
        "total_available": corpus + corrections,
        "corpus_by_source": corpus_by_source,
    }
