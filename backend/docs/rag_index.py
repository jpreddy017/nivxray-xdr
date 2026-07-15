"""BM25 sparse retriever over the YAML documentation registry.

Rationale:
    The docs corpus is tiny (~13 docs, ~10 KB total). Loading a dense
    embedding model would be overkill: it'd add hundreds of MB of RAM and
    a cold-start delay for zero quality gain at this scale. BM25 is
    lexically strong, deterministic, has zero external dependencies, and
    returns results in <1 ms. Perfect for the "which other features
    should we surface next to this one?" question.

Public API
    build_index()                                  → (re)build the in-memory index
    retrieve(query, k=3, exclude_ids=None)         → list of {id, kind, title, category, score, snippet}
    invalidate()                                   → force a rebuild on next call

Docs entries are treated as flat text = title + purpose + when_to_use +
tips + supported_formats + related. Workflows are treated similarly
using steps + related_features.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

from rank_bm25 import BM25Okapi

from docs import list_features, list_workflows

# ------------------------------------------------------------------
# Tokeniser — extremely simple. Lowercase, split on non-word, drop
# 1-char tokens. Adequate for a technical corpus at this scale.
# ------------------------------------------------------------------
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


def _tokens(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) > 1]


# ------------------------------------------------------------------
# Document assembly
# ------------------------------------------------------------------
def _feature_text(f: Dict[str, Any]) -> str:
    parts: List[str] = [f.get("title", ""), f.get("purpose", ""),
                        f.get("category", ""), f.get("audience", "")]
    for k in ("when_to_use", "supported_formats", "confidence_rules",
              "common_errors", "tips", "related"):
        vals = f.get(k) or []
        parts.extend(str(v) for v in vals)
    for ex in (f.get("examples") or []):
        parts.append(str(ex.get("input", "")))
        parts.append(str(ex.get("output", "")))
        parts.append(str(ex.get("notes", "")))
    return " \n ".join(p for p in parts if p)


def _workflow_text(w: Dict[str, Any]) -> str:
    parts: List[str] = [w.get("title", ""), w.get("purpose", "")]
    for s in (w.get("steps") or []):
        parts.append(str(s.get("title", "")))
        parts.append(str(s.get("action", "")))
        parts.append(str(s.get("expected", "")))
    parts.extend(str(r) for r in (w.get("related_features") or []))
    return " \n ".join(p for p in parts if p)


def _snippet(text: str, terms: Iterable[str], width: int = 160) -> str:
    """Return a short snippet centred on the earliest matching term."""
    if not text:
        return ""
    low = text.lower()
    best = -1
    for t in terms:
        idx = low.find(t)
        if idx != -1 and (best == -1 or idx < best):
            best = idx
    if best == -1:
        return text[:width].strip() + ("…" if len(text) > width else "")
    start = max(0, best - width // 3)
    end = min(len(text), start + width)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(text) else ""
    return prefix + text[start:end].strip() + suffix


# ------------------------------------------------------------------
# Index state — thread-safe (re)build
# ------------------------------------------------------------------
_lock = threading.Lock()
_bm25: Optional[BM25Okapi] = None
_docs: List[Dict[str, Any]] = []   # each: {id, kind, title, category, text, tokens}


def build_index() -> None:
    """(Re)build the in-memory BM25 index from the YAML registry."""
    global _bm25, _docs
    with _lock:
        docs: List[Dict[str, Any]] = []
        for f in list_features():
            text = _feature_text(f)
            docs.append({
                "id": f.get("id"),
                "kind": "feature",
                "title": f.get("title", f.get("id", "")),
                "category": f.get("category", ""),
                "text": text,
                "tokens": _tokens(text),
            })
        for w in list_workflows():
            text = _workflow_text(w)
            docs.append({
                "id": w.get("id"),
                "kind": "workflow",
                "title": w.get("title", w.get("id", "")),
                "category": "Workflow",
                "text": text,
                "tokens": _tokens(text),
            })
        # BM25Okapi requires at least one non-empty document.
        corpus = [d["tokens"] or ["__empty__"] for d in docs]
        _bm25 = BM25Okapi(corpus) if corpus else None
        _docs = docs


def invalidate() -> None:
    """Drop the cached index; next `retrieve` will rebuild."""
    global _bm25
    with _lock:
        _bm25 = None


def _ensure_ready() -> None:
    if _bm25 is None or not _docs:
        build_index()


def retrieve(
    query: str,
    k: int = 3,
    exclude_ids: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return the top-`k` docs matching `query`.

    Each hit is a dict:
        {id, kind, title, category, score, snippet}

    `exclude_ids` — ids to filter out (e.g. the currently-selected page,
    to force "cross-feature" retrieval).
    """
    if not (query or "").strip():
        return []
    _ensure_ready()
    if _bm25 is None or not _docs:
        return []
    q_tokens = _tokens(query)
    if not q_tokens:
        return []
    scores = _bm25.get_scores(q_tokens)
    exclude = set(exclude_ids or [])
    # Rank by score desc; drop zeros and excluded ids.
    ranked: List[Tuple[float, int]] = sorted(
        ((float(s), i) for i, s in enumerate(scores) if s > 0),
        key=lambda x: x[0], reverse=True,
    )
    out: List[Dict[str, Any]] = []
    for score, idx in ranked:
        doc = _docs[idx]
        if doc["id"] in exclude:
            continue
        out.append({
            "id": doc["id"],
            "kind": doc["kind"],
            "title": doc["title"],
            "category": doc["category"],
            "score": round(score, 3),
            "snippet": _snippet(doc["text"], q_tokens),
        })
        if len(out) >= k:
            break
    return out


def index_stats() -> Dict[str, Any]:
    _ensure_ready()
    return {
        "documents": len(_docs),
        "features": sum(1 for d in _docs if d["kind"] == "feature"),
        "workflows": sum(1 for d in _docs if d["kind"] == "workflow"),
        "ready": _bm25 is not None,
    }
