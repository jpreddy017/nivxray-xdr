"""Training corpus Confusion Matrix Dashboard  ·  Feb-2026 v3.

Endpoint
--------
GET  /api/training/confusion
     Query params:
       • refresh=true|false   (default: false — return cached run if <10min old)
       • categories=all|<slug>[,slug…]  (default: all)
       • include_negatives=true|false  (default: true)

Returns a rich per-category confusion matrix computed against the deterministic
corpus:

    {
      "generated_at":    "2026-02-15T…",
      "duration_ms":     8432,
      "samples_total":   245,
      "negatives_total": 10,
      "overall": {
        "tp": 240, "fn": 5, "fp": 0, "tn": 10,
        "precision": 1.0, "recall": 0.9796, "f1": 0.9897, "accuracy": 0.9804
      },
      "categories": [
        {
          "category":       "base64_utf16le",
          "samples":        5,
          "tp": 5, "fn": 0, "precision": 1.0, "recall": 1.0, "f1": 1.0,
          "avg_confidence": 82,
          "engines_used":   {"smart": 5},
          "failures":       []
        },
        …
      ],
      "negatives": {
        "tn": 10, "fp": 0,
        "false_positives": []
      },
      "cache": { "hit": true|false, "age_s": 42 }
    }

Definitions
-----------
• **TP** — `expected_decoded` substring found in decoded output.
• **FN** — decode ran but plaintext missing.
• **FP** — a NEGATIVE sample was transformed into something DIFFERENT from
           the input (i.e. the decoder mis-classified benign text as encoded).
• **TN** — negative sample decoded to itself / no substantive change.

We run the pipeline via the SAME code path the frontend hits (`deterministic_best_decode`),
so the matrix reflects real user experience — not a private "test-only" decoder.

Cache
-----
A single-slot in-memory cache is kept per (categories, include_negatives) key.
Running the whole 245-sample sweep takes ~8s serial (much faster than the
xdist test-suite equivalent because we skip the HTTP round-trip). Explicit
`?refresh=true` bypasses the cache.
"""
from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query

from deps import get_current_user

router = APIRouter()

# ─── Cache ──────────────────────────────────────────────────────────────
_CACHE: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL_S = 600  # 10 min


def _cache_key(cats: Optional[Tuple[str, ...]], include_neg: bool) -> str:
    return f"{'+'.join(cats) if cats else 'all'}::{int(include_neg)}"


# ─── Corpus loader ──────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_CORPUS_JSONL = os.path.abspath(os.path.join(
    _HERE, "..", "training", "corpus", "samples.jsonl"))
_NEGATIVES_JSONL = os.path.abspath(os.path.join(
    _HERE, "..", "training", "corpus", "negative_samples.jsonl"))


def _load_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [json.loads(ln) for ln in f if ln.strip()]


# ─── Decode helper (shared with /api/decode/smart) ──────────────────────
def _run_decode(payload: str) -> Dict[str, Any]:
    """Same deterministic best-decode the smart endpoint runs."""
    from analysis_core import deterministic_best_decode
    return deterministic_best_decode(payload)


# ─── Category-level & overall matrix computation ────────────────────────
def _compute_matrix(
    only_categories: Optional[Tuple[str, ...]] = None,
    include_negatives: bool = True,
) -> Dict[str, Any]:
    started = time.time()
    samples = _load_jsonl(_CORPUS_JSONL)
    negatives = _load_jsonl(_NEGATIVES_JSONL) if include_negatives else []

    # Filter to requested categories (default = all)
    if only_categories:
        wanted = set(only_categories)
        samples = [s for s in samples if s.get("category") in wanted]

    # Per-category accumulator
    per_cat: Dict[str, Dict[str, Any]] = {}
    total_tp = total_fn = 0
    total_conf: List[int] = []

    for s in samples:
        cat = s.get("category") or "uncategorized"
        stat = per_cat.setdefault(cat, {
            "category": cat,
            "samples": 0,
            "tp": 0,
            "fn": 0,
            "confidences": [],
            "engines": {},
            "failures": [],
        })
        stat["samples"] += 1
        try:
            d = _run_decode(s["input"])
        except Exception as e:
            stat["fn"] += 1
            total_fn += 1
            stat["failures"].append({
                "id":       s["id"],
                "expected": s["expected_decoded"][:120],
                "got":      f"decoder-error: {e}",
            })
            continue
        out = d.get("output") or ""
        engine = d.get("engine") or "unknown"
        stat["engines"][engine] = stat["engines"].get(engine, 0) + 1

        # Confidence is the deterministic score * 100 (0..100)
        conf = int(round(min(1.0, d.get("score", 0.0)) * 100))
        stat["confidences"].append(conf)
        total_conf.append(conf)

        expected = s.get("expected_decoded") or ""
        # TP condition: plaintext substring is in decoded output.
        if expected and expected in out:
            stat["tp"] += 1
            total_tp += 1
        else:
            stat["fn"] += 1
            total_fn += 1
            stat["failures"].append({
                "id":       s["id"],
                "expected": expected[:120],
                "got":      out[:200],
                "engine":   engine,
                "confidence": conf,
            })

    # Negatives — a benign input must NOT be aggressively rewritten. We accept
    # (a) identity passthrough (out == input) OR (b) a non-empty output that
    # still CONTAINS the input as a substring — both are "no false alarm"
    # scenarios. Anything else is a false positive.
    neg_stats = {"tn": 0, "fp": 0, "false_positives": []}
    for n in negatives:
        try:
            d = _run_decode(n["input"])
        except Exception as e:
            neg_stats["fp"] += 1
            neg_stats["false_positives"].append({
                "id":   n["id"],
                "input": n["input"][:120],
                "got":   f"decoder-error: {e}",
            })
            continue
        out = d.get("output") or ""
        inp = n["input"]
        if out == inp or (out and inp in out) or not out.strip():
            neg_stats["tn"] += 1
        else:
            neg_stats["fp"] += 1
            neg_stats["false_positives"].append({
                "id":     n["id"],
                "input":  inp[:120],
                "got":    out[:200],
                "engine": d.get("engine") or "unknown",
            })

    # Finalize per-category numbers
    cats_out: List[Dict[str, Any]] = []
    for cat_name in sorted(per_cat.keys()):
        stat = per_cat[cat_name]
        tp, fn = stat["tp"], stat["fn"]
        precision = 1.0 if tp else 0.0    # FP=0 by construction (positive only)
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        avg_conf = int(round(sum(stat["confidences"]) / len(stat["confidences"]))) if stat["confidences"] else 0
        cats_out.append({
            "category":       cat_name,
            "samples":        stat["samples"],
            "tp":             tp,
            "fn":             fn,
            "precision":      round(precision, 4),
            "recall":         round(recall, 4),
            "f1":             round(f1, 4),
            "avg_confidence": avg_conf,
            "engines_used":   stat["engines"],
            "failures":       stat["failures"],
        })

    # Overall aggregates (TP+FN over corpus, TN+FP over negatives)
    tp = total_tp
    fn = total_fn
    fp = neg_stats["fp"]
    tn = neg_stats["tn"]

    total_positives = tp + fn
    overall_recall = tp / total_positives if total_positives else 0.0
    overall_precision = tp / (tp + fp) if (tp + fp) else 0.0
    overall_f1 = (2 * overall_precision * overall_recall / (overall_precision + overall_recall)) \
        if (overall_precision + overall_recall) else 0.0
    overall_accuracy = (tp + tn) / (tp + fn + fp + tn) if (tp + fn + fp + tn) else 0.0

    return {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "duration_ms":     int(round((time.time() - started) * 1000)),
        "samples_total":   len(samples),
        "negatives_total": len(negatives),
        "overall": {
            "tp":        tp,
            "fn":        fn,
            "fp":        fp,
            "tn":        tn,
            "precision": round(overall_precision, 4),
            "recall":    round(overall_recall, 4),
            "f1":        round(overall_f1, 4),
            "accuracy":  round(overall_accuracy, 4),
            "avg_confidence": int(round(sum(total_conf) / len(total_conf))) if total_conf else 0,
        },
        "categories": cats_out,
        "negatives":  neg_stats,
    }


# ─── Endpoint ────────────────────────────────────────────────────────────
@router.get("/training/confusion", tags=["training"])
async def get_confusion_matrix(
    refresh: bool = Query(False, description="Bypass the 10-minute cache."),
    categories: Optional[str] = Query(None, description="Comma-separated category slugs (default: all)."),
    include_negatives: bool = Query(True, description="Include TN/FP over the negatives corpus."),
    user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Compute or return the cached confusion matrix over the training corpus.

    All 245 supervised samples + 10 negatives run through the same
    deterministic best-decode pipeline that powers `/api/decode/smart`. The
    result exposes per-category TP/FN and per-negatives FP/TN plus the
    aggregate precision/recall/F1/accuracy so the analyst can see exactly
    which categories need archetype/decoder reinforcement before the offline
    LLM fine-tune.
    """
    only_cats: Optional[Tuple[str, ...]] = None
    if categories and categories.strip().lower() not in ("all", "*"):
        only_cats = tuple(sorted({c.strip() for c in categories.split(",") if c.strip()}))

    ck = _cache_key(only_cats, include_negatives)
    now = time.time()
    if not refresh:
        cached = _CACHE.get(ck)
        if cached and (now - cached["_ts"]) < _CACHE_TTL_S:
            body = dict(cached["body"])
            body["cache"] = {"hit": True, "age_s": int(round(now - cached["_ts"]))}
            return body

    body = _compute_matrix(only_categories=only_cats, include_negatives=include_negatives)
    _CACHE[ck] = {"_ts": now, "body": body}
    body = dict(body)
    body["cache"] = {"hit": False, "age_s": 0}
    return body


@router.get("/training/confusion/summary", tags=["training"])
async def get_confusion_summary(
    user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Lightweight overview — categories with the WORST recall + fastest cache read.

    Falls back to a fresh compute only if no cache exists.
    """
    ck = _cache_key(None, True)
    cached = _CACHE.get(ck)
    if not cached:
        # Trigger a compute-and-cache pass
        body = _compute_matrix()
        _CACHE[ck] = {"_ts": time.time(), "body": body}
    else:
        body = cached["body"]

    worst = sorted(body["categories"], key=lambda c: (c["recall"], c["f1"]))[:5]
    best = sorted(body["categories"], key=lambda c: -c["recall"])[:5]
    return {
        "generated_at":    body["generated_at"],
        "samples_total":   body["samples_total"],
        "negatives_total": body["negatives_total"],
        "overall":         body["overall"],
        "worst_5_recall":  [{"category": c["category"], "recall": c["recall"],
                             "f1": c["f1"], "fn": c["fn"], "samples": c["samples"]}
                            for c in worst],
        "best_5_recall":   [{"category": c["category"], "recall": c["recall"],
                             "f1": c["f1"], "samples": c["samples"]}
                            for c in best],
    }
