"""
Corpus loader — the sole interface for reading `corpus.json`.

Purpose
-------
The certification corpus schema is expected to evolve (more categories,
more per-category metadata, per-sample canonical hashes, etc.). To keep
the rest of the framework (runner, validators, convergence tests, CI
gates) completely schema-agnostic, every consumer MUST access the corpus
through :func:`load_samples`.

Design contract (must not be broken)
------------------------------------
* Only this module understands how `corpus.json` is laid out on disk.
* Consumers receive a flat `list[dict]` where every sample carries a
  synthetic ``"category"`` field describing which category it came from.
* The original nested layout is also available via :func:`load_corpus`
  when reporting needs to publish per-category metrics.

If a new category (JavaScript, Python, VBA, ...) is added to the schema,
this loader is the ONLY file that needs to know about it.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

DEFAULT_CORPUS_PATH = Path(__file__).resolve().parent / "corpus.json"


@dataclass(frozen=True)
class CorpusMeta:
    """Top-level metadata about the loaded corpus."""

    version: str
    description: str
    category_names: tuple[str, ...]
    total_samples: int


def _read_corpus_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_corpus(path: Path | str | None = None) -> dict[str, Any]:
    """Return the raw corpus document as it exists on disk.

    Prefer :func:`load_samples` for iteration; use this only when you
    need the category structure for reporting.
    """
    return _read_corpus_file(Path(path) if path else DEFAULT_CORPUS_PATH)


def load_samples(
    path: Path | str | None = None,
    categories: Iterable[str] | None = None,
) -> list[dict[str, Any]]:
    """Return a flat list of samples, each tagged with its ``category``.

    Parameters
    ----------
    path:
        Optional override for the corpus file location.
    categories:
        Optional iterable of category names to include. ``None`` means
        "all categories". Unknown names are ignored (deterministic — no
        exception, so a new category rolling in cannot break existing
        runners).

    The returned dicts are copies; mutating them does not affect the
    on-disk corpus or subsequent calls.
    """
    doc = load_corpus(path)
    wanted: set[str] | None = set(categories) if categories is not None else None

    flat: list[dict[str, Any]] = []
    cats = doc.get("categories") or {}
    for cat_name in sorted(cats.keys()):
        if wanted is not None and cat_name not in wanted:
            continue
        cat_block = cats[cat_name] or {}
        for sample in cat_block.get("samples", []) or []:
            enriched = dict(sample)
            enriched["category"] = cat_name
            flat.append(enriched)
    return flat


def load_meta(path: Path | str | None = None) -> CorpusMeta:
    doc = load_corpus(path)
    cats = doc.get("categories") or {}
    total = sum(len((cats.get(k) or {}).get("samples", []) or []) for k in cats)
    return CorpusMeta(
        version=str(doc.get("corpus_version", "unknown")),
        description=str(doc.get("description", "")),
        category_names=tuple(sorted(cats.keys())),
        total_samples=total,
    )


def group_by_category(samples: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Regroup a flat sample list back into a category → samples map."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    for s in samples:
        grouped.setdefault(s.get("category", "uncategorized"), []).append(s)
    return grouped


def category_stats(
    results_by_id: dict[str, bool],
    path: Path | str | None = None,
) -> dict[str, dict[str, int]]:
    """Compute per-category pass/total counts from a {sample_id: passed} map.

    Returns a dict shaped like::

        {
          "powershell": {"passed": 7, "total": 7},
          "cmd":        {"passed": 1, "total": 1},
          ...
          "__overall__": {"passed": 13, "total": 13},
        }
    """
    samples = load_samples(path)
    stats: dict[str, dict[str, int]] = {}
    for s in samples:
        cat = s.get("category", "uncategorized")
        bucket = stats.setdefault(cat, {"passed": 0, "total": 0})
        bucket["total"] += 1
        if results_by_id.get(s["id"], False):
            bucket["passed"] += 1
    overall = {"passed": sum(b["passed"] for b in stats.values()),
               "total": sum(b["total"] for b in stats.values())}
    stats["__overall__"] = overall
    return stats


def format_category_stats(stats: dict[str, dict[str, int]]) -> str:
    """Human-readable one-block summary for CLI / markdown reports."""
    lines: list[str] = []
    for cat, counts in stats.items():
        if cat == "__overall__":
            continue
        lines.append(f"  {cat:<12} {counts['passed']}/{counts['total']}")
    overall = stats.get("__overall__", {"passed": 0, "total": 0})
    lines.append(f"  {'Overall':<12} {overall['passed']}/{overall['total']}")
    return "\n".join(lines)


__all__ = [
    "CorpusMeta",
    "DEFAULT_CORPUS_PATH",
    "category_stats",
    "format_category_stats",
    "group_by_category",
    "load_corpus",
    "load_meta",
    "load_samples",
]
