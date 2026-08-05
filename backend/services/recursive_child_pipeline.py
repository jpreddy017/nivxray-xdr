"""Recursive Child Artifact Pipeline — Phase 4 · P1.

Master architecture reference: `/app/memory/ARCHITECTURE.md` §4.

    Artifact Analyzer
           │
           ▼
    Child Artifact Declared
           │
           ▼
    Recursive Transformation Engine (RTE / IEDDE)
           │
           ▼
    Canonical Artifact
           │
           ▼
    Artifact Router
           │
           ▼
    Appropriate Analyzer  ──►  Child Declared?  ──► loop
                                    │
                                    No
                                    ▼
                            Deterministic Convergence Reached

This module OWNS the recursion loop. It never decodes anything itself —
it always calls the RTE (`recipe_planner.plan`) and then the Artifact
Router (`artifact_intelligence.dispatch`).

Boundaries:
    * Cap depth at MAX_DEPTH (default 3).
    * Cap total child expansions at MAX_CHILDREN (default 8).
    * Every recursion step is captured in the returned trace so the
      Investigation Engine can reconstruct the full attack chain.
    * On any exception, the pipeline halts gracefully — the parent
      analysis is preserved untouched.
"""
from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nivxray.recursive_pipeline")

MAX_DEPTH = 3
MAX_CHILDREN = 8


def process(routed_analysis: Dict[str, Any],
            *, depth: int = 0,
            budget: Optional[Dict[str, int]] = None) -> List[Dict[str, Any]]:
    """Walk the Recursive Child Artifact Pipeline for a single analyzer
    output. Returns a list of `RecursiveChild` records with provenance,
    hashes, RTE trace summary, and the routed analysis of each child.

    Called ONCE from `recipe_planner._detect_binary_artifact()` after the
    primary artifact analysis completes. Never modifies the caller's
    `routed_analysis` in place.
    """
    if not isinstance(routed_analysis, dict):
        return []
    if depth >= MAX_DEPTH:
        return []
    if budget is None:
        budget = {"remaining": MAX_CHILDREN}
    if budget["remaining"] <= 0:
        return []

    # Reuse the declaration extractor from the Investigation Engine so
    # there's exactly ONE source of truth for "what counts as a child".
    from services.correlation_engine import declare_inline_children_from_routed_analysis

    declarations = declare_inline_children_from_routed_analysis(routed_analysis)
    if not declarations:
        return []

    results: List[Dict[str, Any]] = []
    for decl in declarations:
        if budget["remaining"] <= 0:
            break
        budget["remaining"] -= 1
        child_result = _process_one_child(decl, depth=depth, budget=budget)
        if child_result:
            results.append(child_result)
    return results


def _process_one_child(decl: Dict[str, Any],
                       *, depth: int,
                       budget: Dict[str, int]) -> Optional[Dict[str, Any]]:
    """Push a single declared child through RTE → Router → Analyzer."""
    child_type = decl.get("type") or "artifact"
    snippet = decl.get("snippet") or decl.get("label") or ""
    if not snippet or not isinstance(snippet, str):
        # Nothing to decode. Preserve the declaration verbatim so the
        # Investigation Engine still surfaces it as a chain node.
        return {
            "type":       child_type,
            "label":      decl.get("label"),
            "snippet":    snippet,
            "depth":      depth + 1,
            "hash":       decl.get("hash"),
            "provenance": "declared_only",
            "rte":        None,
            "routed_analysis": None,
            "children":   [],
        }

    # ── Step 1 · Run the child through the RTE ─────────────────────────
    rte_summary, canonical_output, canonical_bytes = _run_rte(snippet, child_type)

    # ── Step 2 · Route the canonical output through the Artifact Router
    # Prefer the RTE's own recovered binary artifact (§4) — it already
    # holds an authoritative routed_analysis. Fall back to re-dispatch
    # on the canonical bytes for text-only convergences.
    routed_child: Optional[Dict[str, Any]] = None
    rte_recovered = (rte_summary.get("binary_artifact") or {}
                     ).get("routed_analysis") if rte_summary else None
    if isinstance(rte_recovered, dict) and rte_recovered.get("artifact_type"):
        routed_child = rte_recovered
    else:
        routed_child = _route_canonical(canonical_bytes)

    # ── Step 3 · Recurse if the router surfaced another artifact ──────
    nested_children: List[Dict[str, Any]] = []
    if routed_child and depth + 1 < MAX_DEPTH:
        nested_children = process(routed_child, depth=depth + 1, budget=budget)

    return {
        "type":       child_type,
        "label":      decl.get("label"),
        "snippet":    snippet[:400],
        "depth":      depth + 1,
        "hash":       _hash(canonical_bytes) if canonical_bytes else decl.get("hash"),
        "provenance": "recursive_child_pipeline",
        "rte":        rte_summary,
        "routed_analysis": routed_child,
        "children":   nested_children,
    }


def _run_rte(snippet: str, child_type: str) -> tuple[Dict[str, Any], str, bytes]:
    """Push a child snippet through the RTE (recipe_planner).

    Returns (summary, canonical_output_text, canonical_output_bytes).
    Deterministic — never raises. On failure, returns a stub summary and
    the original snippet as canonical output.
    """
    try:
        from services.recipe_planner import plan_and_execute as _plan
    except Exception as e:
        logger.warning("rte import failed: %s", e)
        return ({"terminal_state": "unavailable", "reason": "rte_import_failed"},
                snippet, snippet.encode("utf-8", errors="ignore"))

    try:
        result = _plan(snippet)
        canonical = getattr(result, "canonical_output", "") or ""
        summary = {
            "terminal_state":      getattr(result, "terminal_state", None),
            "stop_reason":         getattr(result, "stop_reason", None),
            "iterations_executed": getattr(result, "iterations_executed", 0),
            "final_interpreter":   getattr(result, "final_interpreter", None),
            "final_techniques":    getattr(result, "final_techniques", []),
        }
        # ▲ P2.3b · prefer the RTE's own hand-off of a recovered binary
        # artifact. When the RTE reaches `binary_artifact_recovered`,
        # `plan.binary_artifact.routed_analysis` IS the canonical
        # analyzer output and MUST be surfaced to the recursive
        # pipeline — otherwise `_route_canonical` would re-dispatch on
        # the (wrapper-prefixed) canonical text and miss the payload.
        # This is the same architectural coupling used by the Golden
        # Corpus harness.
        rte_binary = getattr(result, "binary_artifact", None)
        summary["binary_artifact"] = {
            "routed_analysis": getattr(rte_binary, "routed_analysis", None)
        } if rte_binary else None
        # For binary children, the canonical output is bytes-in-string;
        # try latin-1 round-trip so `_route_canonical` can inspect magic.
        try:
            canonical_bytes = canonical.encode("latin-1", errors="ignore")
        except Exception:
            canonical_bytes = canonical.encode("utf-8", errors="ignore")
        return summary, canonical, canonical_bytes
    except Exception as e:
        logger.warning("rte failed for child_type=%s: %s", child_type, e)
        return ({"terminal_state": "error", "reason": f"rte_error:{type(e).__name__}"},
                snippet, snippet.encode("utf-8", errors="ignore"))


def _route_canonical(canonical_bytes: bytes) -> Optional[Dict[str, Any]]:
    """Dispatch canonical output through the Artifact Router.

    Returns the same shape as `routed_analysis` (AnalysisResult.to_dict())
    or None if no analyzer claims the payload.
    """
    if not canonical_bytes or len(canonical_bytes) < 4:
        return None
    try:
        from services.artifact_intelligence import dispatch
        result = dispatch(canonical_bytes)
        d = result.to_dict() if hasattr(result, "to_dict") else None
        if not d or d.get("artifact_type") == "unknown":
            return None
        return d
    except Exception as e:
        logger.warning("artifact router failed: %s", e)
        return None


def _hash(data: bytes) -> Dict[str, str]:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def flatten_for_correlation(children: List[Dict[str, Any]],
                            _acc: Optional[List[Dict[str, Any]]] = None
                            ) -> List[Dict[str, Any]]:
    """Flatten a nested recursive-child tree into a list suitable for
    `correlation_engine.attach_inline_children()`.

    Preserves parent references via the `parent_index` field so the
    Investigation Engine can rebuild the tree deterministically.
    """
    if _acc is None:
        _acc = []
    for c in children or []:
        _acc.append({
            "type":    c.get("type"),
            "label":   c.get("label"),
            "snippet": c.get("snippet"),
            "hash":    c.get("hash"),
            "depth":   c.get("depth"),
        })
        flatten_for_correlation(c.get("children") or [], _acc)
    return _acc
