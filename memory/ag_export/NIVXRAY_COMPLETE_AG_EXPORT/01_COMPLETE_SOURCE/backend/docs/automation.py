"""Documentation Automation — Feb-2026 Phase 6.

Provides three closed-loop primitives that reduce the manual work of
keeping the YAML docs registry in sync with the codebase:

    coverage_report(app)                 -> which /api/* routes have no
                                             matching feature YAML
    scaffold_yaml(route_path, method)    -> AI-drafted starter YAML for
                                             an undocumented route
    suggest_fix(page_id)                 -> AI-drafted revised YAML that
                                             addresses the recent 👎
                                             feedback for a docs page

All AI paths gracefully degrade to a deterministic template fallback so
the endpoints stay useful without an LLM budget.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from docs import (
    get_feature,
    get_workflow,
    list_features,
)

_DOCS_ROOT = Path(__file__).parent
_FEATURES_DIR = _DOCS_ROOT / "features"


# ---------------------------------------------------------------------
# Coverage — walk the live FastAPI app and cross-reference feature YAMLs
# ---------------------------------------------------------------------
_STANDARD_TAGS_TO_IGNORE = {"health", "internal"}


def walk_routes(app) -> List[Dict[str, Any]]:
    """Return a normalised list of every `/api/*` route on the app."""
    out: List[Dict[str, Any]] = []
    for route in getattr(app, "routes", []):
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        endpoint = getattr(route, "endpoint", None)
        if not path or not methods:
            continue
        if not path.startswith("/api/"):
            continue
        # FastAPI adds HEAD automatically alongside GET — drop it.
        methods = sorted(m for m in methods if m not in {"HEAD", "OPTIONS"})
        if not methods:
            continue
        for method in methods:
            out.append({
                "path": path,
                "method": method,
                "name": (endpoint.__name__ if endpoint else "?"),
                "module": (endpoint.__module__ if endpoint else "?"),
                "tags": list(getattr(route, "tags", None) or []),
                "summary": getattr(route, "summary", None),
                "docstring": (endpoint.__doc__ or "").strip() if endpoint else "",
            })
    # Deduplicate identical (path, method) pairs — some middlewares register twice.
    seen: set = set()
    dedup: List[Dict[str, Any]] = []
    for r in out:
        key = (r["path"], r["method"])
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)
    return dedup


def _feature_index() -> Dict[str, Dict[str, Any]]:
    """Build a lookup table used to match routes to features."""
    idx: Dict[str, Dict[str, Any]] = {}
    for f in list_features():
        fid = f.get("id") or ""
        if not fid:
            continue
        idx[fid.lower()] = f
    return idx


def _route_covered(route: Dict[str, Any],
                    feature_idx: Dict[str, Dict[str, Any]]) -> Optional[str]:
    """Return the id of the covering feature, or None if uncovered.

    Matching strategy (best-effort, biased toward false-negatives):
    - Any explicit route tag whose lowercase form matches a feature id.
    - Consecutive path tokens joined by '_' that equal a feature id.
    - Any single path token that matches ANY '_'-separated component
      of a feature id (e.g. token `taxii` → feature `taxii_push`).
    """
    for tag in route.get("tags") or []:
        if tag and tag.lower() in feature_idx:
            return feature_idx[tag.lower()]["id"]

    tokens = [t for t in route["path"].strip("/").split("/") if t and not t.startswith("{")]
    if tokens and tokens[0] == "api":
        tokens = tokens[1:]

    # Exact multi-token match: `taxii/push` → `taxii_push`.
    for size in (3, 2, 1):
        for i in range(0, max(0, len(tokens) - size + 1)):
            candidate = "_".join(tokens[i:i + size]).lower()
            if candidate in feature_idx:
                return feature_idx[candidate]["id"]

    # Loose token match: any URL token matches any component of a feature id.
    # Ignores 1- and 2-letter tokens so noise like `id`, `v1` doesn't match.
    for t in tokens:
        if len(t) <= 2:
            continue
        needle = t.lower()
        for fid in feature_idx:
            components = fid.split("_")
            if needle in components:
                return feature_idx[fid]["id"]
    return None


def coverage_report(app) -> Dict[str, Any]:
    """Compute a coverage report for the given FastAPI app."""
    routes = walk_routes(app)
    feature_idx = _feature_index()

    covered: List[Dict[str, Any]] = []
    undocumented: List[Dict[str, Any]] = []
    for r in routes:
        fid = _route_covered(r, feature_idx)
        if fid:
            covered.append({**r, "feature_id": fid})
        else:
            undocumented.append(r)

    total = len(routes)
    return {
        "total_routes": total,
        "documented_routes": len(covered),
        "undocumented_routes": len(undocumented),
        "coverage_pct": round(100.0 * len(covered) / total, 1) if total else 0.0,
        "documented_features": len(feature_idx),
        "undocumented": undocumented,
        "sample_covered": covered[:5],
    }


# ---------------------------------------------------------------------
# LLM helpers — Claude via Emergent LLM key, with a template fallback
# ---------------------------------------------------------------------
async def _try_claude(system: str, prompt: str, *,
                       max_tokens: int = 900,
                       session_id: str = "docs-automation") -> Optional[str]:
    key = os.environ.get("EMERGENT_LLM_KEY", "")
    if not key:
        return None
    try:
        from emergentintegrations.llm.chat import LlmChat, UserMessage
        chat = (
            LlmChat(api_key=key, session_id=session_id, system_message=system)
            .with_model("anthropic", "claude-sonnet-4-5-20250929")
            .with_params(max_tokens=max_tokens)
        )
        reply = await chat.send_message(UserMessage(text=prompt))
        return (reply or "").strip() or None
    except Exception:
        return None


_YAML_FENCE_RE = re.compile(r"```(?:ya?ml)?\s*\n?(.*?)```", re.DOTALL)


def _strip_code_fence(text: str) -> str:
    m = _YAML_FENCE_RE.search(text or "")
    if m:
        return m.group(1).strip()
    return (text or "").strip()


def _validate_yaml(text: str) -> Optional[Dict[str, Any]]:
    """Return the parsed YAML dict if it's a well-formed feature/workflow doc."""
    try:
        data = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if not data.get("id") or not data.get("title"):
        return None
    return data


# ---------------------------------------------------------------------
# 1) suggest_fix — turn 👎 events on a page into a revised YAML draft
# ---------------------------------------------------------------------
async def suggest_fix(
    page_id: str,
    negative_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Draft a revised YAML for `page_id` that addresses recent 👎 feedback."""
    doc = get_feature(page_id)
    kind = "feature"
    if not doc:
        doc = get_workflow(page_id)
        kind = "workflow" if doc else None
    if not doc:
        return {
            "provider": "none",
            "page": page_id,
            "error": "no feature or workflow with that id",
        }

    current_yaml = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)

    # Compact the 👎 events into an evidence block.
    evidence_lines: List[str] = []
    for i, ev in enumerate(negative_events[:10], 1):
        q = (ev.get("question") or "").strip()
        snip = (ev.get("reply_snippet") or "").strip()
        comment = (ev.get("comment") or "").strip()
        parts = []
        if q:
            parts.append(f"analyst_question={q!r}")
        if snip:
            parts.append(f"our_reply_snippet={snip[:200]!r}")
        if comment:
            parts.append(f"analyst_comment={comment!r}")
        if parts:
            evidence_lines.append(f"[{i}] " + " · ".join(parts))
    evidence = "\n".join(evidence_lines) or "(no analyst evidence yet)"

    system = (
        "You are a senior technical writer for NivXRay's docs.\n"
        "You are handed one feature/workflow YAML plus a list of thumbs-down\n"
        "analyst-feedback events. Produce a REVISED YAML that keeps the same\n"
        "id and structural shape, but fixes wording, adds missing bullets,\n"
        "clarifies confidence rules, or plugs whichever gap the 👎 events\n"
        "highlight. NEVER invent features that don't already exist. Keep the\n"
        "same top-level keys (id, title, category, audience, purpose,\n"
        "when_to_use, supported_formats, confidence_rules, examples,\n"
        "common_errors, tips, related — or steps/related_features for a\n"
        "workflow). Output ONLY the raw YAML in a fenced ```yaml block."
    )
    prompt = (
        f"kind: {kind}\n\n"
        f"CURRENT YAML:\n```yaml\n{current_yaml}```\n\n"
        f"THUMBS-DOWN EVIDENCE:\n{evidence}\n"
    )
    llm_text = await _try_claude(system, prompt, session_id=f"docs-fix-{page_id}")

    if llm_text:
        cleaned = _strip_code_fence(llm_text)
        parsed = _validate_yaml(cleaned)
        if parsed:
            return {
                "provider": "emergent-claude",
                "page": page_id,
                "kind": kind,
                "current_yaml": current_yaml,
                "revised_yaml": cleaned,
                "notes": (
                    f"Draft built from {len(negative_events)} 👎 events. "
                    "Review the diff, then paste into "
                    f"`backend/docs/features/{page_id}.yaml`."
                ),
            }

    # Template fallback — mechanical patch: append complaints as a
    # "Common errors" note so nothing gets lost.
    doc_copy = dict(doc)
    complaints = [
        (ev.get("question") or ev.get("comment") or "").strip()
        for ev in negative_events
        if (ev.get("question") or ev.get("comment"))
    ]
    if complaints:
        existing = list(doc_copy.get("common_errors") or [])
        for c in complaints[:5]:
            marker = f"[from 👎] {c}"
            if marker not in existing:
                existing.append(marker)
        doc_copy["common_errors"] = existing
    revised = yaml.safe_dump(doc_copy, sort_keys=False, allow_unicode=True)
    return {
        "provider": "template-fallback",
        "page": page_id,
        "kind": kind,
        "current_yaml": current_yaml,
        "revised_yaml": revised,
        "notes": (
            "LLM unavailable — appended the analyst complaints under "
            "`common_errors` as a placeholder. Manual editing recommended."
        ),
    }


# ---------------------------------------------------------------------
# 2) scaffold_yaml — starter YAML for an undocumented route
# ---------------------------------------------------------------------
def _guess_id_from_path(path: str, method: str) -> str:
    tokens = [t for t in path.strip("/").split("/") if t and not t.startswith("{")]
    if tokens and tokens[0] == "api":
        tokens = tokens[1:]
    base = "_".join(tokens) or "unnamed_route"
    if method.upper() != "GET":
        base = f"{base}_{method.lower()}"
    return re.sub(r"[^a-z0-9_]+", "_", base.lower()).strip("_")


def _default_scaffold(route: Dict[str, Any]) -> Dict[str, Any]:
    fid = _guess_id_from_path(route["path"], route["method"])
    doc_lines = (route.get("docstring") or "").splitlines()
    first_line = doc_lines[0].strip() if doc_lines else ""
    purpose = first_line[:200] if first_line else f"{route['method']} {route['path']} — TODO"
    return {
        "id": fid,
        "title": route.get("summary") or fid.replace("_", " ").title(),
        "category": "Uncategorised",
        "audience": "developer",
        "purpose": purpose,
        "when_to_use": ["TODO"],
        "supported_formats": [],
        "confidence_rules": [],
        "examples": [],
        "common_errors": [],
        "tips": [],
        "related": [],
    }


async def scaffold_yaml(route: Dict[str, Any]) -> Dict[str, Any]:
    """AI-draft a starter YAML for an undocumented route."""
    starter = _default_scaffold(route)
    starter_yaml = yaml.safe_dump(starter, sort_keys=False, allow_unicode=True)

    system = (
        "You are a senior technical writer for NivXRay's docs.\n"
        "You are shown one FastAPI route (method + path + handler name +\n"
        "docstring). Produce a starter feature YAML with the following top-\n"
        "level keys, all present even if some are empty lists: id, title,\n"
        "category, audience, purpose, when_to_use, supported_formats,\n"
        "confidence_rules, examples, common_errors, tips, related.\n"
        "Use the docstring verbatim if it's informative. Keep the id from\n"
        "the starter unchanged. Output ONLY YAML in a fenced ```yaml block."
    )
    prompt = (
        f"Route: {route['method']} {route['path']}\n"
        f"Handler: {route.get('name')}   (module: {route.get('module')})\n"
        f"Tags: {route.get('tags') or []}\n"
        f"Docstring:\n{route.get('docstring') or '(none)'}\n\n"
        f"STARTER YAML (extend this):\n```yaml\n{starter_yaml}```"
    )
    llm_text = await _try_claude(system, prompt,
                                  session_id=f"docs-scaffold-{starter['id']}")
    if llm_text:
        cleaned = _strip_code_fence(llm_text)
        parsed = _validate_yaml(cleaned)
        if parsed and parsed.get("id") == starter["id"]:
            return {
                "provider": "emergent-claude",
                "route": route,
                "starter_yaml": starter_yaml,
                "drafted_yaml": cleaned,
                "notes": (
                    "Draft ready — review and save to "
                    f"`backend/docs/features/{starter['id']}.yaml`."
                ),
            }
    return {
        "provider": "template-fallback",
        "route": route,
        "starter_yaml": starter_yaml,
        "drafted_yaml": starter_yaml,
        "notes": (
            "LLM unavailable — returned a mechanical starter. Fill in "
            "when_to_use, examples, and category before saving."
        ),
    }
