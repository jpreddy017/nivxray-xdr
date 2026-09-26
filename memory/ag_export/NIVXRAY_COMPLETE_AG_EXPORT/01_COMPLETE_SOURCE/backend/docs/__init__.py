"""NivXRay Documentation Registry (Feb-2026 roadmap Phase 1).

Loads structured feature + workflow metadata from `docs/features/*.yaml`
and `docs/workflows/*.yaml`, generates task-oriented Markdown guides, and
serves them via /api/docs/*. Uses only PyYAML (already in requirements).

Data model
----------

Feature YAML (`docs/features/<id>.yaml`):
    id, title, category, purpose, when_to_use[], supported_formats[],
    examples[{input, output, notes}], common_errors[], tips[],
    confidence_rules[], screenshots[], related[], audience: user|admin|developer

Workflow YAML (`docs/workflows/<id>.yaml`):
    id, title, purpose, steps[{title, action, expected}], related_features[]
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


ROOT = Path(__file__).parent
FEATURES_DIR = ROOT / "features"
WORKFLOWS_DIR = ROOT / "workflows"


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return None
        return data
    except Exception:
        return None


def list_features(audience: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all features, optionally filtered by target audience."""
    if not FEATURES_DIR.exists():
        return []
    features: List[Dict[str, Any]] = []
    for f in sorted(FEATURES_DIR.glob("*.yaml")):
        data = _load_yaml(f)
        if not data:
            continue
        if audience and data.get("audience") and data.get("audience") != audience:
            continue
        features.append(data)
    return features


def get_feature(feature_id: str) -> Optional[Dict[str, Any]]:
    path = FEATURES_DIR / f"{feature_id}.yaml"
    if not path.exists():
        return None
    return _load_yaml(path)


def list_workflows() -> List[Dict[str, Any]]:
    if not WORKFLOWS_DIR.exists():
        return []
    items: List[Dict[str, Any]] = []
    for f in sorted(WORKFLOWS_DIR.glob("*.yaml")):
        data = _load_yaml(f)
        if data:
            items.append(data)
    return items


def get_workflow(workflow_id: str) -> Optional[Dict[str, Any]]:
    path = WORKFLOWS_DIR / f"{workflow_id}.yaml"
    return _load_yaml(path) if path.exists() else None


def search(q: str) -> Dict[str, Any]:
    """Case-insensitive substring search across features + workflows."""
    q = (q or "").strip().lower()
    if not q:
        return {"features": [], "workflows": []}
    feats = []
    for f in list_features():
        hay = " ".join([
            f.get("id", ""), f.get("title", ""), f.get("purpose", ""),
            " ".join(f.get("when_to_use") or []),
            " ".join(f.get("tips") or []),
            " ".join(f.get("supported_formats") or []),
        ]).lower()
        if q in hay:
            feats.append({"id": f.get("id"), "title": f.get("title"),
                          "category": f.get("category")})
    wfs = []
    for w in list_workflows():
        hay = " ".join([
            w.get("id", ""), w.get("title", ""), w.get("purpose", ""),
        ]).lower()
        if q in hay:
            wfs.append({"id": w.get("id"), "title": w.get("title")})
    return {"features": feats, "workflows": wfs}


# --------------------------------------------------------------
# Markdown generation
# --------------------------------------------------------------
def _fmt_bullets(items: Optional[List[str]]) -> str:
    if not items:
        return "_(none)_\n"
    return "\n".join(f"- {i}" for i in items) + "\n"


def _render_feature_md(f: Dict[str, Any]) -> str:
    parts = [f"### {f.get('title', '?')}\n",
             f"**id**: `{f.get('id', '?')}` · "
             f"**category**: {f.get('category', '?')} · "
             f"**audience**: {f.get('audience', 'user')}\n"]
    if f.get("purpose"):
        parts.append(f"\n**Purpose** — {f['purpose']}\n")
    if f.get("when_to_use"):
        parts.append("\n**When to use**\n" + _fmt_bullets(f["when_to_use"]))
    if f.get("supported_formats"):
        parts.append("\n**Supported formats**\n" + _fmt_bullets(f["supported_formats"]))
    if f.get("confidence_rules"):
        parts.append("\n**Confidence rules**\n" + _fmt_bullets(f["confidence_rules"]))
    if f.get("examples"):
        parts.append("\n**Examples**\n")
        for ex in f["examples"]:
            parts.append(f"- **Input**: `{ex.get('input', '')}`  \n"
                         f"  **Output**: `{ex.get('output', '')}`"
                         + (f"  \n  _{ex['notes']}_" if ex.get('notes') else "") + "\n")
    if f.get("common_errors"):
        parts.append("\n**Common errors**\n" + _fmt_bullets(f["common_errors"]))
    if f.get("tips"):
        parts.append("\n**Tips**\n" + _fmt_bullets(f["tips"]))
    if f.get("related"):
        parts.append("\n**Related** — " + ", ".join(
            f"`{r}`" for r in f["related"]) + "\n")
    return "".join(parts) + "\n---\n\n"


def _render_workflow_md(w: Dict[str, Any]) -> str:
    parts = [f"### {w.get('title', '?')}\n",
             f"_{w.get('purpose', '')}_\n\n"]
    for i, step in enumerate(w.get("steps") or [], 1):
        parts.append(f"**Step {i} — {step.get('title', '')}**\n")
        if step.get("action"):
            parts.append(f"- Action: {step['action']}\n")
        if step.get("expected"):
            parts.append(f"- Expected: {step['expected']}\n")
        parts.append("\n")
    if w.get("related_features"):
        parts.append("**Related features** — " +
                     ", ".join(f"`{r}`" for r in w["related_features"]) + "\n")
    return "".join(parts) + "\n---\n\n"


def generate_guide(audience: str = "user") -> str:
    """Auto-generate a full Markdown guide for the given audience."""
    feats = list_features(audience=audience if audience != "all" else None)
    wfs = list_workflows()

    # Group features by category
    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for f in feats:
        by_cat.setdefault(f.get("category") or "Uncategorised", []).append(f)

    md: List[str] = [f"# NivXRay — {audience.title()} Guide\n\n",
                     "> Auto-generated from `docs/features/` and `docs/workflows/`. "
                     "See individual YAML files to edit.\n\n"]

    if wfs:
        md.append("## Task-Oriented Workflows\n\n")
        md.append(
            "Real analyst workflows — start here. Each workflow chains the "
            "features below into an investigation.\n\n"
        )
        for w in wfs:
            md.append(_render_workflow_md(w))

    md.append("## Features by Category\n\n")
    for cat in sorted(by_cat.keys()):
        md.append(f"## {cat}\n\n")
        for f in by_cat[cat]:
            md.append(_render_feature_md(f))

    return "".join(md)


def guide_stats() -> Dict[str, Any]:
    feats = list_features()
    wfs = list_workflows()
    categories = sorted({(f.get("category") or "Uncategorised") for f in feats})
    return {
        "features": len(feats),
        "workflows": len(wfs),
        "categories": categories,
    }
