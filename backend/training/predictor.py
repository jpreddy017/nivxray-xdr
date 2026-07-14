"""LLM-driven process-tree predictor.

Uses the Emergent LLM key + Claude Sonnet 4.5 (via `deps.llm_json`) to convert
a (raw + decoded) payload pair into a validated ProcessTree.

Anti-hallucination stack:
    1. Strict system prompt (`training.system_prompt`)
    2. Schema-typed parse (`training.schema`)
    3. Post-parse citation validator (`training.validator`)
"""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Optional

from fastapi import HTTPException

from deps import llm_json
from training.schema import ProcessTree, ProcessNode, SocRationale, ProcessEvidence
from training.system_prompt import NIVXRAY_PROCESS_TREE_SYSTEM
from training.validator import validate_and_prune


def _insufficient(reason: str) -> ProcessTree:
    return ProcessTree(
        root=ProcessNode(process="(insufficient)", action=reason,
                         evidence=ProcessEvidence(citation="", inferred=True, confidence=0.0)),
        evidence_source="insufficient",
        warnings=[reason],
    )


def _build_node(d: dict) -> ProcessNode:
    if not isinstance(d, dict):
        return ProcessNode(process="(malformed)", action="LLM returned non-dict node")
    d = {k: v for k, v in d.items() if v is not None}
    kids = d.pop("children", []) or []
    ev = d.pop("evidence", None) or {}
    node_kwargs = {
        k: v for k, v in d.items()
        if k in ProcessNode.model_fields and k not in ("children", "evidence")
    }
    node = ProcessNode(
        **node_kwargs,
        evidence=ProcessEvidence(**{k: v for k, v in ev.items() if k in ProcessEvidence.model_fields}),
    )
    node.children = [_build_node(c) for c in kids if isinstance(c, dict)]
    return node


async def predict_process_tree(raw: str, decoded: str,
                               session_id: Optional[str] = None) -> ProcessTree:
    """Predict + validate a process tree for the given raw/decoded pair."""
    if not (decoded or raw):
        return _insufficient("empty input")

    sid = session_id or f"ptp-{datetime.now(timezone.utc).timestamp()}"
    user_prompt = (
        f"RAW_INPUT:\n{(raw or '')[:4000]}\n\n"
        f"DECODED_OUTPUT:\n{(decoded or '')[:6000]}\n\n"
        "Emit strict JSON per the schema. Cite every node."
    )

    try:
        data = await llm_json(sid, NIVXRAY_PROCESS_TREE_SYSTEM, user_prompt, retries=1)
    except HTTPException as e:
        return _insufficient(f"LLM upstream unavailable ({e.detail})")
    except Exception as e:
        return _insufficient(f"LLM error: {e}")

    if not isinstance(data, dict) or "root" not in data:
        return _insufficient("LLM returned malformed JSON")

    try:
        tree = ProcessTree(
            platform=data.get("platform", "windows"),
            root=_build_node(data.get("root") or {}),
            rationale=SocRationale(
                **{k: v for k, v in (data.get("rationale") or {}).items()
                   if k in SocRationale.model_fields}
            ),
            evidence_source=data.get("evidence_source", "decoded"),
            warnings=list(data.get("warnings", [])),
        )
    except Exception as e:
        return _insufficient(f"schema build error: {e}")

    validated, _dropped = validate_and_prune(tree, decoded or "", raw or "")
    return validated
