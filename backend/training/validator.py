"""Post-generation validation: verify every citation exists in the decoded payload.

The LLM might still hallucinate despite the system prompt's rules. This module
is the last line of defence — every node whose citation can't be found in
DECODED or RAW gets pruned. IOCs that don't appear are dropped from rationale.
"""
from __future__ import annotations
from typing import Tuple, List

from training.schema import ProcessTree, ProcessNode


def _cite_ok(node: ProcessNode, decoded_lc: str, raw_lc: str) -> bool:
    if node.evidence.inferred and node.evidence.confidence <= 0.7:
        # Inferred nodes are allowed if their citation appears (weaker check)
        cite = (node.evidence.citation or "").strip().lower()
        return bool(cite) and (cite in decoded_lc or cite in raw_lc)

    cite = (node.evidence.citation or "").strip().lower()
    if not cite:
        return False
    return cite in decoded_lc or cite in raw_lc


def _prune(node: ProcessNode, decoded_lc: str, raw_lc: str, dropped: List[str]) -> ProcessNode:
    kept_children: List[ProcessNode] = []
    for c in node.children:
        if _cite_ok(c, decoded_lc, raw_lc):
            kept_children.append(_prune(c, decoded_lc, raw_lc, dropped))
        else:
            dropped.append(f"{c.process} (no citation)")
    node.children = kept_children
    return node


def validate_and_prune(tree: ProcessTree, decoded: str, raw: str = "") -> Tuple[ProcessTree, List[str]]:
    """Returns pruned tree and a list of drop-reasons appended to warnings."""
    decoded_lc = (decoded or "").lower()
    raw_lc = (raw or "").lower()
    warnings: List[str] = []
    dropped: List[str] = []

    # 1. Root must be citable — otherwise flag as insufficient
    if not _cite_ok(tree.root, decoded_lc, raw_lc):
        warnings.append("root citation missing/uncorroborated — evidence_source=insufficient")
        tree.evidence_source = "insufficient"
    else:
        tree.root = _prune(tree.root, decoded_lc, raw_lc, dropped)
        if dropped:
            warnings.append(f"pruned {len(dropped)} uncited node(s): {', '.join(dropped[:5])}"
                            + ("…" if len(dropped) > 5 else ""))

    # 2. Prune IOCs that don't appear in decoded/raw
    for kind, values in list(tree.rationale.iocs.items()):
        kept = [v for v in values
                if isinstance(v, str) and (v.lower() in decoded_lc or v.lower() in raw_lc)]
        if len(kept) < len(values):
            warnings.append(f"dropped {len(values) - len(kept)} uncited {kind} IOC(s)")
        tree.rationale.iocs[kind] = kept

    tree.warnings = list(tree.warnings) + warnings
    return tree, warnings
