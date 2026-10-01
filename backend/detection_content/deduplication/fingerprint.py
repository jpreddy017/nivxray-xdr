"""
NivXRay XDR — Semantic Behavioral Fingerprint Generator.
Computes deterministic structural and behavioral hashes from CanonicalIR instances.
Enables cross-format semantic deduplication independent of vendor rule naming.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Set, Tuple

from ..canonical_ir.models import CanonicalIR
from ..canonical_ir.nodes import BooleanLogicNode, FieldCompareNode, IRNode


_FIELD_ALIAS_MAP: Dict[str, str] = {
    "image": "process.name",
    "process": "process.name",
    "commandline": "process.command_line",
    "process_command_line": "process.command_line",
    "parentimage": "process.parent_name",
    "parent_image": "process.parent_name",
    "parentcommandline": "process.parent_command_line",
    "parent_command_line": "process.parent_command_line",
    "user": "identity.principal_id",
    "username": "identity.username",
    "src_ip": "network.src_ip",
    "sourceip": "network.src_ip",
    "dest_ip": "network.dest_ip",
    "destinationip": "network.dest_ip",
    "dest_port": "network.dest_port",
    "destinationport": "network.dest_port",
}


def _canonicalize_ast_structure(node: IRNode) -> Dict[str, Any]:
    """Recursively convert an AST node into a deterministic, sorted canonical dictionary."""
    if isinstance(node, FieldCompareNode):
        val = node.value
        if isinstance(val, (list, set, tuple)):
            val = sorted([str(x).lower() for x in val])
        else:
            val = str(val).lower()
        f_norm = node.field_name.lower().strip()
        f_canon = _FIELD_ALIAS_MAP.get(f_norm, f_norm)
        return {
            "type": "field_compare",
            "field": f_canon,
            "op": node.operator.value,
            "value": val,
        }
    elif isinstance(node, BooleanLogicNode):
        # Canonicalize children and sort by stringified representation to eliminate ordering variance
        canon_children = [_canonicalize_ast_structure(c) for c in node.children]
        canon_children.sort(key=lambda x: json.dumps(x, sort_keys=True))
        return {
            "type": "boolean_logic",
            "op": node.operator.value,
            "children": canon_children,
        }
    return node.to_dict()


class BehavioralFingerprinter:
    """Generates deterministic multi-dimensional fingerprints for detection content."""

    @staticmethod
    def compute_fingerprint(ir: CanonicalIR) -> Dict[str, Any]:
        # 1. AST Structural Hash
        canon_ast = _canonicalize_ast_structure(ir.root_node)
        ast_json = json.dumps(canon_ast, sort_keys=True)
        ast_hash = hashlib.sha256(ast_json.encode("utf-8")).hexdigest()

        # 2. Behavioral Vector
        if isinstance(ir.platform, (list, set, tuple)):
            platform_norm = (str(next(iter(ir.platform), "windows"))).lower().strip()
        else:
            platform_norm = str(ir.platform or "windows").lower().strip()
        tactic_norm = str(ir.tactic or "execution").lower().strip()
        technique_norm = str(ir.technique_id or "T1059").upper().strip()
        fields_sorted = sorted([str(f).lower().strip() for f in (ir.required_fields or [])])

        # 3. Composite Semantic Fingerprint
        composite_payload = {
            "ast_hash": ast_hash,
            "platform": platform_norm,
            "tactic": tactic_norm,
            "technique": technique_norm,
            "fields": fields_sorted,
        }
        semantic_hash = hashlib.sha256(
            json.dumps(composite_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        return {
            "semantic_hash": semantic_hash,
            "ast_hash": ast_hash,
            "platform": platform_norm,
            "tactic": tactic_norm,
            "technique": technique_norm,
            "required_fields": fields_sorted,
        }
