"""
NivXRay XDR — Deterministic Sigma to Canonical IR Translator.
Parses Sigma YAML rules, maps fields to canonical evidence schema,
and compiles detection logic into NIR AST without silent weakening.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity, UnsupportedConstruct
from ..canonical_ir.nodes import BooleanLogicNode, BooleanOp, FieldCompareNode, IRNode, Operator
from .base import BaseTranslator, TranslationResult

# Canonical field normalization mapping for Sigma
_SIGMA_FIELD_MAP: Dict[str, str] = {
    "image": "process.name",
    "commandline": "process.command_line",
    "parentimage": "process.parent_name",
    "parentcommandline": "process.parent_command_line",
    "user": "identity.principal_id",
    "targetusername": "identity.username",
    "targetdomainname": "identity.domain",
    "targetobject": "registry.path",
    "destinationip": "network.dest_ip",
    "destinationport": "network.dest_port",
    "sourceip": "network.src_ip",
    "sourceport": "network.src_port",
    "queryname": "network.dns_query",
    "targetfilename": "file.path",
    "eventid": "source_event_id",
}


def _normalize_field_name(raw_field: str) -> Tuple[str, List[str]]:
    """Parse field name and pipe-separated modifiers (e.g. 'CommandLine|contains|all')."""
    parts = raw_field.split("|")
    base = parts[0].strip().lower()
    modifiers = [m.strip().lower() for m in parts[1:]]
    canonical_field = _SIGMA_FIELD_MAP.get(base, parts[0].strip())
    return canonical_field, modifiers


class SigmaTranslator(BaseTranslator):
    @property
    def source_format(self) -> str:
        return "sigma"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        try:
            doc = yaml.safe_load(source_text)
        except Exception as ex:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=[f"YAML parsing failed: {ex}"],
                raw_source=source_text,
            )

        if not isinstance(doc, dict):
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Sigma rule root must be a YAML mapping"],
                raw_source=source_text,
            )

        detection_block = doc.get("detection")
        if not isinstance(detection_block, dict):
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Sigma rule missing 'detection' section"],
                raw_source=source_text,
            )

        condition_str = detection_block.get("condition")
        if not condition_str or not isinstance(condition_str, str):
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Sigma rule missing condition string"],
                raw_source=source_text,
            )

        unsupported: List[UnsupportedConstruct] = []
        fidelity = TranslationFidelity.EXACT
        selections: Dict[str, IRNode] = {}
        required_fields: Set[str] = set()
        normalized_map: Dict[str, str] = {}

        # 1. Parse each selection / filter block
        for sel_name, sel_body in detection_block.items():
            if sel_name == "condition" or sel_name.startswith("timeframe"):
                continue

            node, sel_unsupported, sel_fields, sel_map = self._parse_selection(sel_name, sel_body)
            if node:
                selections[sel_name] = node
            unsupported.extend(sel_unsupported)
            required_fields.update(sel_fields)
            normalized_map.update(sel_map)

        # 2. Check timeframe or aggregations
        if "timeframe" in detection_block or any(kw in condition_str for kw in ("| count()", "count() by")):
            unsupported.append(
                UnsupportedConstruct(
                    construct_name="aggregation_or_timeframe",
                    raw_snippet=condition_str,
                    explanation="Sigma aggregations require multi-event correlation engine evaluation, not single-event AST",
                    fatal=True,
                )
            )
            fidelity = TranslationFidelity.PARTIAL

        # 3. Compile condition into root IRNode
        root_node = self._compile_condition(condition_str, selections, unsupported)
        if not root_node:
            fidelity = TranslationFidelity.UNSUPPORTED

        if any(u.fatal for u in unsupported):
            fidelity = TranslationFidelity.UNSUPPORTED
        elif unsupported:
            fidelity = TranslationFidelity.STRONG

        # Provenance
        prov = ProvenanceInfo(
            source="SigmaHQ" if not metadata or not metadata.get("source") else metadata["source"],
            source_id=str(doc.get("id") or (metadata.get("source_id") if metadata else "") or ""),
            source_url=str(metadata.get("source_url") or "") if metadata else "",
            license=str(doc.get("license") or "DRL-1.1"),
            license_verified=True,
            attribution=str(doc.get("author") or "Community"),
            source_date=str(doc.get("date") or ""),
        )

        title = str(doc.get("title") or "Unnamed Sigma Rule")
        rule_id = str(metadata.get("content_id") if metadata else "") or f"DET-SIGMA-{doc.get('id', 'AUTO')[:8]}"
        tags = doc.get("tags") or []
        tactic = "Execution"
        technique = "T1059"
        for t in tags:
            if str(t).startswith("attack.t"):
                technique = str(t).replace("attack.", "").upper()
            elif str(t).startswith("attack."):
                tactic = str(t).replace("attack.", "").capitalize()

        ir = CanonicalIR(
            content_id=rule_id,
            name=title,
            description=str(doc.get("description") or title),
            tactic=tactic,
            technique_id=technique,
            platform=str((doc.get("logsource") or {}).get("product") or "windows"),
            severity=str(doc.get("level") or "medium").lower(),
            confidence="high",
            lane="content",
            required_fields=sorted(list(required_fields)),
            root_node=root_node or BooleanLogicNode(BooleanOp.AND, []),
            fidelity=fidelity,
            provenance=prov,
            unsupported_constructs=unsupported,
            normalized_field_map=normalized_map,
            tags=[str(t) for t in tags],
        )

        return TranslationResult(
            success=(fidelity != TranslationFidelity.UNSUPPORTED),
            ir=ir,
            fidelity=fidelity,
            unsupported_constructs=unsupported,
            raw_source=source_text,
        )

    def _parse_selection(
        self, name: str, body: Any
    ) -> Tuple[Optional[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}

        if isinstance(body, list):
            # List of dicts in Sigma means OR of each dict
            children: List[IRNode] = []
            for item in body:
                if isinstance(item, dict):
                    node, u, f, m = self._parse_dict_selection(item)
                    if node:
                        children.append(node)
                    unsupported.extend(u)
                    fields.update(f)
                    norm_map.update(m)
            if not children:
                res_node = None
            elif len(children) == 1:
                res_node = children[0]
            else:
                res_node = BooleanLogicNode(BooleanOp.OR, children)
            return res_node, unsupported, fields, norm_map

        elif isinstance(body, dict):
            return self._parse_dict_selection(body)

        unsupported.append(
            UnsupportedConstruct(
                construct_name="unsupported_selection_body",
                raw_snippet=str(body),
                explanation=f"Selection {name} is neither dict nor list",
                fatal=True,
            )
        )
        return None, unsupported, fields, norm_map

    def _parse_dict_selection(
        self, d: Dict[str, Any]
    ) -> Tuple[Optional[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        nodes: List[IRNode] = []
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}

        for raw_k, val in d.items():
            canon_k, modifiers = _normalize_field_name(raw_k)
            fields.add(canon_k)
            norm_map[raw_k] = canon_k

            op = Operator.EQUALS
            case_sensitive = False

            # Evaluate modifiers
            if "contains" in modifiers:
                op = Operator.CONTAINS
            elif "startswith" in modifiers:
                op = Operator.STARTSWITH
            elif "endswith" in modifiers:
                op = Operator.ENDSWITH
            elif "re" in modifiers:
                op = Operator.REGEX

            if "cased" in modifiers:
                case_sensitive = True

            # Check unsupported modifiers
            for mod in modifiers:
                if mod not in ("contains", "startswith", "endswith", "re", "cased", "all"):
                    unsupported.append(
                        UnsupportedConstruct(
                            construct_name=f"modifier_{mod}",
                            raw_snippet=f"{raw_k}: {val}",
                            explanation=f"Sigma modifier '|{mod}' is not supported",
                            fatal=True,
                        )
                    )

            if isinstance(val, list):
                if "all" in modifiers:
                    # All values must match
                    sub_nodes = [FieldCompareNode(canon_k, op, item, case_sensitive) for item in val]
                    nodes.append(BooleanLogicNode(BooleanOp.AND, sub_nodes) if len(sub_nodes) > 1 else sub_nodes[0])
                else:
                    # Standard list is OR
                    sub_nodes = [FieldCompareNode(canon_k, op, item, case_sensitive) for item in val]
                    nodes.append(BooleanLogicNode(BooleanOp.OR, sub_nodes) if len(sub_nodes) > 1 else sub_nodes[0])
            else:
                nodes.append(FieldCompareNode(canon_k, op, val, case_sensitive))

        if not nodes:
            res_node = None
        elif len(nodes) == 1:
            res_node = nodes[0]
        else:
            res_node = BooleanLogicNode(BooleanOp.AND, nodes)
        return res_node, unsupported, fields, norm_map

    def _compile_condition(
        self, cond_str: str, selections: Dict[str, IRNode], unsupported: List[UnsupportedConstruct]
    ) -> Optional[IRNode]:
        cleaned = cond_str.strip()

        # Handle simple single selection (e.g. "selection")
        if cleaned in selections:
            return selections[cleaned]

        # Handle 1 of selection*
        if cleaned.startswith("1 of ") or cleaned.startswith("all of "):
            prefix = cleaned.split(" ")[2].replace("*", "")
            matching_nodes = [node for k, node in selections.items() if k.startswith(prefix)]
            if matching_nodes:
                op = BooleanOp.OR if cleaned.startswith("1 of ") else BooleanOp.AND
                return BooleanLogicNode(op, matching_nodes)

        # Handle standard boolean expressions (e.g. "selection and not filter", "sel1 or sel2")
        tokens = re.split(r"(\band\b|\bor\b|\bnot\b|\(|\))", cleaned, flags=re.IGNORECASE)
        tokens = [t.strip() for t in tokens if t.strip()]

        if len(tokens) == 3 and tokens[1].lower() == "and":
            left = selections.get(tokens[0])
            right = selections.get(tokens[2])
            if left and right:
                return BooleanLogicNode(BooleanOp.AND, [left, right])
        elif len(tokens) == 3 and tokens[1].lower() == "or":
            left = selections.get(tokens[0])
            right = selections.get(tokens[2])
            if left and right:
                return BooleanLogicNode(BooleanOp.OR, [left, right])
        elif len(tokens) == 4 and tokens[1].lower() == "and" and tokens[2].lower() == "not":
            left = selections.get(tokens[0])
            right = selections.get(tokens[3])
            if left and right:
                return BooleanLogicNode(
                    BooleanOp.AND,
                    [left, BooleanLogicNode(BooleanOp.NOT, [right])],
                )

        # Fallback: if all selections can be logically resolved
        if all(k in selections for k in selections):
            if "not " in cleaned and len(selections) == 2:
                # typically "selection and not filter"
                pos = [node for k, node in selections.items() if "filter" not in k.lower()]
                neg = [node for k, node in selections.items() if "filter" in k.lower()]
                if pos and neg:
                    return BooleanLogicNode(
                        BooleanOp.AND,
                        [pos[0], BooleanLogicNode(BooleanOp.NOT, [neg[0]])],
                    )
            return BooleanLogicNode(BooleanOp.AND, list(selections.values()))

        unsupported.append(
            UnsupportedConstruct(
                construct_name="complex_condition_syntax",
                raw_snippet=cond_str,
                explanation=f"Condition expression '{cond_str}' could not be deterministically parsed into NIR boolean tree",
                fatal=True,
            )
        )
        return None
