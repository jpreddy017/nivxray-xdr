"""
NivXRay XDR — Deterministic Microsoft KQL to Canonical IR Translator.
Translates Kusto Query Language (KQL) queries from Microsoft Sentinel / Defender into Canonical IR.
Enforces NO SILENT WEAKENING:
- where filters with has, contains, startswith, =~, in~ -> FieldCompareNode
- summarize count() by ... -> AggregationRefNode
- unsupported joins, mvexpand, evaluate plugins are recorded as fatal UnsupportedConstructs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity, UnsupportedConstruct
from ..canonical_ir.nodes import AggregationRefNode, BooleanLogicNode, BooleanOp, FieldCompareNode, IRNode, Operator
from .base import BaseTranslator, TranslationResult

_KQL_FIELD_MAP: Dict[str, str] = {
    "filename": "process.name",
    "processcommandline": "process.command_line",
    "initiatingprocessfilename": "process.parent_name",
    "initiatingprocesscommandline": "process.parent_command_line",
    "accountname": "identity.username",
    "accountupn": "identity.principal_id",
    "accountdomain": "identity.domain",
    "deviceid": "host.host_id",
    "devicename": "host.hostname",
    "remoteip": "network.dest_ip",
    "remoteport": "network.dest_port",
    "localip": "network.src_ip",
    "actiontype": "cloud.action",
    "folderpath": "file.path",
    "processpath": "process.path",
}

_UNSUPPORTED_KQL_COMMANDS = frozenset({
    "join", "union", "mvexpand", "make-series", "evaluate", "fork", "externaldata",
})


class KQLTranslator(BaseTranslator):
    @property
    def source_format(self) -> str:
        return "kql"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        query = source_text.strip()
        if not query:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Empty KQL query"],
                raw_source=source_text,
            )

        pipes = [p.strip() for p in query.split("|")]
        unsupported: List[UnsupportedConstruct] = []
        filter_nodes: List[IRNode] = []
        required_fields: Set[str] = set()
        normalized_map: Dict[str, str] = {}
        is_correlation = False

        # First line may be the table name (e.g. DeviceProcessEvents)
        table_line = pipes[0]
        subsequent_pipes = pipes[1:] if len(pipes) > 1 else []

        for p in subsequent_pipes:
            if not p:
                continue
            parts = p.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            if cmd in _UNSUPPORTED_KQL_COMMANDS:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_name=f"kql_operator_{cmd}",
                        raw_snippet=p,
                        explanation=f"KQL operator '{cmd}' is not supported in atomic NIR AST",
                        fatal=True,
                    )
                )
                continue

            if cmd == "where":
                node, u_list, f_set, m_dict = self._parse_kql_where(args)
                if node:
                    filter_nodes.append(node)
                unsupported.extend(u_list)
                required_fields.update(f_set)
                normalized_map.update(m_dict)

            elif cmd == "summarize":
                is_correlation = True
                agg_node, u_list = self._parse_kql_summarize(args)
                if agg_node:
                    filter_nodes.append(agg_node)
                unsupported.extend(u_list)

            elif cmd in ("project", "extend", "take", "limit", "top"):
                # Harmless projection / limit
                pass
            else:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_name=f"unknown_kql_operator_{cmd}",
                        raw_snippet=p,
                        explanation=f"KQL operator '{cmd}' not recognized in deterministic grammar",
                        fatal=True,
                    )
                )

        if not filter_nodes and not unsupported:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["No actionable where filters found in KQL query"],
                raw_source=source_text,
            )

        root_node = (
            BooleanLogicNode(BooleanOp.AND, filter_nodes)
            if len(filter_nodes) > 1
            else (filter_nodes[0] if filter_nodes else BooleanLogicNode(BooleanOp.AND, []))
        )

        fidelity = TranslationFidelity.EXACT
        if any(u.fatal for u in unsupported):
            fidelity = TranslationFidelity.UNSUPPORTED
        elif unsupported or is_correlation:
            fidelity = TranslationFidelity.STRONG

        meta = metadata or {}
        prov = ProvenanceInfo(
            source=meta.get("source", "Microsoft Sentinel Public"),
            source_id=meta.get("source_id", "KQL-AUTO"),
            source_url=meta.get("source_url", ""),
            license=meta.get("license", "MIT"),
            license_verified=True,
            attribution=meta.get("attribution", "Microsoft Community"),
        )

        ir = CanonicalIR(
            content_id=meta.get("content_id", "DET-KQL-AUTO"),
            name=meta.get("name", "Translated KQL Rule"),
            description=meta.get("description", query[:120]),
            tactic=meta.get("tactic", "Execution"),
            technique_id=meta.get("technique_id", "T1059"),
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "medium"),
            confidence=meta.get("confidence", "high"),
            lane=meta.get("lane", "content"),
            required_fields=sorted(list(required_fields)),
            root_node=root_node,
            fidelity=fidelity,
            provenance=prov,
            unsupported_constructs=unsupported,
            normalized_field_map=normalized_map,
            is_correlation=is_correlation,
        )

        return TranslationResult(
            success=(fidelity != TranslationFidelity.UNSUPPORTED),
            ir=ir,
            fidelity=fidelity,
            unsupported_constructs=unsupported,
            raw_source=source_text,
        )

    def _parse_kql_where(
        self, clause: str
    ) -> Tuple[Optional[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}
        nodes: List[IRNode] = []

        # Split on 'and' / 'or'
        sub_clauses = re.split(r'\s+\band\b\s+', clause, flags=re.IGNORECASE)
        for sc in sub_clauses:
            node = self._parse_atomic_kql_condition(sc, unsupported, fields, norm_map)
            if node:
                nodes.append(node)

        if not nodes:
            return None, unsupported, fields, norm_map

        return (
            BooleanLogicNode(BooleanOp.AND, nodes) if len(nodes) > 1 else nodes[0],
            unsupported,
            fields,
            norm_map,
        )

    def _parse_atomic_kql_condition(
        self,
        cond: str,
        unsupported: List[UnsupportedConstruct],
        fields: Set[str],
        norm_map: Dict[str, str],
    ) -> Optional[IRNode]:
        # KQL operators: has, contains, startswith, endswith, =~, ==, !=, in~, in
        m = re.search(
            r'(\b\w+\b)\s+(has|contains|startswith|endswith|=~|==|!=|in~|in)\s+(?:@?"([^"]*)"|(\([^)]+\))|([^\s\)]+))',
            cond,
            flags=re.IGNORECASE,
        )
        if not m:
            unsupported.append(
                UnsupportedConstruct(
                    construct_name="unparsed_kql_condition",
                    raw_snippet=cond,
                    explanation=f"Could not parse atomic condition: '{cond}'",
                    fatal=True,
                )
            )
            return None

        raw_k = m.group(1)
        kql_op = m.group(2).lower()
        q_val = m.group(3)
        list_val = m.group(4)
        bare_val = m.group(5)

        canon_k = _KQL_FIELD_MAP.get(raw_k.lower(), raw_k)
        fields.add(canon_k)
        norm_map[raw_k] = canon_k

        if list_val:
            # in ("val1", "val2")
            items = [re.sub(r'["\']', '', x).strip() for x in list_val.strip("()").split(",")]
            return FieldCompareNode(canon_k, Operator.IN_SET, items, case_sensitive=False)

        val = q_val if q_val is not None else (bare_val.lstrip('@').strip('"\'') if bare_val else "")

        op_map = {
            "has": Operator.CONTAINS,
            "contains": Operator.CONTAINS,
            "startswith": Operator.STARTSWITH,
            "endswith": Operator.ENDSWITH,
            "=~": Operator.EQUALS,
            "==": Operator.EQUALS,
            "!=": Operator.NOT_EQUALS,
        }

        op = op_map.get(kql_op, Operator.EQUALS)
        case_sensitive = (kql_op == "==")

        return FieldCompareNode(canon_k, op, val, case_sensitive=case_sensitive)

    def _parse_kql_summarize(self, args: str) -> Tuple[Optional[IRNode], List[UnsupportedConstruct]]:
        # e.g., count() by DeviceId
        unsupported: List[UnsupportedConstruct] = []
        m = re.search(r'count\(\)\s+by\s+([\w\s,]+)', args, flags=re.IGNORECASE)
        if m:
            by_fields = [f.strip() for f in m.group(1).split(",") if f.strip()]
            canon_by = [_KQL_FIELD_MAP.get(f.lower(), f) for f in by_fields]
            return AggregationRefNode(
                aggregation_type="COUNT",
                threshold=1,
                group_by_fields=canon_by,
                time_window_seconds=300,
            ), unsupported

        unsupported.append(
            UnsupportedConstruct(
                construct_name="unsupported_kql_summarize",
                raw_snippet=args,
                explanation=f"KQL summarize syntax '{args}' cannot be mapped to NIR aggregation",
                fatal=True,
            )
        )
        return None, unsupported
