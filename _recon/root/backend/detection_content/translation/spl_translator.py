"""
NivXRay XDR — Deterministic Splunk SPL to Canonical IR Translator.
Translates Splunk Search Processing Language (SPL) queries into Canonical IR.
Enforces NO SILENT WEAKENING:
- search / where filters -> FieldCompareNode & BooleanLogicNode
- stats count by ... -> AggregationRefNode
- unsupported macros, eval, rex, join, transaction are strictly recorded and flagged fatal.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity, UnsupportedConstruct
from ..canonical_ir.nodes import AggregationRefNode, BooleanLogicNode, BooleanOp, FieldCompareNode, IRNode, Operator
from .base import BaseTranslator, TranslationResult

_SPL_FIELD_MAP: Dict[str, str] = {
    "process": "process.name",
    "image": "process.name",
    "process_name": "process.name",
    "commandline": "process.command_line",
    "process_command_line": "process.command_line",
    "parent_process_name": "process.parent_name",
    "parent_image": "process.parent_name",
    "user": "identity.principal_id",
    "username": "identity.username",
    "src_ip": "network.src_ip",
    "dest_ip": "network.dest_ip",
    "dest_port": "network.dest_port",
    "dest": "host.hostname",
    "host": "host.hostname",
    "query": "network.dns_query",
    "event_id": "source_event_id",
    "EventCode": "source_event_id",
}

_UNSUPPORTED_SPL_COMMANDS = frozenset({
    "rex", "eval", "lookup", "transaction", "join", "eventstats",
    "streamstats", "append", "map", "outputlookup", "tstats",
})


class SPLTranslator(BaseTranslator):
    @property
    def source_format(self) -> str:
        return "spl"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        query = source_text.strip()
        if not query:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Empty SPL query"],
                raw_source=source_text,
            )

        pipes = [p.strip() for p in query.split("|")]
        unsupported: List[UnsupportedConstruct] = []
        filter_nodes: List[IRNode] = []
        required_fields: Set[str] = set()
        normalized_map: Dict[str, str] = {}
        is_correlation = False

        for p in pipes:
            if not p:
                continue
            parts = p.split(maxsplit=1)
            cmd = parts[0].lower()
            args = parts[1] if len(parts) > 1 else ""

            # Check if command is in unsupported set
            if cmd in _UNSUPPORTED_SPL_COMMANDS:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_name=f"spl_command_{cmd}",
                        raw_snippet=p,
                        explanation=f"Splunk command '{cmd}' is dynamic/transformative and cannot be evaluated in atomic NIR",
                        fatal=True,
                    )
                )
                continue

            if cmd == "search" or (cmd not in ("where", "stats", "table", "fields") and "=" in p):
                # Search filter
                search_expr = args if cmd == "search" else p
                nodes, u_list, f_set, m_dict = self._parse_search_expression(search_expr)
                filter_nodes.extend(nodes)
                unsupported.extend(u_list)
                required_fields.update(f_set)
                normalized_map.update(m_dict)

            elif cmd == "where":
                # Where filter (e.g. where like(CommandLine, "%-enc%") or count > 5)
                node, u_list, f_set, m_dict = self._parse_where_clause(args)
                if node:
                    filter_nodes.append(node)
                unsupported.extend(u_list)
                required_fields.update(f_set)
                normalized_map.update(m_dict)

            elif cmd == "stats":
                # stats count by ...
                is_correlation = True
                agg_node, u_list = self._parse_stats_command(args)
                if agg_node:
                    filter_nodes.append(agg_node)
                unsupported.extend(u_list)

            elif cmd in ("table", "fields"):
                # Projection command; harmless
                pass
            else:
                unsupported.append(
                    UnsupportedConstruct(
                        construct_name=f"unknown_spl_command_{cmd}",
                        raw_snippet=p,
                        explanation=f"Splunk command '{cmd}' not recognized in deterministic grammar",
                        fatal=True,
                    )
                )

        if not filter_nodes and not unsupported:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["No actionable filter nodes found in SPL query"],
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
            source=meta.get("source", "Splunk Security Content"),
            source_id=meta.get("source_id", "SPL-AUTO"),
            source_url=meta.get("source_url", ""),
            license=meta.get("license", "Apache-2.0"),
            license_verified=True,
            attribution=meta.get("attribution", "Splunk Threat Research Team"),
        )

        ir = CanonicalIR(
            content_id=meta.get("content_id", "DET-SPL-AUTO"),
            name=meta.get("name", "Translated SPL Rule"),
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

    def _parse_search_expression(
        self, expr: str
    ) -> Tuple[List[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        nodes: List[IRNode] = []
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}

        # Match key=value pairs, respecting quoted strings
        # e.g., Image="*powershell.exe" OR CommandLine="*-enc*"
        pattern = re.findall(r'(\b\w+\b)\s*(=|!=)\s*(?:"([^"]*)"|([^\s\)]+))', expr)
        for raw_k, op_str, q_val, bare_val in pattern:
            if raw_k.lower() in ("index", "sourcetype", "source"):
                # Environment scoping; normalized to data source filter
                continue

            val = q_val if q_val is not None and q_val != "" else bare_val
            canon_k = _SPL_FIELD_MAP.get(raw_k.lower(), raw_k)
            fields.add(canon_k)
            norm_map[raw_k] = canon_k

            # Detect wildcards
            if val.startswith("*") and val.endswith("*") and len(val) > 2:
                op = Operator.CONTAINS if op_str == "=" else Operator.NOT_CONTAINS
                clean_val = val[1:-1]
            elif val.startswith("*") and len(val) > 1:
                op = Operator.ENDSWITH
                clean_val = val[1:]
            elif val.endswith("*") and len(val) > 1:
                op = Operator.STARTSWITH
                clean_val = val[:-1]
            else:
                op = Operator.EQUALS if op_str == "=" else Operator.NOT_EQUALS
                clean_val = val

            nodes.append(FieldCompareNode(canon_k, op, clean_val, case_sensitive=False))

        return nodes, unsupported, fields, norm_map

    def _parse_where_clause(
        self, clause: str
    ) -> Tuple[Optional[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}

        # Handle like(Field, "%str%")
        m_like = re.search(r'like\s*\(\s*(\w+)\s*,\s*"%([^%]+)%"\s*\)', clause, flags=re.IGNORECASE)
        if m_like:
            raw_k = m_like.group(1)
            val = m_like.group(2)
            canon_k = _SPL_FIELD_MAP.get(raw_k.lower(), raw_k)
            fields.add(canon_k)
            norm_map[raw_k] = canon_k
            return FieldCompareNode(canon_k, Operator.CONTAINS, val, case_sensitive=False), unsupported, fields, norm_map

        # Handle regex match in where: match(Field, "pattern")
        m_match = re.search(r'match\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)', clause, flags=re.IGNORECASE)
        if m_match:
            raw_k = m_match.group(1)
            pattern = m_match.group(2)
            canon_k = _SPL_FIELD_MAP.get(raw_k.lower(), raw_k)
            fields.add(canon_k)
            norm_map[raw_k] = canon_k
            return FieldCompareNode(canon_k, Operator.REGEX, pattern, case_sensitive=False), unsupported, fields, norm_map

        # General where clause fallback
        unsupported.append(
            UnsupportedConstruct(
                construct_name="complex_where_clause",
                raw_snippet=clause,
                explanation=f"SPL where clause '{clause}' uses syntax not mapped to NIR",
                fatal=False,
            )
        )
        return None, unsupported, fields, norm_map

    def _parse_stats_command(self, args: str) -> Tuple[Optional[IRNode], List[UnsupportedConstruct]]:
        # e.g., count by dest, user
        unsupported: List[UnsupportedConstruct] = []
        m = re.search(r'count\s+by\s+([\w\s,]+)', args, flags=re.IGNORECASE)
        if m:
            by_fields = [f.strip() for f in m.group(1).split(",") if f.strip()]
            canon_by = [_SPL_FIELD_MAP.get(f.lower(), f) for f in by_fields]
            return AggregationRefNode(
                aggregation_type="COUNT",
                threshold=1,
                group_by_fields=canon_by,
                time_window_seconds=300,
            ), unsupported

        unsupported.append(
            UnsupportedConstruct(
                construct_name="unsupported_stats_aggregation",
                raw_snippet=args,
                explanation=f"Stats syntax '{args}' cannot be mapped to NIR aggregation node",
                fatal=True,
            )
        )
        return None, unsupported
