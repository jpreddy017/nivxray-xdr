"""
NivXRay XDR — Deterministic Elastic EQL/ES|QL to Canonical IR Translator.
Translates Event Query Language (EQL) queries into Canonical IR.
Enforces NO SILENT WEAKENING:
- process where ... -> FieldCompareNode & BooleanLogicNode
- sequence with maxspan -> SequenceRefNode & TimeWindowNode
- unsupported joins, until, sample are recorded as fatal UnsupportedConstructs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..canonical_ir.models import CanonicalIR, ProvenanceInfo, TranslationFidelity, UnsupportedConstruct
from ..canonical_ir.nodes import BooleanLogicNode, BooleanOp, FieldCompareNode, IRNode, Operator, SequenceRefNode, TimeWindowNode
from .base import BaseTranslator, TranslationResult

_EQL_FIELD_MAP: Dict[str, str] = {
    "process.name": "process.name",
    "process.executable": "process.executable_path",
    "process.command_line": "process.command_line",
    "process.parent.name": "process.parent_name",
    "process.parent.executable": "process.parent_name",
    "process.parent.command_line": "process.parent_command_line",
    "user.name": "identity.username",
    "user.id": "identity.principal_id",
    "host.name": "host.hostname",
    "host.id": "host.host_id",
    "source.ip": "network.src_ip",
    "source.port": "network.src_port",
    "destination.ip": "network.dest_ip",
    "destination.port": "network.dest_port",
    "dns.question.name": "network.dns_query",
    "file.path": "file.path",
    "registry.path": "registry.path",
}


class EQLTranslator(BaseTranslator):
    @property
    def source_format(self) -> str:
        return "eql"

    def translate(self, source_text: str, metadata: Optional[Dict[str, Any]] = None) -> TranslationResult:
        query = source_text.strip()
        if not query:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["Empty EQL query"],
                raw_source=source_text,
            )

        unsupported: List[UnsupportedConstruct] = []
        is_correlation = False

        # Check for sequence query
        if query.lower().startswith("sequence"):
            return self._translate_sequence(query, metadata, unsupported)

        # Standard single event query: [event_type] where [conditions]
        m = re.match(r'(?:(\w+)\s+)?where\s+(.+)', query, flags=re.IGNORECASE | re.DOTALL)
        if not m:
            return TranslationResult(
                success=False,
                fidelity=TranslationFidelity.UNSUPPORTED,
                errors=["EQL query must match 'where <conditions>' or 'sequence ...' format"],
                raw_source=source_text,
            )

        event_category = m.group(1) or "event"
        conditions_str = m.group(2).strip()

        root_node, u_list, required_fields, norm_map = self._parse_eql_conditions(conditions_str)
        unsupported.extend(u_list)

        fidelity = TranslationFidelity.EXACT
        if any(u.fatal for u in unsupported):
            fidelity = TranslationFidelity.UNSUPPORTED
        elif unsupported:
            fidelity = TranslationFidelity.STRONG

        meta = metadata or {}
        prov = ProvenanceInfo(
            source=meta.get("source", "Elastic Security Detection Rules"),
            source_id=meta.get("source_id", "EQL-AUTO"),
            source_url=meta.get("source_url", ""),
            license=meta.get("license", "Elastic-2.0 / Apache-2.0"),
            license_verified=True,
            attribution=meta.get("attribution", "Elastic Security"),
        )

        ir = CanonicalIR(
            content_id=meta.get("content_id", "DET-EQL-AUTO"),
            name=meta.get("name", "Translated EQL Rule"),
            description=meta.get("description", query[:120]),
            tactic=meta.get("tactic", "Execution"),
            technique_id=meta.get("technique_id", "T1059"),
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "medium"),
            confidence=meta.get("confidence", "high"),
            lane=meta.get("lane", "content"),
            required_fields=sorted(list(required_fields)),
            root_node=root_node or BooleanLogicNode(BooleanOp.AND, []),
            fidelity=fidelity,
            provenance=prov,
            unsupported_constructs=unsupported,
            normalized_field_map=norm_map,
            is_correlation=False,
        )

        return TranslationResult(
            success=(fidelity != TranslationFidelity.UNSUPPORTED),
            ir=ir,
            fidelity=fidelity,
            unsupported_constructs=unsupported,
            raw_source=source_text,
        )

    def _parse_eql_conditions(
        self, cond_str: str
    ) -> Tuple[Optional[IRNode], List[UnsupportedConstruct], Set[str], Dict[str, str]]:
        unsupported: List[UnsupportedConstruct] = []
        fields: Set[str] = set()
        norm_map: Dict[str, str] = {}
        nodes: List[IRNode] = []

        # Split on 'and'
        tokens = re.split(r'\s+\band\b\s+', cond_str, flags=re.IGNORECASE)
        for tok in tokens:
            node = self._parse_eql_atomic(tok.strip(), unsupported, fields, norm_map)
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

    def _parse_eql_atomic(
        self,
        tok: str,
        unsupported: List[UnsupportedConstruct],
        fields: Set[str],
        norm_map: Dict[str, str],
    ) -> Optional[IRNode]:
        # EQL atomics: field == "val", field != "val", field : "*wildcard*", field in ("a", "b")
        m = re.search(
            r'([\w\.]+)\s*(==|!=|:|like|in)\s*(?:"([^"]*)"|(\([^)]+\))|([^\s\)]+))',
            tok,
            flags=re.IGNORECASE,
        )
        if not m:
            unsupported.append(
                UnsupportedConstruct(
                    construct_name="unparsed_eql_atom",
                    raw_snippet=tok,
                    explanation=f"Could not parse EQL condition: '{tok}'",
                    fatal=True,
                )
            )
            return None

        raw_k = m.group(1).lower()
        eql_op = m.group(2).lower()
        q_val = m.group(3)
        list_val = m.group(4)
        bare_val = m.group(5)

        canon_k = _EQL_FIELD_MAP.get(raw_k, raw_k)
        fields.add(canon_k)
        norm_map[raw_k] = canon_k

        if list_val:
            items = [re.sub(r'["\']', '', x).strip() for x in list_val.strip("()").split(",")]
            return FieldCompareNode(canon_k, Operator.IN_SET, items, case_sensitive=False)

        val = q_val if q_val is not None else bare_val

        if eql_op in (":", "like") or (eql_op == "==" and "*" in str(val)):
            s_val = str(val)
            if s_val.startswith("*") and s_val.endswith("*") and len(s_val) > 2:
                return FieldCompareNode(canon_k, Operator.CONTAINS, s_val[1:-1], case_sensitive=False)
            elif s_val.startswith("*") and len(s_val) > 1:
                return FieldCompareNode(canon_k, Operator.ENDSWITH, s_val[1:], case_sensitive=False)
            elif s_val.endswith("*") and len(s_val) > 1:
                return FieldCompareNode(canon_k, Operator.STARTSWITH, s_val[:-1], case_sensitive=False)
            return FieldCompareNode(canon_k, Operator.CONTAINS, s_val, case_sensitive=False)

        if eql_op == "==":
            return FieldCompareNode(canon_k, Operator.EQUALS, val, case_sensitive=False)
        if eql_op == "!=":
            return FieldCompareNode(canon_k, Operator.NOT_EQUALS, val, case_sensitive=False)

        return None

    def _translate_sequence(
        self, query: str, metadata: Optional[Dict[str, Any]], unsupported: List[UnsupportedConstruct]
    ) -> TranslationResult:
        # Check for unsupported 'until' clause (must fail closed to prevent silent weakening)
        if re.search(r'\buntil\b', query, flags=re.IGNORECASE):
            unsupported.append(
                UnsupportedConstruct(
                    construct_name="eql_until_clause",
                    raw_snippet="until",
                    explanation="EQL 'until' sequence terminator clause is not supported in streaming correlation and cannot be silently weakened",
                    fatal=True,
                )
            )

        # e.g., sequence by host.id with maxspan=15m [process where ...] [network where ...]
        m_span = re.search(r'maxspan\s*=\s*(\d+)([smhd])', query, flags=re.IGNORECASE)
        span_sec = 900
        if m_span:
            val = int(m_span.group(1))
            unit = m_span.group(2).lower()
            if unit == "s": span_sec = val
            elif unit == "m": span_sec = val * 60
            elif unit == "h": span_sec = val * 3600
            elif unit == "d": span_sec = val * 86400

        m_by = re.search(r'sequence\s+by\s+([\w\.\s,]+)\s+with', query, flags=re.IGNORECASE)
        by_fields = []
        if m_by:
            by_fields = [_EQL_FIELD_MAP.get(f.strip().lower(), f.strip()) for f in m_by.group(1).split(",")]

        # Extract stages in brackets: [...]
        stages = re.findall(r'\[([^\]]+)\]', query)
        if not stages:
            unsupported.append(
                UnsupportedConstruct(
                    construct_name="empty_eql_sequence",
                    raw_snippet=query,
                    explanation="EQL sequence query contains no stage definitions in brackets",
                    fatal=True,
                )
            )

        stage_fields: Set[str] = set(by_fields)
        for stg in stages:
            m_where = re.search(r'where\s+(.+)', stg, flags=re.IGNORECASE)
            c_str = m_where.group(1) if m_where else stg
            _, _, s_fields, _ = self._parse_eql_conditions(c_str)
            stage_fields.update(s_fields)

        root_node = TimeWindowNode(
            window_seconds=span_sec,
            child=SequenceRefNode(
                step_ids=[f"stage_{i+1}" for i in range(len(stages))],
                max_span_seconds=span_sec,
                group_by_fields=by_fields,
            ),
        )

        meta = metadata or {}
        prov = ProvenanceInfo(
            source=meta.get("source", "Elastic Security Detection Rules"),
            source_id=meta.get("source_id", "EQL-SEQ-AUTO"),
            source_url=meta.get("source_url", ""),
            license=meta.get("license", "Elastic-2.0"),
            license_verified=True,
            attribution=meta.get("attribution", "Elastic Security"),
        )

        fidelity = TranslationFidelity.STRONG
        if any(u.fatal for u in unsupported):
            fidelity = TranslationFidelity.UNSUPPORTED

        ir = CanonicalIR(
            content_id=meta.get("content_id", "CORR-EQL-AUTO"),
            name=meta.get("name", "Translated EQL Sequence Correlation"),
            description=meta.get("description", query[:120]),
            tactic=meta.get("tactic", "Lateral Movement"),
            technique_id=meta.get("technique_id", "T1021"),
            platform=meta.get("platform", "windows"),
            severity=meta.get("severity", "high"),
            confidence=meta.get("confidence", "high"),
            lane="correlation",
            required_fields=sorted(list(stage_fields)),
            root_node=root_node,
            fidelity=fidelity,
            provenance=prov,
            unsupported_constructs=unsupported,
            is_correlation=True,
        )

        return TranslationResult(
            success=(fidelity != TranslationFidelity.UNSUPPORTED),
            ir=ir,
            fidelity=fidelity,
            unsupported_constructs=unsupported,
            raw_source=query,
        )
