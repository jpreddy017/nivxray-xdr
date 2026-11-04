"""
NivXRay XDR — Canonical Content Intermediate Representation (NIR) AST Nodes.
Defines strongly-typed, serializable AST nodes for cross-format detection and correlation logic.
Supports atomic field comparisons, boolean trees, lists, regex, string operations,
temporal windows, sequences, and aggregations.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Union


class Operator(str, Enum):
    EQUALS              = "equals"
    NOT_EQUALS          = "not_equals"
    CONTAINS            = "contains"
    NOT_CONTAINS        = "not_contains"
    STARTSWITH          = "startswith"
    ENDSWITH            = "endswith"
    REGEX               = "regex"
    IN_SET              = "in_set"
    NOT_IN_SET          = "not_in_set"
    GREATER_THAN        = "gt"
    GREATER_EQUAL       = "gte"
    LESS_THAN           = "lt"
    LESS_EQUAL          = "lte"
    EXISTS              = "exists"
    NOT_EXISTS          = "not_exists"


class BooleanOp(str, Enum):
    AND = "AND"
    OR  = "OR"
    NOT = "NOT"


@dataclass
class IRNode:
    """Base class for all NIR AST nodes."""
    def evaluate(self, event: Dict[str, Any]) -> bool:
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_COMMON_FIELD_FALLBACKS: Dict[str, List[str]] = {
    "process.command_line": ["command_line", "CommandLine", "cmd", "process.cmdline", "process_command_line"],
    "process.name": ["image", "Image", "process_name", "proc", "FileName"],
    "process.parent_name": ["parent_image", "ParentImage", "process.parent.name", "parent_process", "process.parent.name"],
    "network.dest_ip": ["network.dst.ip", "destinationip", "dest_ip", "dst_ip", "DestinationIp", "RemoteIp"],
    "network.dst.ip": ["network.dest_ip", "destinationip", "dest_ip", "dst_ip", "DestinationIp", "RemoteIp"],
    "network.src_ip": ["sourceip", "src_ip", "SourceIp", "SourceNetworkAddress"],
    "network.dest_port": ["network.dst.port", "destinationport", "dest_port", "dst_port", "RemotePort"],
    "file.path": ["targetfilename", "target.file", "filepath", "TargetFilename", "FolderPath"],
    "source_event_id": ["event.code", "EventID", "event_id", "EventCode", "eventid"],
    "identity.username": ["user.name", "username", "TargetUserName", "user", "AccountName"],
    "identity.principal_id": ["user.id", "principal_id", "user", "subject.account"],
    "ad.extended_rights": ["Properties", "properties", "extended_rights"],
    "k8s.security_context.privileged": ["requestObject.spec.containers.securityContext.privileged"],
    "k8s.resource": ["objectRef.resource", "resource"],
    "k8s.verb": ["verb"],
}


def _safe_get_field(ev: Dict[str, Any], field_path: str) -> Any:
    """Resolve dotted path (e.g. process.name, network.src.ip) or flat key, with alias fallbacks."""
    if not field_path:
        return None

    def _resolve(path: str) -> Any:
        if path in ev:
            return ev[path]
        if "." in path:
            parts = path.split(".")
            curr: Any = ev
            for p in parts:
                if isinstance(curr, dict) and p in curr:
                    curr = curr[p]
                else:
                    return None
            return curr
        return ev.get(path)

    val = _resolve(field_path)
    if val is not None:
        return val

    # Check registered fallbacks
    fallbacks = _COMMON_FIELD_FALLBACKS.get(field_path, [])
    for fb in fallbacks:
        val = _resolve(fb)
        if val is not None:
            return val

    # Last resort: check leaf key
    if "." in field_path:
        leaf = field_path.split(".")[-1]
        if leaf in ev:
            return ev[leaf]

    return None


@dataclass
class FieldCompareNode(IRNode):
    """Atomic field comparison node."""
    field_name: str
    operator: Operator
    value: Any
    case_sensitive: bool = False
    node_type: str = "field_compare"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        actual = _safe_get_field(event, self.field_name)

        if self.operator == Operator.EXISTS:
            return actual is not None
        if self.operator == Operator.NOT_EXISTS:
            return actual is None

        if actual is None:
            return False

        # If actual is a list, evaluate element-wise OR
        if isinstance(actual, list):
            return any(
                FieldCompareNode(self.field_name, self.operator, self.value, self.case_sensitive)._eval_scalar(item)
                for item in actual
            )
        return self._eval_scalar(actual)

    def _eval_scalar(self, actual: Any) -> bool:
        op = self.operator
        val = self.value

        # Numeric comparisons
        if op in (Operator.GREATER_THAN, Operator.GREATER_EQUAL, Operator.LESS_THAN, Operator.LESS_EQUAL):
            try:
                a_num = float(actual)
                v_num = float(val)
                if op == Operator.GREATER_THAN: return a_num > v_num
                if op == Operator.GREATER_EQUAL: return a_num >= v_num
                if op == Operator.LESS_THAN: return a_num < v_num
                if op == Operator.LESS_EQUAL: return a_num <= v_num
            except Exception:
                return False

        # In-set comparisons
        if op in (Operator.IN_SET, Operator.NOT_IN_SET):
            if not isinstance(val, (list, set, tuple)):
                val = [val]
            if self.case_sensitive:
                matched = str(actual) in [str(x) for x in val]
            else:
                act_str = str(actual).lower()
                matched = act_str in [str(x).lower() for x in val]
            return matched if op == Operator.IN_SET else not matched

        # Regex comparison
        if op == Operator.REGEX:
            try:
                flags = 0 if self.case_sensitive else re.IGNORECASE
                return re.search(str(val), str(actual), flags) is not None
            except Exception:
                return False

        # String operations
        a_str = str(actual)
        v_str = str(val)
        if not self.case_sensitive:
            a_str = a_str.lower()
            v_str = v_str.lower()

        if op == Operator.EQUALS:
            return a_str == v_str
        if op == Operator.NOT_EQUALS:
            return a_str != v_str
        if op == Operator.CONTAINS:
            return v_str in a_str
        if op == Operator.NOT_CONTAINS:
            return v_str not in a_str
        if op == Operator.STARTSWITH:
            if a_str.startswith(v_str):
                return True
            if a_str.startswith(v_str.lstrip("\\/")):
                return True
            return False
        if op == Operator.ENDSWITH:
            if a_str.endswith(v_str):
                return True
            v_clean = v_str.lstrip("\\/")
            if a_str.endswith(v_clean):
                return True
            a_leaf = a_str.split("\\")[-1].split("/")[-1]
            if a_leaf == v_clean:
                return True
            return False

        return False


@dataclass
class BooleanLogicNode(IRNode):
    """Combines child nodes with boolean logic (AND, OR, NOT)."""
    operator: BooleanOp
    children: List[IRNode] = field(default_factory=list)
    node_type: str = "boolean_logic"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        if not self.children:
            return True

        if self.operator == BooleanOp.AND:
            return all(child.evaluate(event) for child in self.children)
        elif self.operator == BooleanOp.OR:
            return any(child.evaluate(event) for child in self.children)
        elif self.operator == BooleanOp.NOT:
            # NOT wraps first child (or all children in NAND semantics)
            return not self.children[0].evaluate(event)
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": self.node_type,
            "operator": self.operator.value,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class TimeWindowNode(IRNode):
    """Bounded time window for temporal correlation evaluation."""
    window_seconds: int
    child: IRNode
    node_type: str = "time_window"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        # Atomic single-event evaluation delegates to child
        return self.child.evaluate(event)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": self.node_type,
            "window_seconds": self.window_seconds,
            "child": self.child.to_dict(),
        }


@dataclass
class SequenceRefNode(IRNode):
    """Represents a stateful multi-step progression (e.g. Step A -> Step B)."""
    step_ids: List[str]
    max_span_seconds: int
    group_by_fields: List[str] = field(default_factory=list)
    node_type: str = "sequence_ref"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        # Sequence progression is evaluated by Correlation Engine stream
        return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AggregationRefNode(IRNode):
    """Represents threshold / counting conditions (e.g. count > 5 by host)."""
    aggregation_type: str  # COUNT, THRESHOLD, VALUE_COUNT
    threshold: int
    group_by_fields: List[str]
    time_window_seconds: int
    node_type: str = "aggregation_ref"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        # Aggregations are evaluated by Correlation Engine
        return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationRefNode(IRNode):
    """Represents link to an authoritative ICE correlation scenario."""
    scenario_id: str
    target_operators: List[str]
    node_type: str = "correlation_ref"

    def evaluate(self, event: Dict[str, Any]) -> bool:
        return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
