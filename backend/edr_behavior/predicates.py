"""Deterministic, three-valued predicate evaluation. No regex, no eval."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from .contracts import FALSE, TRUE, UNKNOWN, EvidenceRecord

MAX_DEPTH = 6
MAX_LEAVES = 64
MAX_LIST = 256
MAX_LITERAL = 512

OPS = frozenset({"eq", "neq", "in", "not_in", "contains", "contains_any",
                 "startswith", "startswith_any", "endswith", "endswith_any", "exists",
                 "not_exists", "gte", "lte", "len_gte"})
FIELD_PREFIXES = ("process.", "parent.", "file.", "registry.", "dns.",
                  "network.", "auth.", "user.", "detection.", "host.")


class PredicateError(ValueError):
    pass


def validate(node: Any, depth: int = 0, counter: Optional[List[int]] = None) -> None:
    counter = counter if counter is not None else [0]
    if depth > MAX_DEPTH:
        raise PredicateError("predicate nesting too deep")
    if not isinstance(node, dict) or len(node) == 0:
        raise PredicateError("predicate must be a non-empty object")
    if set(node) <= {"all"} or set(node) <= {"any"}:
        key = next(iter(node))
        items = node[key]
        if not isinstance(items, list) or not items:
            raise PredicateError(f"'{key}' needs a non-empty list")
        for it in items:
            validate(it, depth + 1, counter)
        return
    if set(node) == {"not"}:
        validate(node["not"], depth + 1, counter)
        return
    allowed = {"field", "op", "value", "case"}
    if not set(node) <= allowed or "field" not in node or "op" not in node:
        raise PredicateError(f"invalid predicate keys: {sorted(node)}")
    counter[0] += 1
    if counter[0] > MAX_LEAVES:
        raise PredicateError("too many predicate leaves")
    f, op = node["field"], node["op"]
    if not isinstance(f, str) or not f.startswith(FIELD_PREFIXES) or len(f) > 64:
        raise PredicateError(f"field not allowed: {f!r}")
    if op not in OPS:
        raise PredicateError(f"operator not allowed: {op!r}")
    if node.get("case", "insensitive") not in ("insensitive", "sensitive"):
        raise PredicateError("case must be insensitive|sensitive")
    v = node.get("value")
    if op in ("exists", "not_exists"):
        return
    if op in ("in", "not_in", "contains_any", "startswith_any", "endswith_any"):
        if not isinstance(v, list) or not v or len(v) > MAX_LIST:
            raise PredicateError(f"{op} needs a list of 1..{MAX_LIST} literals")
        for x in v:
            _literal(x)
    elif op in ("gte", "lte", "len_gte"):
        if not isinstance(v, (int, float)) or isinstance(v, bool):
            raise PredicateError(f"{op} needs a number")
    else:
        _literal(v)


def _literal(x: Any) -> None:
    if isinstance(x, bool) or not isinstance(x, (str, int, float)):
        raise PredicateError("literal must be string or number")
    if isinstance(x, str) and len(x) > MAX_LITERAL:
        raise PredicateError("literal too long")


def get_field(rec: EvidenceRecord, path: str) -> Any:
    cur: Any = rec.fields
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    if cur == "" or cur == [] or cur == {}:
        return None
    return cur


def _norm(v: Any, case: str) -> Any:
    if isinstance(v, str) and case == "insensitive":
        return v.lower()
    return v


def _seq(v: Any) -> Iterable[Any]:
    return v if isinstance(v, (list, tuple)) else [v]


def _leaf(rec: EvidenceRecord, node: Dict[str, Any]) -> str:
    op, case = node["op"], node.get("case", "insensitive")
    raw = get_field(rec, node["field"])
    if op == "exists":
        return TRUE if raw is not None else FALSE
    if op == "not_exists":
        return FALSE if raw is not None else TRUE
    if raw is None:
        return UNKNOWN
    val = node.get("value")
    if op in ("gte", "lte", "len_gte"):
        try:
            num = len(raw) if op == "len_gte" else float(raw)
        except (TypeError, ValueError):
            return UNKNOWN
        ok = num >= val if op in ("gte", "len_gte") else num <= val
        return TRUE if ok else FALSE
    items = [_norm(x, case) for x in _seq(raw) if isinstance(x, (str, int, float))]
    if not items:
        return UNKNOWN
    lit = [_norm(x, case) for x in val] if isinstance(val, list) else _norm(val, case)

    def any_item(fn) -> str:
        return TRUE if any(fn(i) for i in items) else FALSE

    if op == "eq":
        return any_item(lambda i: i == lit)
    if op == "neq":
        return FALSE if any(i == lit for i in items) else TRUE
    if op == "in":
        return any_item(lambda i: i in lit)
    if op == "not_in":
        return FALSE if any(i in lit for i in items) else TRUE
    strs = [str(i) for i in items]
    if op == "contains":
        return TRUE if any(str(lit) in s for s in strs) else FALSE
    if op == "contains_any":
        return TRUE if any(str(x) in s for s in strs for x in lit) else FALSE
    if op == "startswith":
        return TRUE if any(s.startswith(str(lit)) for s in strs) else FALSE
    if op == "startswith_any":
        return TRUE if any(s.startswith(str(x)) for s in strs for x in lit) else FALSE
    if op == "endswith":
        return TRUE if any(s.endswith(str(lit)) for s in strs) else FALSE
    if op == "endswith_any":
        return TRUE if any(s.endswith(str(x)) for s in strs for x in lit) else FALSE
    return UNKNOWN


def evaluate(rec: EvidenceRecord, node: Dict[str, Any]) -> str:
    """Kleene logic: UNKNOWN propagates unless the result is already decided."""
    if "all" in node:
        res = [evaluate(rec, n) for n in node["all"]]
        if FALSE in res:
            return FALSE
        return UNKNOWN if UNKNOWN in res else TRUE
    if "any" in node:
        res = [evaluate(rec, n) for n in node["any"]]
        if TRUE in res:
            return TRUE
        return UNKNOWN if UNKNOWN in res else FALSE
    if "not" in node:
        r = evaluate(rec, node["not"])
        return {TRUE: FALSE, FALSE: TRUE}.get(r, UNKNOWN)
    return _leaf(rec, node)


def fields_of(node: Dict[str, Any]) -> List[str]:
    if "all" in node or "any" in node:
        out: List[str] = []
        for n in node.get("all") or node.get("any"):
            out.extend(fields_of(n))
        return out
    if "not" in node:
        return fields_of(node["not"])
    return [node["field"]]
