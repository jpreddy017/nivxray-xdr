"""
NivXRay Native Sigma Evaluator — P0.2e reference DETECTION_ENGINE.

The FIRST real Sigma-executing engine in NivXRay.  Small on purpose
— supports a deterministic subset of pySigma detection primitives
that maps cleanly onto canonical evidence dicts:

    Supported field modifiers
      * equals (default)
      * |contains
      * |startswith
      * |endswith
      * |re                   (Python re.search)
      * lists of values       (OR semantics per Sigma spec)

    Supported detection block shapes
      * one or more `selection`-style dicts of {field: value|list}
      * `condition` referencing selections combined with AND / OR /
        NOT — a small deterministic parser handles the common cases:
          selection
          selection1 and selection2
          selection1 or selection2
          not selection

The evaluator is DETERMINISTIC, SIDE-EFFECT FREE, and callable via
`evaluate(rule, evidence) → bool`.  It is validated against real
positive and negative fixtures by the P0.2e Detection Execution
Harness before its capability contract may be promoted to
`execution.detection = True` and `classification = DETECTION_ENGINE`.

Nothing here evaluates Sigma correlations, timeframes, aggregations,
or `all of X*` conditions — those require the correlation engine
(P0.2 slice not covered by this reference evaluator).  Rules that
use unsupported features raise UnsupportedSigmaFeature so the
harness records a real FAILED verdict rather than a false PASS.
"""
from __future__ import annotations
import re
from typing import Any


ENGINE_ID = "nivxray::detection_content::nivxray_native_sigma"
ENGINE_ROLE = "DETECTION_ENGINE"


class UnsupportedSigmaFeature(Exception):
    """Raised when a Sigma primitive is outside this evaluator's scope."""


# ── Field-level match ───────────────────────────────────────────

def _match_atom(actual: Any, expected: Any, modifiers: list[str]) -> bool:
    if actual is None:
        return False
    # list of expected values → OR semantics
    if isinstance(expected, list):
        return any(_match_atom(actual, v, modifiers) for v in expected)
    a = str(actual)
    e = str(expected)
    if not modifiers:
        return a.lower() == e.lower()
    for m in modifiers:
        m = m.lower()
        if m == "contains":
            if e.lower() in a.lower(): return True
        elif m == "startswith":
            if a.lower().startswith(e.lower()): return True
        elif m == "endswith":
            if a.lower().endswith(e.lower()): return True
        elif m == "re":
            try:
                if re.search(e, a): return True
            except re.error:
                return False
        elif m == "all":
            # 'all' is handled at the selection level, not here.
            continue
        else:
            raise UnsupportedSigmaFeature(f"modifier '{m}' not supported")
    return False


def _eval_selection(sel: dict, evidence: dict) -> bool:
    """
    A Sigma `selection` is a dict of {field[|mod...]: value|list}.
    All keys must match (AND semantics), each key OR-across-list.
    A key with '|all' modifier requires all list values to match.
    """
    for key, expected in sel.items():
        parts = str(key).split("|")
        field, modifiers = parts[0], parts[1:]
        actual = evidence.get(field)
        if "all" in [m.lower() for m in modifiers] and isinstance(expected, list):
            others = [m for m in modifiers if m.lower() != "all"]
            ok = all(_match_atom(actual, v, others) for v in expected)
        else:
            ok = _match_atom(actual, expected, modifiers)
        if not ok:
            return False
    return True


# ── Condition parsing (tiny deterministic parser) ────────────────

_TOKEN = re.compile(r"\s*(\bnot\b|\band\b|\bor\b|\(|\)|[A-Za-z0-9_]+)\s*",
                          re.IGNORECASE)


def _tokenize(cond: str) -> list[str]:
    out = []
    i = 0
    while i < len(cond):
        m = _TOKEN.match(cond, i)
        if not m:
            raise UnsupportedSigmaFeature(f"cannot tokenize condition near: {cond[i:i+20]!r}")
        tok = m.group(1)
        out.append(tok.lower() if tok.lower() in ("and", "or", "not") else tok)
        i = m.end()
    return out


def _eval_condition(cond: str, evaluated: dict[str, bool]) -> bool:
    """
    Support:
      - single selection name
      - not selection
      - a and b
      - a or b
      - parentheses
    Anything else → UnsupportedSigmaFeature.
    """
    tokens = _tokenize(cond)
    if not tokens:
        raise UnsupportedSigmaFeature("empty condition")

    def parse(pos: int):
        # Pratt-ish tiny parser: atom (and|or atom)*
        def atom(pos: int):
            t = tokens[pos]
            if t == "(":
                v, pos = parse(pos + 1)
                if pos >= len(tokens) or tokens[pos] != ")":
                    raise UnsupportedSigmaFeature("unbalanced parens")
                return v, pos + 1
            if t == "not":
                v, pos = atom(pos + 1)
                return (not v), pos
            if t in ("and", "or", ")"):
                raise UnsupportedSigmaFeature(f"unexpected token {t!r}")
            if t not in evaluated:
                if "*" in t:
                    raise UnsupportedSigmaFeature(f"wildcard identifier '{t}' not supported")
                raise UnsupportedSigmaFeature(f"unknown selection identifier {t!r}")
            return evaluated[t], pos + 1

        left, pos = atom(pos)
        while pos < len(tokens) and tokens[pos] in ("and", "or"):
            op = tokens[pos]; pos += 1
            right, pos = atom(pos)
            left = (left and right) if op == "and" else (left or right)
        return left, pos

    value, end = parse(0)
    if end != len(tokens):
        raise UnsupportedSigmaFeature(
            f"trailing tokens in condition: {tokens[end:]}")
    return value


# ── Top-level evaluate() ─────────────────────────────────────────

def evaluate(rule, evidence: dict) -> bool:
    """
    Deterministic Sigma-subset evaluator.

    `rule` is a pySigma SigmaRule.  We access .detection.detections
    (a dict of selection_name → SigmaDetection) and the parsed
    condition string.

    Any unsupported Sigma primitive raises UnsupportedSigmaFeature —
    the harness treats the resulting exception as a real FAILED
    verdict, preserving honesty over silent false-positives.
    """
    if rule is None:
        raise UnsupportedSigmaFeature("no rule provided")
    detection = getattr(rule, "detection", None)
    if detection is None:
        raise UnsupportedSigmaFeature("rule has no detection section")

    # Convert each SigmaDetection back into a plain dict we can match.
    evaluated: dict[str, bool] = {}
    selections_raw = getattr(detection, "detections", {}) or {}
    for name, sd in selections_raw.items():
        # Build a plain-dict selection from pysigma's parsed items.
        plain: dict = {}
        for atom in getattr(sd, "detection_items", []):
            fld = getattr(atom, "field", None)
            mods_raw = getattr(atom, "modifiers", []) or []
            mods = []
            for m in mods_raw:
                nm = m.__name__ if isinstance(m, type) else type(m).__name__
                nm = nm.lower()
                for pfx in ("sigmastring", "sigma"):
                    if nm.startswith(pfx):
                        nm = nm[len(pfx):]; break
                if nm.endswith("modifier"):
                    nm = nm[:-len("modifier")]
                mods.append(nm)
            vals_obj = getattr(atom, "value", None)
            def _to_lit(v):
                if hasattr(v, "to_plain"):
                    s = v.to_plain()
                else:
                    s = getattr(v, "original_value", None) or str(v)
                s = str(s)
                # pysigma normalizes |contains / |startswith / |endswith by
                # baking '*' into the SigmaString.  Since we apply those
                # modifiers explicitly, strip the redundant wildcards.
                return s.strip("*")
            if isinstance(vals_obj, list):
                vals = [_to_lit(v) for v in vals_obj]
                if len(vals) == 1: vals = vals[0]
            else:
                vals = _to_lit(vals_obj)
            if fld is None:
                raise UnsupportedSigmaFeature(
                    "keyword-style selection without a field is not supported")
            key = fld + ("|" + "|".join(mods) if mods else "")
            plain[key] = vals
        evaluated[str(name)] = _eval_selection(plain, evidence)

    # Condition string
    condition_raw = None
    parsed_conds = getattr(detection, "parsed_condition", None) or \
                        getattr(detection, "condition", None)
    if isinstance(parsed_conds, list) and parsed_conds:
        # pySigma stores conditions as list; take the first canonical.
        first = parsed_conds[0]
        condition_raw = getattr(first, "condition", first)
    else:
        condition_raw = parsed_conds
    if condition_raw is None:
        raise UnsupportedSigmaFeature("rule has no condition")

    return _eval_condition(str(condition_raw), evaluated)
