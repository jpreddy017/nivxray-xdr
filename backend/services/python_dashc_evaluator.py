"""Python `-c` deterministic evaluator plugin  · Rule 22 Category C
=====================================================================

Reusable interpreter capability: recover the stdout of ``python -c
"…"`` invocations when the expression is a deterministic string /
byte transformation.

Interpreter Ownership (Rule 19): fires ONLY when the raw input
positively identifies the Python interpreter (``python``, ``python3``,
``py``, ``python3.x``, or a shebang).

Safety contract (READ CAREFULLY):
- Uses ``ast.parse`` + a **strict AST whitelist walker**.
- REJECTS: imports, attribute access outside a whitelist, subscript
  assignment, subprocess/os/socket/eval/exec, function/class defs,
  loops (except comprehension), yield, global, with, try/except,
  del, raise, async, walrus, augmented assign.
- ACCEPTS: constants (str/bytes/int/float/bool/None), simple names
  bound to whitelisted builtins/stdlib, binary/unary/bool/compare
  ops, comprehensions (list/set/dict/generator), joined strings
  (f-strings), tuple/list/dict/set literals, subscript reads,
  slicing, `Attribute` reads only for whitelisted stdlib modules
  (base64 / binascii / codecs / zlib / gzip).
- No eval, no exec, no subprocess. Every allowed function is a
  Python builtin or a whitelisted stdlib helper.

Coverage (what this plugin can safely simulate):
- String / byte comprehensions: ``''.join(chr(ord(c) ^ K) for c in 'abc')``
- Base conversions: ``bytes.fromhex(…)``, ``bytes(…).hex()``
- Base64 / base32 / base16 (via `base64.*` module)
- Hex un/hexlify (via `binascii.*`)
- Zlib / gzip decompress (via `zlib.*` / `gzip.*`)
- codecs.decode / codecs.encode
- Character arithmetic (chr/ord/int/hex/bin/oct)
- String concat via + / * / join / format / f-string

The plugin returns the printed stdout — i.e. the *actual value*
produced by the deterministic expression, which is what the next
pipeline stage (e.g. `| bash`) would consume at runtime.
"""
from __future__ import annotations
import ast
import base64 as _b64
import binascii
import codecs
import gzip
import io
import re
import zlib
from typing import Any, Dict, Optional


# ─── Positive interpreter identification ────────────────────────────────
_PY_HOST_RE = re.compile(
    r"""(?ix)
    ^\s*
    (?:python(?:3(?:\.\d+)?)?|py)   # python / python3 / python3.11 / py
    \s+
    (?:-[a-zA-Z0-9]\s+)*             # tolerated flags before -c
    -c\s+
    (?P<quote>['"])
    (?P<code>.+?)
    (?P=quote)
    \s*
    (?P<tail>(?:\|.*)?)
    \s*$
    """,
    re.DOTALL,
)


# ─── Whitelisted names ──────────────────────────────────────────────────
_ALLOWED_BUILTINS: Dict[str, Any] = {
    "chr":       chr,
    "ord":       ord,
    "len":       len,
    "print":     print,
    "str":       str,
    "bytes":     bytes,
    "bytearray": bytearray,
    "int":       int,
    "float":     float,
    "bool":      bool,
    "hex":       hex,
    "bin":       bin,
    "oct":       oct,
    "list":      list,
    "tuple":     tuple,
    "set":       set,
    "dict":      dict,
    "frozenset": frozenset,
    "range":     range,
    "sum":       sum,
    "min":       min,
    "max":       max,
    "abs":       abs,
    "sorted":    sorted,
    "reversed":  reversed,
    "map":       map,
    "filter":    filter,
    "enumerate": enumerate,
    "zip":       zip,
    "round":     round,
    "True":      True,
    "False":     False,
    "None":      None,
}

_ALLOWED_MODULES: Dict[str, Any] = {
    "base64":   _b64,
    "binascii": binascii,
    "codecs":   codecs,
    "zlib":     zlib,
    "gzip":     gzip,
}

_ALLOWED_MODULE_ATTRS: Dict[str, set] = {
    "base64":   {"b64encode", "b64decode", "b32encode", "b32decode",
                  "b16encode", "b16decode", "urlsafe_b64encode",
                  "urlsafe_b64decode", "a85encode", "a85decode"},
    "binascii": {"hexlify", "unhexlify", "a2b_base64", "b2a_base64",
                  "a2b_hex", "b2a_hex"},
    "codecs":   {"decode", "encode"},
    "zlib":     {"decompress", "compress"},
    "gzip":     {"decompress", "compress"},
}

_ALLOWED_STR_METHODS = {
    "join", "split", "replace", "strip", "lstrip", "rstrip",
    "lower", "upper", "swapcase", "title", "startswith",
    "endswith", "encode", "decode", "format", "count", "find",
    "rfind", "index", "rindex", "zfill", "translate", "maketrans",
    "isalpha", "isdigit", "isalnum", "isascii", "isspace",
}
_ALLOWED_BYTES_METHODS = _ALLOWED_STR_METHODS | {"fromhex", "hex"}


# ─── Safe AST evaluator ─────────────────────────────────────────────────
class _PythonEvalError(RuntimeError):
    pass


class _SafeEvaluator(ast.NodeVisitor):
    def __init__(self):
        self.env = dict(_ALLOWED_BUILTINS)
        self.env.update(_ALLOWED_MODULES)
        self.stdout = io.StringIO()

    def _forbidden(self, node):
        raise _PythonEvalError(f"forbidden node: {type(node).__name__}")

    # ── program entry
    def run(self, source: str) -> str:
        tree = ast.parse(source, mode="exec")
        for stmt in tree.body:
            self._exec(stmt)
        return self.stdout.getvalue().rstrip("\n")

    def _exec(self, node):
        if isinstance(node, ast.Expr):
            # Bare expressions — evaluate for side effects (e.g. print()).
            self._eval(node.value)
        elif isinstance(node, ast.Assign):
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                self._forbidden(node)
            value = self._eval(node.value)
            self.env[node.targets[0].id] = value
        else:
            self._forbidden(node)

    # ── expression evaluator ---------------------------------------------
    def _eval(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            raise _PythonEvalError(f"name not allowed: {node.id!r}")
        if isinstance(node, ast.BinOp):
            L = self._eval(node.left); R = self._eval(node.right)
            op = type(node.op).__name__
            return {
                "Add":  lambda: L + R,
                "Sub":  lambda: L - R,
                "Mult": lambda: L * R,
                "Div":  lambda: L / R,
                "FloorDiv": lambda: L // R,
                "Mod":  lambda: L % R,
                "Pow":  lambda: L ** R,
                "LShift": lambda: L << R,
                "RShift": lambda: L >> R,
                "BitOr":  lambda: L | R,
                "BitXor": lambda: L ^ R,
                "BitAnd": lambda: L & R,
            }.get(op, lambda: self._forbidden(node))()
        if isinstance(node, ast.UnaryOp):
            V = self._eval(node.operand)
            op = type(node.op).__name__
            return {"USub": lambda: -V, "UAdd": lambda: +V,
                    "Not": lambda: not V, "Invert": lambda: ~V}.get(
                        op, lambda: self._forbidden(node))()
        if isinstance(node, ast.Compare):
            left = self._eval(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = self._eval(comparator)
                name = type(op).__name__
                r = {
                    "Eq": left == right, "NotEq": left != right,
                    "Lt": left < right, "LtE": left <= right,
                    "Gt": left > right, "GtE": left >= right,
                    "In": left in right, "NotIn": left not in right,
                    "Is": left is right, "IsNot": left is not right,
                }.get(name)
                if r is None: self._forbidden(op)
                if not r: return False
                left = right
            return True
        if isinstance(node, ast.BoolOp):
            values = [self._eval(v) for v in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
            self._forbidden(node.op)
        if isinstance(node, ast.IfExp):
            return self._eval(node.body) if self._eval(node.test) else self._eval(node.orelse)
        if isinstance(node, ast.JoinedStr):   # f-string
            return "".join(str(self._eval(v)) for v in node.values)
        if isinstance(node, ast.FormattedValue):
            return format(self._eval(node.value),
                          self._eval(node.format_spec) if node.format_spec else "")
        if isinstance(node, ast.Tuple):
            return tuple(self._eval(e) for e in node.elts)
        if isinstance(node, ast.List):
            return [self._eval(e) for e in node.elts]
        if isinstance(node, ast.Set):
            return {self._eval(e) for e in node.elts}
        if isinstance(node, ast.Dict):
            return {self._eval(k): self._eval(v)
                    for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.Subscript):
            v = self._eval(node.value)
            s = self._eval(node.slice) if not isinstance(node.slice, ast.Slice) \
                    else slice(self._eval(node.slice.lower) if node.slice.lower else None,
                               self._eval(node.slice.upper) if node.slice.upper else None,
                               self._eval(node.slice.step)  if node.slice.step  else None)
            return v[s]
        if isinstance(node, ast.Attribute):
            v = self._eval(node.value)
            attr = node.attr
            # Whitelisted stdlib modules
            for mod_name, mod in _ALLOWED_MODULES.items():
                if v is mod:
                    if attr in _ALLOWED_MODULE_ATTRS.get(mod_name, set()):
                        return getattr(mod, attr)
                    raise _PythonEvalError(f"attr not allowed: {mod_name}.{attr}")
            # str / bytes methods
            if isinstance(v, str) and attr in _ALLOWED_STR_METHODS:
                return getattr(v, attr)
            if isinstance(v, (bytes, bytearray)) and attr in _ALLOWED_BYTES_METHODS:
                return getattr(v, attr)
            # class-level bytes.fromhex etc.
            if v is bytes and attr in _ALLOWED_BYTES_METHODS:
                return getattr(bytes, attr)
            if v is str and attr in _ALLOWED_STR_METHODS:
                return getattr(str, attr)
            raise _PythonEvalError(f"attr not allowed: {attr}")
        if isinstance(node, ast.Call):
            func = self._eval(node.func)
            args = [self._eval(a) for a in node.args]
            kwargs = {kw.arg: self._eval(kw.value) for kw in node.keywords}
            # print → capture into stdout buffer
            if func is print:
                sep = kwargs.get("sep", " ")
                end = kwargs.get("end", "\n")
                self.stdout.write(sep.join(str(a) for a in args) + end)
                return None
            # Any other callable coming from the whitelist is safe.
            return func(*args, **kwargs)
        if isinstance(node, (ast.GeneratorExp, ast.ListComp,
                              ast.SetComp, ast.DictComp)):
            return self._comp(node)
        self._forbidden(node)

    def _comp(self, node):
        results = []
        self._iter_generators(node, node.generators, 0, results)
        if isinstance(node, ast.ListComp):     return list(results)
        if isinstance(node, ast.SetComp):      return set(results)
        if isinstance(node, ast.GeneratorExp): return iter(results)
        if isinstance(node, ast.DictComp):     return dict(results)
        return results

    def _iter_generators(self, node, generators, gi, out):
        if gi == len(generators):
            if isinstance(node, ast.DictComp):
                out.append((self._eval(node.key), self._eval(node.value)))
            else:
                out.append(self._eval(node.elt))
            return
        gen = generators[gi]
        iterable = self._eval(gen.iter)
        for item in iterable:
            self._bind(gen.target, item)
            if all(self._eval(f) for f in gen.ifs):
                self._iter_generators(node, generators, gi + 1, out)

    def _bind(self, target, value):
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for t, v in zip(target.elts, value):
                self._bind(t, v)
        else:
            self._forbidden(target)


# ─── Public plugin entry ────────────────────────────────────────────────
def _detect_python_dashc(text: str) -> Optional[Dict[str, Any]]:
    """Return {'code': str, 'tail': str} if the input is a
    ``python -c "…"`` invocation (optionally followed by a pipeline),
    else ``None``."""
    m = _PY_HOST_RE.match(text or "")
    if not m:
        return None
    return {
        "code": m.group("code"),
        "tail": (m.group("tail") or "").strip(),
    }


def try_python_dashc_evaluator(text: str) -> Optional[Dict[str, Any]]:
    """Deterministically evaluate a ``python -c "…"`` expression.

    Returns ``None`` when the pattern doesn't match or the AST is
    outside the whitelist. Callers fall through to the L0 engine.

    Returns on success:
      {"stdout": str, "code": str, "tail": str, "next_stage": str|None}
    ``next_stage`` is populated when the python output is piped into
    another shell (`| bash`, `| sh`) — the analyst can then feed
    stdout into the next stage's decoder if desired.
    """
    hit = _detect_python_dashc(text)
    if hit is None:
        return None
    try:
        ev = _SafeEvaluator()
        stdout = ev.run(hit["code"])
    except _PythonEvalError:
        return None
    except Exception:
        return None
    if stdout is None:
        return None
    next_stage: Optional[str] = None
    tail = hit["tail"]
    if tail:
        m_tail = re.match(r"\|\s*(bash|sh|/bin/(?:ba)?sh|zsh|dash|python\d?)\s*$",
                          tail, re.IGNORECASE)
        if m_tail:
            next_stage = m_tail.group(1).lower()
    return {
        "stdout":     stdout,
        "code":       hit["code"],
        "tail":       tail,
        "next_stage": next_stage,
    }


__all__ = ["try_python_dashc_evaluator", "_SafeEvaluator", "_PythonEvalError"]
