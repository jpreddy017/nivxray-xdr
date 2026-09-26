"""Deterministic PowerShell constant folder.

Peels the surface-level obfuscation tricks operators use to hide
API/class/cmdlet identifiers from grep-based detection *before* the
artifact extractor runs.  No AI, no execution, pure text transforms.

Handled tricks (in order of application):

  1. Backtick escape removal          `S`ys`tem`  → `System`
  2. Case normalization is DELIBERATE not applied — the extractor
     already handles case-insensitive matching, and lowercasing would
     lose forensic fidelity.
  3. String-concatenation folding      'S'+'ys'+'tem' → 'System'
  4. Format-operator folding           '{0}{1}' -f 'Sys','tem' → 'System'
  5. Variable-alias folding            single-shot Set-Variable /
                                        Set-Item Variable:X 'literal'
                                        substitutions where the value
                                        is a *literal* string.

Rule of thumb:  every transformation is 100% syntactic.  We NEVER
execute PowerShell, NEVER call an external interpreter, NEVER guess.
If a fold is ambiguous we leave the original text alone.

Output shape:

    NormalizedText(
        text:            <folded text>,
        transformations: [{"kind": "concat", "before": "...", "after": "..."}, ...],
    )
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


# ─── Regexes (compiled once) ──────────────────────────────────────────
# String-concat chain of 2+ quoted literals joined by `+`.
# Allows optional whitespace around `+`.  Supports both single and
# double quotes.  The literals themselves may contain any char except
# the enclosing quote (no escapes inside — a rare enough tradeoff to
# be worth the simplicity).
_CONCAT_RE = re.compile(
    r"""
    (                                 # capture the whole chain
      (?:'[^']*'|"[^"]*")             # first quoted literal
      (?:\s*\+\s*                     # …joined by +…
         (?:'[^']*'|"[^"]*")          # …to another literal
      )+                              # (repeat at least once)
    )
    """,
    re.VERBOSE,
)

# Format-operator chain:  '<template>' -f <arg1>, <arg2>, ...
# We only fold when every arg is a plain quoted literal.  Anything else
# (variable, sub-expression, function call) is left alone.
_FORMAT_RE = re.compile(
    r"""
    (?P<tmpl>'[^']*'|"[^"]*")         # template
    \s*-f\s*
    (?P<args>
      (?:'[^']*'|"[^"]*")             # first arg
      (?:\s*,\s*(?:'[^']*'|"[^"]*"))* # further args
    )
    """,
    re.VERBOSE,
)

# Backtick escape — PowerShell's line-continuation / literal-escape
# operator.  Inside a normal identifier we can safely drop them.
_BACKTICK_RE = re.compile(r"`(?=[A-Za-z0-9_])")

# Set-Variable / Set-Item Variable:X 'literal'  (single-shot alias assign)
_SET_ALIAS_RE = re.compile(
    r"""
    (?:Set-Variable|Set-Item)\s+
    (?:Variable:)?
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)   # variable name
    \s+
    (?:-Value\s+)?
    (?P<value>'[^']*'|"[^"]*")         # LITERAL value only
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass
class NormalizedText:
    text: str
    transformations: List[Dict[str, Any]] = field(default_factory=list)


# ─── Individual folders ───────────────────────────────────────────────
def _fold_backticks(text: str, out: List[Dict[str, Any]]) -> str:
    """Drop backticks that only obfuscate an identifier."""
    if "`" not in text:
        return text
    new = _BACKTICK_RE.sub("", text)
    if new != text:
        out.append({"kind": "backtick_strip",
                    "removed_count": text.count("`") - new.count("`")})
    return new


def _fold_concat(text: str, out: List[Dict[str, Any]]) -> str:
    """Fold 'a'+'b'+'c' → 'abc'.  Preserves the outer quote style of
    the FIRST literal in the chain."""
    def _replace(m: "re.Match[str]") -> str:
        chain = m.group(1)
        parts = re.findall(r"'([^']*)'|\"([^\"]*)\"", chain)
        merged = "".join(a or b for (a, b) in parts)
        # Preserve original outer quote style
        outer_q = "'" if chain.lstrip()[:1] == "'" else "\""
        replacement = f"{outer_q}{merged}{outer_q}"
        out.append({"kind": "concat", "before": chain, "after": replacement})
        return replacement
    # We iterate to fold nested / composed chains (rare but harmless).
    for _ in range(5):
        new = _CONCAT_RE.sub(_replace, text)
        if new == text:
            break
        text = new
    return text


def _fold_format(text: str, out: List[Dict[str, Any]]) -> str:
    """Fold  '{0}{1}' -f 'Sys','tem'  →  'System'  when every arg is a literal."""
    def _replace(m: "re.Match[str]") -> str:
        tmpl_raw = m.group("tmpl")
        args_raw = m.group("args")
        # Strip outer quotes on template
        tmpl = tmpl_raw[1:-1]
        # Extract literal args (only quoted; refuse if any arg is a variable / expression)
        arg_lits = re.findall(r"'([^']*)'|\"([^\"]*)\"", args_raw)
        # If the arg list contains anything that ISN'T a quoted literal, we
        # can't safely fold.  Compare arg count in the string vs matched.
        approx_arg_count = len(re.findall(r",", args_raw)) + 1
        if len(arg_lits) != approx_arg_count:
            return m.group(0)   # bail — non-literal argument
        args = [a or b for (a, b) in arg_lits]
        try:
            folded = tmpl.format(*args)
        except (IndexError, KeyError, ValueError):
            return m.group(0)
        outer_q = tmpl_raw[0]
        replacement = f"{outer_q}{folded}{outer_q}"
        out.append({"kind": "format", "before": m.group(0), "after": replacement})
        return replacement
    return _FORMAT_RE.sub(_replace, text)


def _fold_alias(text: str, out: List[Dict[str, Any]]) -> str:
    """Substitute the SINGLE literal value into every subsequent
    ``$name`` / ``${name}`` reference in the text.

    Deliberately conservative: only kicks in when there is exactly ONE
    ``Set-Variable`` / ``Set-Item Variable:X 'literal'`` assignment for
    a given name in the input.  Multi-assign or non-literal cases are
    left alone.
    """
    assigns: Dict[str, str] = {}
    dupes: set = set()
    for m in _SET_ALIAS_RE.finditer(text):
        name = m.group("name")
        val = m.group("value")[1:-1]   # strip surrounding quotes
        if name in assigns and assigns[name] != val:
            dupes.add(name)
        assigns.setdefault(name, val)
    # Drop ambiguous multi-value assigns
    for d in dupes:
        assigns.pop(d, None)
    if not assigns:
        return text
    new = text
    for name, val in assigns.items():
        # ${OB} or $OB — replace with the literal value.  We DELIBERATELY
        # do not remove the original Set-Variable / Set-Item line so the
        # analyst still sees the operator's obfuscation attempt.
        pat = re.compile(r"\$\{?" + re.escape(name) + r"\}?\b")
        new2, count = pat.subn(f'"{val}"', new)
        if count > 0:
            out.append({"kind": "alias_expand", "name": name,
                        "value": val, "replacements": count})
            new = new2
    return new


# ─── Public entry point ───────────────────────────────────────────────
def fold(text: str) -> NormalizedText:
    """Apply every deterministic folder in the canonical order.

    Idempotent: calling ``fold`` on already-folded text yields the same
    string with an empty ``transformations`` list.
    """
    transforms: List[Dict[str, Any]] = []
    if not isinstance(text, str) or not text:
        return NormalizedText(text=text or "", transformations=transforms)
    t = text
    t = _fold_backticks(t, transforms)
    # Two-pass concat/format — folding a format operator can expose a
    # new concat chain and vice versa.
    for _ in range(3):
        prev = t
        t = _fold_concat(t, transforms)
        t = _fold_format(t, transforms)
        if t == prev:
            break
    t = _fold_alias(t, transforms)
    # One last concat pass in case alias expansion created a new chain.
    t = _fold_concat(t, transforms)
    return NormalizedText(text=t, transformations=transforms)


def fold_text(text: str) -> str:
    """Convenience wrapper — returns just the folded text.  Use this
    where you don't need the transformation trail."""
    return fold(text).text
