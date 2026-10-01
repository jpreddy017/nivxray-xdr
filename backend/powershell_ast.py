"""NivXRay — PowerShell AST-lite deobfuscator.

Not a full PowerShell parser — a pattern-based mini-AST that resolves the
handful of obfuscator tricks analysts see 95% of the time:

    $a = "I"; $b = "EX"; $a + $b          → IEX
    'i' + 'e' + 'x'                       → iex
    "{0}{1}{2}" -f 'I','E','X'            → IEX
    ('IZEZX').Replace('Z','')             → IEX
    [char]73 + [char]69 + [char]88        → IEX
    i`e`x                                 → iex (backtick escapes)
    InVOkE-eXpReSsION                     → Invoke-Expression (case-norm keyword)

Runs as a post-decode polish step in `command_analyzer`. Every transformation
performed is captured in `transformations` so analysts can trace what changed.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# Transformation record
# =============================================================================
@dataclass
class Transformation:
    kind: str                                                # what we did
    before: str
    after: str
    detail: str = ""
    # R-2 · `complete=False` means the rule fired but could not fully evaluate
    # the construct (e.g. a concat run that hit a non-string operand).
    complete: bool = True


# Transformation kinds that are COSMETIC — they change spelling, not meaning.
# R-2: these must never, on their own, make the engine claim a recovery.
COSMETIC_KINDS = frozenset({"case-normalization"})


# =============================================================================
# 1. Backtick removal ($a`b → $ab)
# =============================================================================
_BACKTICK_ESC_RE = re.compile(r"`([A-Za-z0-9])")


def _strip_backticks(text: str, out: List[Transformation]) -> str:
    if "`" not in text:
        return text
    new = _BACKTICK_ESC_RE.sub(r"\1", text)
    if new != text:
        out.append(Transformation(
            kind="backtick-escape",
            before=text[:120] + ("…" if len(text) > 120 else ""),
            after=new[:120] + ("…" if len(new) > 120 else ""),
            detail="Stripped inline backtick escapes",
        ))
    return new


# =============================================================================
# 2. Char-code substitution — [char]73 → 'I'
# =============================================================================
_CHAR_CODE_RE = re.compile(r"\[char\]\s*(\d{1,3})", re.I)


def _resolve_char_codes(text: str, out: List[Transformation]) -> str:
    def _sub(m):
        n = int(m.group(1))
        if 0 <= n <= 255:
            ch = chr(n)
            return "'" + (ch if ch != "'" else "''") + "'"
        return m.group(0)
    new = _CHAR_CODE_RE.sub(_sub, text)
    if new != text:
        cnt = len(_CHAR_CODE_RE.findall(text))
        out.append(Transformation(
            kind="char-code",
            before=text[:120] + ("…" if len(text) > 120 else ""),
            after=new[:120] + ("…" if len(new) > 120 else ""),
            detail=f"Substituted {cnt} [char]NNN literal(s)",
        ))
    return new


# =============================================================================
# 3. String concatenation — 'i' + 'e' + 'x' → 'iex'
# =============================================================================
_STR_LIT = r"""(?:'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")"""
_CONCAT_RE = re.compile(rf"({_STR_LIT})(?:\s*\+\s*({_STR_LIT}))+")

# R-2 · a `+` operand that is NOT a string literal. The folding rule above
# cannot evaluate these, so they are recorded as UNRESOLVED rather than being
# silently emitted as source text inside a "decoded" artifact.
_NON_STR_OPERAND = (
    r"""(?:\$[A-Za-z_][A-Za-z0-9_:]*"""                     # $var / $env:x
    r"""|\[[^\]\n]{1,48}\](?:::)?[A-Za-z0-9_.]*(?:\([^()\n]{0,120}\))?"""  # [Type]::Member(...)
    r"""|\d+"""                                             # bare number
    r"""|[A-Za-z_][A-Za-z0-9_.-]*\s*\([^()\n]{0,120}\))"""  # call(...)
)
_UNRESOLVED_CONCAT_RE = re.compile(
    rf"(?:{_STR_LIT}\s*\+\s*{_NON_STR_OPERAND})"
    rf"|(?:{_NON_STR_OPERAND}\s*\+\s*{_STR_LIT})"
)


def _unquote(lit: str) -> str:
    if len(lit) >= 2 and lit[0] == lit[-1] and lit[0] in ("'", '"'):
        body = lit[1:-1]
        # PowerShell '' inside single-quoted string escapes a single quote
        if lit[0] == "'":
            return body.replace("''", "'")
        # inside double-quoted: unescape \" and \\
        return body.replace('\\"', '"').replace("\\\\", "\\")
    return lit


def _requote(s: str) -> str:
    # Prefer single quotes unless the string contains a single quote
    if "'" not in s:
        return "'" + s + "'"
    return '"' + s.replace('"', '\\"') + '"'


def _collapse_string_concat(text: str, out: List[Transformation]) -> str:
    def _sub(m):
        lits = re.findall(_STR_LIT, m.group(0))
        joined = "".join(_unquote(l) for l in lits)
        return _requote(joined)
    new = _CONCAT_RE.sub(_sub, text)
    if new != text:
        # R-2 · honesty. This rule folds runs of ADJACENT STRING LITERALS only.
        # A `+` whose operand is a number / variable / cast / call terminates the
        # run and is emitted verbatim. Say so instead of claiming a full fold.
        residual = len(_UNRESOLVED_CONCAT_RE.findall(new))
        detail = "Collapsed adjacent string-literal concatenations"
        if residual:
            detail += (f" — PARTIAL: {residual} concatenation(s) still have a "
                       f"non-string operand and were NOT evaluated")
        out.append(Transformation(
            kind="string-concat",
            before=text[:200] + ("…" if len(text) > 200 else ""),
            after=new[:200] + ("…" if len(new) > 200 else ""),
            detail=detail,
            complete=residual == 0,
        ))
    return new


# =============================================================================
# 4. Format-string obfuscation — "{0}{2}{1}" -f 'a','b','c' → 'acb'
# =============================================================================
_FMT_RE = re.compile(
    rf"({_STR_LIT})\s*-f\s*((?:{_STR_LIT})(?:\s*,\s*{_STR_LIT})*)",
    re.I,
)


def _resolve_format_strings(text: str, out: List[Transformation]) -> str:
    def _sub(m):
        fmt = _unquote(m.group(1))
        args_raw = m.group(2)
        args = [_unquote(x) for x in re.findall(_STR_LIT, args_raw)]
        try:
            # {N} placeholders → args[N]
            def _fill(mm):
                idx = int(mm.group(1))
                return args[idx] if 0 <= idx < len(args) else mm.group(0)
            resolved = re.sub(r"\{(\d+)\}", _fill, fmt)
            return _requote(resolved)
        except Exception:
            return m.group(0)
    new = _FMT_RE.sub(_sub, text)
    if new != text:
        out.append(Transformation(
            kind="format-string",
            before=text[:200] + ("…" if len(text) > 200 else ""),
            after=new[:200] + ("…" if len(new) > 200 else ""),
            detail='Resolved "{N}{N}" -f arg,arg,… format-string obfuscation',
        ))
    return new


# =============================================================================
# 5. .Replace() char-substitution — ('IZEZX').Replace('Z','') → 'IEX'
# =============================================================================
_REPLACE_RE = re.compile(
    rf"""\(?\s*({_STR_LIT})\s*\)?\s*\.\s*[Rr]eplace\s*\(\s*({_STR_LIT})\s*,\s*({_STR_LIT})\s*\)""",
    re.I,
)


def _apply_replace_calls(text: str, out: List[Transformation]) -> str:
    changed = True
    passes = 0
    while changed and passes < 5:
        changed = False
        passes += 1

        def _sub(m):
            nonlocal changed
            s   = _unquote(m.group(1))
            src = _unquote(m.group(2))
            dst = _unquote(m.group(3))
            if not src:
                return m.group(0)
            new_s = s.replace(src, dst)
            changed = True
            return _requote(new_s)

        new = _REPLACE_RE.sub(_sub, text)
        if new == text:
            break
        text = new
    if changed or passes > 1:
        out.append(Transformation(
            kind="replace-call",
            before="", after=text[:200] + ("…" if len(text) > 200 else ""),
            detail=f"Applied .Replace(src,dst) transforms ({passes} pass(es))",
        ))
    return text


# =============================================================================
# 6. Variable assignment tracking — $a = "…"; … $a → substitute
# =============================================================================
# Match `$name = "…"` or `$name = '…'` — assignments only on their own line/stmt.
# Explicitly excludes `$env:XXX` / `$script:XXX` / `$global:XXX` — those are
# scoped variable references, not user-defined bindings, and must be handled by
# `env-expand` (for env:) or left untouched (for scope-qualified vars).
_VAR_ASSIGN_RE = re.compile(
    rf"""(?:^|[\s;{{]) *(\$(?!(?:env|script|global|local|private|using):)
                          [A-Za-z_][A-Za-z0-9_]*)\s*=\s*({_STR_LIT})\s*
                          (?=$|[;|\n\r}}])""",
    re.M | re.X | re.I,
)
# Variable *usage* — same exclusion. Only replace ones NOT immediately followed
# by `=` (that'd be a fresh assignment).
_VAR_USAGE_RE = re.compile(
    r"(?<!\$)(\$(?!(?:env|script|global|local|private|using):)"
    r"[A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_=])",
    re.I,
)


def _substitute_variables(text: str, out: List[Transformation]) -> Tuple[str, Dict[str, str]]:
    bindings: Dict[str, str] = {}
    for m in _VAR_ASSIGN_RE.finditer(text):
        name = m.group(1)
        val = _unquote(m.group(2))
        # First assignment wins — closest-to-usage isn't tracked in a mini-AST.
        # (Real deobfuscation would scope this per-line, but the common case is
        # top-of-script assignments used everywhere downstream.)
        bindings.setdefault(name, val)
    if not bindings:
        return text, {}

    def _replace(m):
        name = m.group(1)
        return _requote(bindings[name]) if name in bindings else m.group(0)

    # Replace usages *outside* string literals — otherwise `"($var)"` would
    # be corrupted. We do a two-pass: (a) split on strings, (b) apply on
    # non-string chunks only.
    parts = re.split(f"({_STR_LIT})", text)
    for i, chunk in enumerate(parts):
        if i % 2 == 1:                                      # inside a string literal
            continue
        parts[i] = _VAR_USAGE_RE.sub(_replace, chunk)
    new = "".join(parts)
    if new != text:
        out.append(Transformation(
            kind="variable-substitution",
            before=text[:200] + ("…" if len(text) > 200 else ""),
            after=new[:200] + ("…" if len(new) > 200 else ""),
            detail=f"Resolved {len(bindings)} variable binding(s): "
                   f"{', '.join(f'{k}={v[:20]!r}' for k, v in list(bindings.items())[:6])}",
        ))
    return new, bindings


# =============================================================================
# 7. Case normalization for known cmdlets — helps signature matching later.
# =============================================================================
_KEYWORDS = [
    "Invoke-Expression", "IEX", "Invoke-Command", "iCM",
    "Invoke-WebRequest", "IWR", "Invoke-RestMethod", "IRM",
    "New-Object", "Get-Content", "Set-Content", "Add-Content",
    "DownloadString", "DownloadData", "DownloadFile",
    "FromBase64String", "ConvertTo-SecureString", "ConvertFrom-SecureString",
    "System.Management.Automation.AmsiUtils", "AmsiScanBuffer", "AmsiInitFailed",
    "System.Reflection.Assembly", "GetType", "SetValue",
    "Start-Process", "Start-BitsTransfer",
    "Register-ScheduledTask", "New-Service", "schtasks",
    "Convert.FromBase64String", "System.Convert",
    "WScript.Shell", "Shell.Application",
]


def _normalize_case(text: str, out: List[Transformation]) -> str:
    new = text
    hits = []
    for kw in _KEYWORDS:
        # Regex match ignoring case, replace with canonical spelling
        pat = re.compile(re.escape(kw), re.I)
        new2, n = pat.subn(kw, new)
        if n:
            hits.append(f"{kw} ({n}×)")
            new = new2
    if hits:
        out.append(Transformation(
            kind="case-normalization",
            before="", after=new[:200] + ("…" if len(new) > 200 else ""),
            detail=f"Case-normalised keywords: {', '.join(hits[:6])}",
        ))
    return new


# =============================================================================
# R-2 · Unresolved-expression reporting
#
# The engine must be able to say "this construct exists and I did NOT evaluate
# it". Without that, a partial fold is indistinguishable from a full recovery.
# =============================================================================
_VAR_REF_RE = re.compile(
    r"(?<!\$)\$(?!(?:env|script|global|local|private|using):)"
    r"([A-Za-z_][A-Za-z0-9_]*)"
)

# Constructs whose operand is a VARIABLE or an expression — not a literal —
# so the corresponding rewrite rule cannot fire at all.
_UNSUPPORTED_PATTERNS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("dynamic-base64",
     re.compile(r"(?:\[[\w.]*Convert\]|\bConvert)::FromBase64String\s*\(\s*[^'\")]", re.I),
     "[Convert]::FromBase64String() applied to an expression, not a literal"),
    ("dynamic-scriptblock",
     re.compile(r"\[\s*ScriptBlock\s*\]::Create\s*\(\s*[^'\")]", re.I),
     "[ScriptBlock]::Create() built from an expression — target code is dynamic"),
    ("dynamic-encoding-getstring",
     re.compile(r"\[\s*(?:System\.)?Text\.Encoding\s*\]::\w+\.GetString\s*\(", re.I),
     "Text.Encoding::GetString() over a byte expression"),
    ("dynamic-join",
     re.compile(r"-join\s*(?:\(|\$)", re.I),
     "-join over an expression, not a literal array"),
    ("dynamic-format",
     re.compile(rf"{_STR_LIT}\s*-f\s*(?:\$|\()", re.I),
     "-f format string with non-literal arguments"),
    ("dynamic-replace",
     re.compile(r"\$\w+\s*\.\s*[Rr]eplace\s*\(", re.I),
     ".Replace() on a variable receiver"),
    ("dynamic-substring",
     re.compile(r"\.\s*(?:Substring|ToCharArray|Split|Trim)\s*\(", re.I),
     "string method over a non-literal receiver"),
    ("dynamic-xor",
     re.compile(r"-bxor\s*\$", re.I),
     "-bxor with a variable key"),
    ("dynamic-invoke",
     re.compile(r"(?:\bIEX\b|\bInvoke-Expression\b|\bInvoke-Command\b)[^\n]{0,40}\$", re.I),
     "invocation of a variable-held program"),
]


def _snip(text: str, start: int, end: int, pad: int = 12) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b].replace("\n", " ⏎ ")
    return (("…" if a else "") + s + ("…" if b < len(text) else "")).strip()


def find_unresolved(text: str,
                    bindings: Optional[Dict[str, str]] = None
                    ) -> List[Dict[str, Any]]:
    """Enumerate PowerShell constructs this engine provably did NOT evaluate.

    Returned entries are the R-2 `unresolved_expressions[]` contract. While this
    list is non-empty the decode status may never be `RECOVERED`.
    """
    if not text:
        return []
    bindings = bindings or {}
    found: List[Dict[str, Any]] = []
    seen: set = set()

    def _add(kind: str, expr: str, offset: int, reason: str):
        key = (kind, expr)
        if key in seen:
            return
        seen.add(key)
        found.append({"kind": kind, "expression": expr[:200],
                      "offset": offset, "reason": reason})

    for m in _UNRESOLVED_CONCAT_RE.finditer(text):
        _add("non-string-concat-operand", m.group(0), m.start(),
             "Concatenation operand is not a string literal; .NET `+` coercion "
             "was not evaluated, so the operator text survives verbatim")

    assigned = {m.group(1) for m in _VAR_ASSIGN_RE.finditer(text)}
    bound = {k.lstrip("$") for k in bindings}
    for m in _VAR_REF_RE.finditer(text):
        name = m.group(1)
        if name in bound:
            continue
        # `$x =` on this very match is an assignment, not an unresolved read.
        tail = text[m.end():m.end() + 3]
        if tail.lstrip().startswith("=") and not tail.lstrip().startswith("=="):
            continue
        why = ("variable is assigned from an expression this engine cannot "
               "evaluate" if ("$" + name) in assigned or name in
               {a.lstrip("$") for a in assigned}
               else "variable has no recoverable assignment in the observed text")
        _add("unbound-variable", "$" + name, m.start(), why)

    for kind, pat, reason in _UNSUPPORTED_PATTERNS:
        for m in pat.finditer(text):
            _add(kind, _snip(text, m.start(), m.end()), m.start(), reason)

    found.sort(key=lambda f: f["offset"])
    return found


# =============================================================================
# Public entry
# =============================================================================
def deobfuscate_ps(text: str, max_passes: int = 3) -> Dict[str, Any]:
    """Deobfuscate a PowerShell command using pattern-based AST rules.

    Runs multiple passes so that each transformation can feed the next
    (variable substitution reveals a new string concat, which reveals a new
    format-string, etc.). Stops when no further changes are produced.
    """
    if not text:
        return {"output": text, "transformations": [], "bindings": {},
                "unresolved": [], "semantic_transformations": 0,
                "incomplete_transformations": 0}
    out: List[Transformation] = []
    bindings: Dict[str, str] = {}
    current = text
    for _ in range(max_passes):
        before = current
        current = _strip_backticks(current, out)
        current = _resolve_char_codes(current, out)
        current, b = _substitute_variables(current, out)
        bindings.update(b)
        current = _collapse_string_concat(current, out)
        current = _resolve_format_strings(current, out)
        current = _apply_replace_calls(current, out)
        if current == before:
            break
    current = _normalize_case(current, out)
    semantic = [t for t in out if t.kind not in COSMETIC_KINDS]
    return {
        "output": current,
        "transformations": [t.__dict__ for t in out],
        "bindings": bindings,
        # R-2 · honest reporting surface
        "unresolved": find_unresolved(current, bindings),
        "semantic_transformations": len(semantic),
        "incomplete_transformations": len([t for t in out if not t.complete]),
    }
