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
        out.append(Transformation(
            kind="string-concat",
            before=text[:200] + ("…" if len(text) > 200 else ""),
            after=new[:200] + ("…" if len(new) > 200 else ""),
            detail="Collapsed adjacent string-literal concatenations",
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
# Public entry
# =============================================================================
def deobfuscate_ps(text: str, max_passes: int = 3) -> Dict[str, Any]:
    """Deobfuscate a PowerShell command using pattern-based AST rules.

    Runs multiple passes so that each transformation can feed the next
    (variable substitution reveals a new string concat, which reveals a new
    format-string, etc.). Stops when no further changes are produced.
    """
    if not text:
        return {"output": text, "transformations": [], "bindings": {}}
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
    return {
        "output": current,
        "transformations": [t.__dict__ for t in out],
        "bindings": bindings,
    }
