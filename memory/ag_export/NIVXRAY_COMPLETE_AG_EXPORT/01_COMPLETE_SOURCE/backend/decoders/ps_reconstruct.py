"""PowerShell string-reconstruction plugin.

Handles common obfuscation patterns that rebuild a plaintext command from
character arithmetic without any encoding transform:

    [char]0x49 + [char]0x45 + [char]0x58                       → "IEX"
    [char]73 + [char]69 + [char]88                             → "IEX"
    [char[]](73,69,88) -join ''                                → "IEX"
    'IX' -f 'E' style                                          → best-effort
    'p'+'o'+'w'+'ers'+'hell'                                   → "powershell"
    -join ('IEX'.ToCharArray())                                → passthrough

Design
------
* detect() fires only when at least one of the reconstruction patterns is
  present in the payload — cheap regex scan.
* decode() rewrites *only the reconstruction fragments*, leaving the
  surrounding script structure intact so the next layer (extract_wrapper /
  base64 / hex) can still peel it further.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


# 1) [char]0xNN or [char]NN  (single-char accessor) — supports chained
#    concatenation like `[char]0x49 + [char]0x45 + [char]0x58` which we
#    collapse to a single quoted string.
_RX_CHAR_CHAIN = re.compile(
    r"""(?:\[\s*char\s*\]\s*(?:0x[0-9A-Fa-f]{1,4}|\d{1,5})\s*\+?\s*){2,}""",
    re.IGNORECASE,
)
_RX_CHAR = re.compile(
    r"""\[\s*char\s*\]\s*(0x[0-9A-Fa-f]{1,4}|\d{1,5})""",
    re.IGNORECASE,
)

# 2) [char[]]  ( 73 , 69 , 88 )  -join ''    (array to string)
_RX_CHAR_ARRAY = re.compile(
    r"""\[\s*char\s*\[\s*\]\s*\]\s*\(\s*([0-9xXA-Fa-f,\s]+?)\s*\)\s*-\s*join\s*(['"])(.*?)\2""",
    re.IGNORECASE | re.DOTALL,
)

# 3) simple string concat 'a'+'b'+'c'
_RX_STR_CONCAT = re.compile(
    r"""(['"])((?:(?!\1).)+?)\1(?:\s*\+\s*(['"])((?:(?!\3).)+?)\3){1,}""",
    re.DOTALL,
)

# 4) PowerShell backtick escapes inside identifiers / keywords: p`ow`e`r`shell
_RX_BACKTICK = re.compile(r"(?<!`)`(?![nrt0abfv`\"'])")


# 5) `.Replace('a','b')` on a quoted literal or a chained expression.
#    Supports both single- and double-quoted args; chained calls apply
#    left-to-right ('X').Replace('a','b').Replace('c','d')
_RX_REPLACE = re.compile(
    r"""(['"])((?:(?!\1).)*?)\1\s*\)?\s*\.Replace\s*\(\s*(['"])((?:(?!\3).)*)\3\s*,\s*(['"])((?:(?!\5).)*)\5\s*\)""",
    re.IGNORECASE | re.DOTALL,
)


# 6) Simple variable-to-string-literal assignment tracking.
#    `$var = 'literal'` or `$var='literal'` (single or double quotes).
#    We only track assignments to pure string literals — anything computed is
#    left alone. This is a deliberate precision-over-recall choice: the
#    orchestrator's downstream regex passes handle chained expressions.
_RX_VAR_ASSIGN = re.compile(
    r"""\$(\w+)\s*=\s*(['"])((?:(?!\2).)*)\2""",
    re.DOTALL,
)


# 7) `('a','b','c') -join ''` — join a quoted-string array with a separator.
#    Also matches `'a','b','c' -join '.'` without wrapping parens.
_RX_JOIN_ARRAY = re.compile(
    r"""\(?\s*((?:(['"])(?:(?!\2).)*\2\s*,\s*){1,}(['"])(?:(?!\3).)*\3)\s*\)?\s*-\s*join\s*(['"])((?:(?!\4).)*)\4""",
    re.IGNORECASE | re.DOTALL,
)


# 8) `"format" -f "arg1","arg2",...` — .NET format-string operator.
#    Precision-first: only fire when format string uses {N} placeholders.
_RX_FORMAT_OP = re.compile(
    r"""(['"])((?:(?!\1).)*\{\d+\}(?:(?!\1).)*)\1\s*-\s*f\s*((?:(?:['"])(?:(?!['"]).)*(?:['"])\s*,?\s*)+)""",
    re.IGNORECASE | re.DOTALL,
)


# 9) `[ScriptBlock]::Create('command')` or `[scriptblock]::Create("command")`
#    Unwrap the string literal argument — the resulting block IS the command.
#    Used by RC2.6 P0.3 to peel scriptblock wrappers before downstream passes.
_RX_SCRIPTBLOCK_CREATE = re.compile(
    r"""\[\s*(?:System\.Management\.Automation\.)?ScriptBlock\s*\]\s*::\s*Create\s*\(\s*(['"])((?:(?!\1).)*)\1\s*\)""",
    re.IGNORECASE | re.DOTALL,
)


# 10) IEX-of-variable / invocation-of-variable — the second half of the
#     reconstruction-and-invoke dance:
#         $a = ('I','E','X') -join ''; & $a  ...
#         $c = [char]73+[char]69+[char]88; IEX $c ...
#     We detect this to (a) raise ps-reconstruct detection confidence so it
#     wins the orchestrator race against extract-wrapper, and (b) after
#     var-expansion, rewrite `& $var` / `IEX $var` to `& 'RESOLVED'` /
#     `IEX 'RESOLVED'` so the reconstructed keyword surfaces in the final
#     output for MITRE / IOC extractors.
_RX_INVOKE_VAR = re.compile(
    r"""(?:^|[\s;&|\(])(?:&|Invoke-Expression|IEX)\s*\(?\s*\$(\w+)\b""",
    re.IGNORECASE,
)


def _int_from_token(tok: str) -> int:
    tok = tok.strip()
    if tok.lower().startswith("0x"):
        return int(tok, 16)
    return int(tok)


def _replace_char_arrays(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        numlist = m.group(1)
        try:
            chars = [chr(_int_from_token(t)) for t in re.split(r"[\s,]+", numlist) if t.strip()]
        except (ValueError, OverflowError):
            return m.group(0)
        hits += 1
        return "'" + "".join(chars).replace("'", "''") + "'"

    return _RX_CHAR_ARRAY.sub(_sub, text), hits


def _replace_char_singletons(text: str) -> Tuple[str, int]:
    hits = 0

    # First pass — collapse chained `[char]NN + [char]MM + ...` into a
    # single quoted literal so downstream regexes see a clean string.
    def _sub_chain(m: re.Match) -> str:
        nonlocal hits
        nums = _RX_CHAR.findall(m.group(0))
        try:
            chars = [chr(_int_from_token(n)) for n in nums]
        except (ValueError, OverflowError):
            return m.group(0)
        hits += 1
        return "'" + "".join(chars).replace("'", "''") + "'"

    text = _RX_CHAR_CHAIN.sub(_sub_chain, text)

    # Second pass — leftover standalone `[char]NN` (not part of a chain).
    def _sub(m: re.Match) -> str:
        nonlocal hits
        try:
            v = _int_from_token(m.group(1))
            if 0 <= v <= 0x10FFFF:
                hits += 1
                return chr(v)
        except (ValueError, OverflowError):
            pass
        return m.group(0)

    return _RX_CHAR.sub(_sub, text), hits


def _replace_str_concat(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        # Grab every quoted fragment in the match
        frags = re.findall(r"""(['"])((?:(?!\1).)+?)\1""", m.group(0), re.DOTALL)
        if len(frags) < 2:
            return m.group(0)
        joined = "".join(f[1] for f in frags)
        hits += 1
        return "'" + joined.replace("'", "''") + "'"

    return _RX_STR_CONCAT.sub(_sub, text), hits


def _strip_ps_backticks(text: str) -> Tuple[str, int]:
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        hits += 1
        return ""

    return _RX_BACKTICK.sub(_sub, text), hits


def _replace_dot_replace(text: str) -> Tuple[str, int]:
    """Apply `.Replace('a','b')` on quoted literals; iterate to chain."""
    hits = 0
    while True:
        m = _RX_REPLACE.search(text)
        if not m:
            break
        target = m.group(2)
        needle = m.group(4)
        subst = m.group(6)
        if not needle:                                  # empty needle is a no-op
            break
        try:
            replaced = target.replace(needle, subst)
        except Exception:                               # pragma: no cover
            break
        text = text[:m.start()] + "'" + replaced.replace("'", "''") + "'" + text[m.end():]
        hits += 1
        if hits > 32:                                   # runaway guard
            break
    return text, hits


def _expand_string_vars(text: str) -> Tuple[str, int]:
    """Substitute `$var` references with their assigned string literals.

    Only expands variables assigned to plain string literals in the same
    payload. Assignments that use `[char]` / `-join` / expressions are left
    to earlier passes to resolve first.
    """
    assigns: Dict[str, str] = {}
    for m in _RX_VAR_ASSIGN.finditer(text):
        # Precision guard: last assignment wins; overwriting is fine.
        assigns[m.group(1)] = m.group(3)
    if not assigns:
        return text, 0

    hits = 0
    for name, value in assigns.items():
        # Substitute `$name` when not immediately followed by a word char
        # (so `$name` matches but `$namespace` doesn't).
        rx = re.compile(rf"\${re.escape(name)}(?![A-Za-z0-9_])")
        # Preserve the assignment line itself; only replace usage sites.
        # Simple heuristic: skip replacement at the assignment position.
        assign_rx = re.compile(rf"\${re.escape(name)}\s*=\s*(['\"])")
        pieces: List[str] = []
        last = 0
        for m in rx.finditer(text):
            # Skip if this occurrence is the LHS of an assignment.
            probe = text[m.start():m.start() + 200]
            if assign_rx.match(probe):
                continue
            pieces.append(text[last:m.start()])
            pieces.append("'" + value.replace("'", "''") + "'")
            last = m.end()
            hits += 1
        if pieces:
            pieces.append(text[last:])
            text = "".join(pieces)
    return text, hits


def _apply_join_array(text: str) -> Tuple[str, int]:
    """Collapse `('a','b','c') -join 'sep'` into a single quoted literal."""
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        elems_blob = m.group(1)
        sep = m.group(5)
        # Extract every quoted fragment from the element list
        frags = re.findall(r"""(['"])((?:(?!\1).)*)\1""", elems_blob, re.DOTALL)
        if len(frags) < 2:
            return m.group(0)
        joined = sep.join(f[1] for f in frags)
        hits += 1
        return "'" + joined.replace("'", "''") + "'"

    return _RX_JOIN_ARRAY.sub(_sub, text), hits


def _apply_format_operator(text: str) -> Tuple[str, int]:
    """Apply `"{2}{0}{1}" -f "E","X","I"` .NET string.Format semantics."""
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        fmt = m.group(2)
        args_blob = m.group(3)
        args = [f[1] for f in re.findall(r"""(['"])((?:(?!\1).)*)\1""",
                                          args_blob, re.DOTALL)]
        if not args:
            return m.group(0)
        # Substitute {N} placeholders
        try:
            def _slot(sm: re.Match) -> str:
                idx = int(sm.group(1))
                return args[idx] if 0 <= idx < len(args) else sm.group(0)
            out = re.sub(r"\{(\d+)\}", _slot, fmt)
        except Exception:                                # pragma: no cover
            return m.group(0)
        hits += 1
        return "'" + out.replace("'", "''") + "'"

    return _RX_FORMAT_OP.sub(_sub, text), hits


def _unwrap_scriptblock_create(text: str) -> Tuple[str, int]:
    """RC2.6 P0.3.b — `[ScriptBlock]::Create('cmd')` → `'cmd'`.

    Keeps the surrounding structure so if the block is chained with
    `.Invoke()` or piped into `&`, the next pass still sees it as a
    string literal ready for var-expansion / MITRE extraction.
    """
    hits = 0

    def _sub(m: re.Match) -> str:
        nonlocal hits
        hits += 1
        inner = m.group(2)
        return "'" + inner.replace("'", "''") + "'"

    return _RX_SCRIPTBLOCK_CREATE.sub(_sub, text), hits


def _reveal_invoked_var(text: str) -> Tuple[str, int]:
    """RC2.6 P0.3.c — rewrite `& $var` / `IEX $var` / `Invoke-Expression $var`
    to embed the resolved literal INLINE alongside the invocation.

    Only fires when `$var` was assigned to a plain string literal in the
    same payload. Original invocation is preserved (so downstream analysts
    still see the variable reference); the resolved literal is appended in
    a comment-like marker so IOC / MITRE extractors can see keywords like
    `IEX` in the final output.
    """
    assigns: Dict[str, str] = {}
    for m in _RX_VAR_ASSIGN.finditer(text):
        assigns[m.group(1)] = m.group(3)
    if not assigns:
        return text, 0

    hits = 0
    pieces: List[str] = []
    last = 0
    for m in _RX_INVOKE_VAR.finditer(text):
        name = m.group(1)
        if name not in assigns:
            continue
        # Idempotency guard (Jul-2026) — skip when the invocation is
        # already followed by a `<#=>` reveal marker so re-runs of the
        # decoder don't stack duplicate literals in the output.
        tail = text[m.end() : m.end() + 8]
        if tail.lstrip().startswith("<#=>"):
            continue
        pieces.append(text[last:m.end()])
        # Emit the resolved literal after the invocation so it appears in
        # final output for keyword surfacing (IEX / powershell / cmd etc.)
        # without corrupting the syntax if analysts copy-paste.
        resolved = assigns[name]
        pieces.append(f" <#=> '{resolved.replace(chr(39), chr(39)*2)}' <#=>")
        last = m.end()
        hits += 1
    if hits == 0:
        return text, 0
    pieces.append(text[last:])
    return "".join(pieces), hits


class PowerShellReconstructDecoder(BaseDecoder):
    id = "ps-reconstruct"
    name = "PowerShell String Reconstruct"
    category = "reconstruct"
    cost = 2
    tags = ("powershell", "reconstruct", "deobfuscate", "char-arithmetic", "backtick")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 6:
            return DetectResult(confidence=0.0, why="Too short")
        signals: List[str] = []
        if _RX_CHAR_ARRAY.search(payload):
            signals.append("char[]-join")
        if _RX_CHAR.search(payload):
            signals.append("[char]NN")
        # Only count string-concat if it contains at least one non-word bridge
        # (i.e. real obfuscation like 'p'+'o'+'w' → not casual 'x'+'y' text).
        m = _RX_STR_CONCAT.search(payload)
        if m and m.group(0).count("+") >= 2:
            signals.append("str-concat")
        if _RX_BACKTICK.search(payload) and re.search(r"[A-Za-z]`[A-Za-z]", payload):
            signals.append("ps-backtick")
        if _RX_REPLACE.search(payload):
            signals.append("ps-replace")
        if _RX_JOIN_ARRAY.search(payload):
            signals.append("ps-join-array")
        if _RX_FORMAT_OP.search(payload):
            signals.append("ps-format-op")
        if _RX_SCRIPTBLOCK_CREATE.search(payload):
            signals.append("ps-scriptblock")
        if _RX_VAR_ASSIGN.search(payload):
            # Only count var-expansion as a signal if the variable is actually
            # referenced somewhere in the same payload.
            for m in _RX_VAR_ASSIGN.finditer(payload):
                name = m.group(1)
                if re.search(rf"\${re.escape(name)}(?![A-Za-z0-9_=])", payload):
                    signals.append("ps-var-expand")
                    break
        # RC2.6 P0.3 — invocation-of-variable pattern. When we see BOTH a
        # reconstruction signal AND `& $var` / `IEX $var`, this is the
        # canonical reconstruct-then-invoke dance — bump confidence high
        # enough to beat extract-wrapper (0.65) so the reconstructed
        # keyword surfaces in the final output.
        invoke_var_present = bool(_RX_INVOKE_VAR.search(payload))
        if invoke_var_present and signals:
            signals.append("ps-invoke-var")
        if not signals:
            return DetectResult(confidence=0.0, why="No PS reconstruction pattern")
        # Confidence: single mild signal is 0.6; two = 0.9; the
        # reconstruct-then-invoke combo lifts to 0.85 (>0.65 extract-wrapper).
        if invoke_var_present and len(signals) >= 2:
            conf = 0.9
        elif len(signals) >= 2:
            conf = 0.9
        else:
            conf = 0.6
        return DetectResult(
            confidence=conf,
            why=f"PowerShell reconstruction signals: {', '.join(signals)}",
            args={"signals": signals},
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        text = payload
        total_hits = 0
        notes: List[str] = []

        # RC2.6 P0.3.b — Peel ScriptBlock wrappers first so the inner
        # command becomes a plain string literal that later passes can
        # reason about (var expansion, .Replace, etc.).
        text, n = _unwrap_scriptblock_create(text)
        if n:
            total_hits += n
            notes.append(f"Unwrapped {n} [ScriptBlock]::Create(...) call(s)")

        text, n = _replace_char_arrays(text)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} [char[]]-join(...) block(s)")

        text, n = _replace_char_singletons(text)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} [char]NN literal(s)")

        text, n = _replace_str_concat(text)
        if n:
            total_hits += n
            notes.append(f"Collapsed {n} string-concat chain(s)")

        text, n = _strip_ps_backticks(text)
        if n:
            total_hits += n
            notes.append(f"Stripped {n} PowerShell backtick escape(s)")

        text, n = _replace_dot_replace(text)
        if n:
            total_hits += n
            notes.append(f"Applied {n} .Replace() call(s)")

        text, n = _apply_join_array(text)
        if n:
            total_hits += n
            notes.append(f"Collapsed {n} -join array(s)")

        text, n = _apply_format_operator(text)
        if n:
            total_hits += n
            notes.append(f"Applied {n} -f format operator(s)")

        text, n = _expand_string_vars(text)
        if n:
            total_hits += n
            notes.append(f"Expanded {n} PowerShell variable reference(s)")

        # Second pass — variable expansion may unlock new .Replace targets
        # (e.g. `$x = 'IZZEZZX'; $x.Replace('ZZ','')`).
        text, n = _replace_dot_replace(text)
        if n:
            total_hits += n
            notes.append(f"Applied {n} additional .Replace() call(s) after var expansion")

        # RC2.6 P0.3.c — After all reconstruction is done, surface the
        # resolved literal alongside `& $var` / `IEX $var` invocations so
        # keywords like IEX / powershell reach the IOC + MITRE extractors.
        text, n = _reveal_invoked_var(text)
        if n:
            total_hits += n
            notes.append(f"Revealed {n} invoked-variable literal(s)")

        if total_hits == 0:
            return PluginResult(output=payload, notes=["ps-reconstruct: no changes"])

        return PluginResult(
            output=text,
            notes=notes,
            mitre_hints=[
                MitreHint(
                    id="T1027", technique="Obfuscated Files or Information",
                    tactic="Defense Evasion",
                    evidence=f"PowerShell string reconstruction ({total_hits} rewrite(s))",
                    source="archetype",
                ),
            ],
            tradecraft=[
                TradecraftFlag(
                    flag="ps-string-obfuscation", severity="medium",
                    evidence="; ".join(notes),
                ),
            ],
            explanation=(
                "Rebuilt obfuscated PowerShell string literals using char-arithmetic / "
                "string-concat / backtick removal so the underlying command surfaces."
            ),
        )


DecoderRegistry.register(PowerShellReconstructDecoder())
