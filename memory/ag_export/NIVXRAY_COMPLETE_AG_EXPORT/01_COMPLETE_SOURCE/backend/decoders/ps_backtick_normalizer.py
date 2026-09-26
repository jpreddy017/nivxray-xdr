"""RC4.5 · PowerShell Backtick / Line-Continuation Normalizer (Feb 2026).

Deterministically removes two PowerShell obfuscation tricks:

    1. In-token backtick escapes — ``po`we`rshell`` → ``powershell``.

       PowerShell treats a backtick before a printable ASCII character
       (that isn't already an escape sequence — ``n``/``t``/``r``/``0``/
       ``a``/``b``/``f``/``v``/``\``/``'``/``"``) as a literal character.
       Malware sprays these across cmdlet names and parameter names so
       naïve string matchers miss the invocation.

    2. Line-continuation backtick + newline (`` `\n``) — PowerShell joins
       the next physical line to the current logical line. We collapse
       ``\r?\n`` that follows a backtick, plus any leading whitespace on
       the next line.

We intentionally PRESERVE legitimate escape sequences (``\`n``, ``\`t``,
``\`r``, ``\`0``, ``\`a``, ``\`b``, ``\`f``, ``\`v``, ``\`\```, ``\`'``,
``\`"``) so string literals like ``"line1`nline2"`` still render newlines.

Registered as:

    * ``@op("powershell-backtick-normalize", …)`` — analyst-facing op.
    * ``PSBacktickNormalizerDecoder(BaseDecoder)`` — Orchestrator plugin.

Zero execution, zero sandbox, zero AI.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from engine.decoder_base import BaseDecoder
from engine.models import AnalysisContext, DetectResult, Fingerprint, PluginResult
from engine.registry import DecoderRegistry
from operations import op


# Legitimate PowerShell escape targets — DO NOT strip the backtick WHEN
# the backtick appears inside a double-quoted string (that's where PS
# actually interprets escapes). Outside any string, ALL in-token
# backticks are pure obfuscation.
_LEGIT_ESCAPES = set("ntrabfv0\\\"'`")

# Line continuation: `` ` `` at EOL (optionally trailed by whitespace)
# followed by ``\r?\n`` and any whitespace on the next line.
_RX_LINE_CONT = re.compile(r"`[ \t]*\r?\n[ \t]*")


def normalize_backticks(src: str) -> Tuple[str, List[Dict[str, Any]]]:
    """Return ``(normalized_text, trace)``.

    Semantics:
      * Line-continuation ``` ` \\n``` (optionally with trailing spaces
        on either side) is always collapsed regardless of context.
      * Outside any string literal — strip every in-token backtick.
      * Inside single-quoted literal (``'…'``) — leave content untouched
        (PS treats single quotes as literal, backticks have no meaning).
      * Inside double-quoted literal (``"…"``) — preserve the specific
        escape sequences ``\\`n``/``\\`t``/``\\`r``/``\\`0``/``\\`a``/
        ``\\`b``/``\\`f``/``\\`v``/``\\``\\``/``\\`"``/``\\`'``/``\\` ` ``;
        strip everything else (attackers use ``\\`E`X`` inside the
        `-Command "..."` payload).
    """
    trace: List[Dict[str, Any]] = []
    if not isinstance(src, str) or "`" not in src:
        return src, trace

    original = src

    # 1) Line-continuation collapse first (context-agnostic).
    line_cont_matches = _RX_LINE_CONT.findall(src)
    if line_cont_matches:
        src = _RX_LINE_CONT.sub("", src)
        trace.append({
            "step": "ps-backtick-line-continuation",
            "detail": f"joined {len(line_cont_matches)} line continuation(s)",
        })

    # 2) Walk char-by-char, tracking string state, and strip in-token
    # backticks context-appropriately.
    out: List[str] = []
    n = len(src)
    i = 0
    in_str: str = ""   # "" outside, "'" or '"' inside
    stripped = 0
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        # Toggle string state on unescaped quote.
        if not in_str and ch in ("'", '"'):
            in_str = ch
            out.append(ch)
            i += 1
            continue
        if in_str and ch == in_str:
            # PS does not honour ``\` `` as string escape inside single
            # quotes; inside double quotes, ``\\`"`` DOES escape the
            # closing quote. Handle that specifically.
            if in_str == '"' and out and out[-1] == "`":
                out.append(ch)
                i += 1
                continue
            in_str = ""
            out.append(ch)
            i += 1
            continue

        # Backtick handling
        if ch == "`":
            # Line continuation was already stripped, so any ``` ` `` at
            # EOL that remains isn't a line continuation.
            if in_str == "'":
                # Inside single-quotes: literal. Preserve verbatim.
                out.append(ch)
                i += 1
                continue
            if in_str == '"':
                # Inside double-quotes: preserve only legit escape
                # targets. Everything else is obfuscation → strip.
                if nxt in _LEGIT_ESCAPES:
                    # Emit the escape verbatim (`` ` `` + target char) and
                    # advance PAST the target so we don't re-visit it.
                    out.append(ch)
                    out.append(nxt)
                    i += 2
                    continue
                # Strip
                if nxt.isalnum() or nxt == "_":
                    stripped += 1
                    i += 1
                    continue
                # Backtick before punctuation / whitespace → leave.
                out.append(ch)
                i += 1
                continue
            # Outside any string: strip if followed by identifier char.
            if nxt.isalnum() or nxt == "_":
                stripped += 1
                i += 1
                continue
            out.append(ch)
            i += 1
            continue

        out.append(ch)
        i += 1

    text = "".join(out)
    if stripped:
        trace.append({
            "step": "ps-backtick-inline-strip",
            "detail": f"removed {stripped} in-token backtick(s)",
        })
    if text != original:
        trace.append({
            "step": "ps-backtick-normalize",
            "detail": f"{original[:60]!r} → {text[:60]!r}",
        })
    return text, trace


# ── @op registration ──────────────────────────────────────────────
@op(
    "powershell-backtick-normalize",
    "PowerShell Backtick / Line-Continuation Normalize",
    "Semantic Evaluation",
    "Removes in-token backtick escapes (``po`we`rshell`` → ``powershell``) "
    "and collapses line-continuation backticks + newline. Preserves "
    "legitimate escape sequences (``\\`n``, ``\\`t``, ``\\`r``, etc.). "
    "Deterministic — no execution, no sandbox, no AI.",
    [],
)
def op_powershell_backtick_normalize(data: str, args: Dict[str, Any] | None = None) -> str:
    normalized, trace = normalize_backticks(data)
    if normalized == data:
        return "(powershell-backtick-normalize · no backtick obfuscation found)"
    lines: List[str] = []
    lines.append("▼ POWERSHELL BACKTICK NORMALIZATION (RC4.5 · deterministic)")
    for i, row in enumerate(trace, 1):
        lines.append(f"  Step {i}: {row['step']} — {row['detail']}")
    lines.append("")
    lines.append("Normalized Command:")
    lines.append(f"  {normalized}")
    return "\n".join(lines) + "\n"


# ── BaseDecoder plugin ────────────────────────────────────────────
class PSBacktickNormalizerDecoder(BaseDecoder):
    id = "powershell-backtick-normalize"
    name = "PowerShell Backtick / Line-Continuation Normalizer"
    category = "normalize"
    cost = 1
    tags = ("powershell", "pwsh", "backtick", "normalize")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not isinstance(payload, str) or "`" not in payload:
            return DetectResult(confidence=0.0, why="no backtick present")
        # Skip legit escape-only strings ("`n" / "`t" ...)
        stripped = re.sub(r"`[ntrabfv0\\\"'`]", "", payload)
        if "`" not in stripped:
            return DetectResult(confidence=0.0, why="only legit escapes")
        return DetectResult(
            confidence=0.90,
            why="in-token backtick or line-continuation detected",
        )

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        normalized, trace = normalize_backticks(payload)
        return PluginResult(
            output=normalized,
            notes=[f"stripped={len(trace)} step(s)"] +
                   [f"{r['step']}: {r['detail']}" for r in trace],
            explanation=(
                "Deterministically removed in-token backtick escapes and "
                "collapsed line-continuation backticks. Legitimate escape "
                "sequences preserved."
            ),
        )


DecoderRegistry.register(PSBacktickNormalizerDecoder())
