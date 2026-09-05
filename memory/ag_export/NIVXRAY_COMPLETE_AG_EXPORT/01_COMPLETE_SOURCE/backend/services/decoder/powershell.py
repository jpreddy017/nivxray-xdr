"""PowerShell sub-engine · P0-1B Gate 2C ·

Ships six deobfuscation capabilities aimed at closing the well-known
PowerShell Plane-B gaps identified in P0-1 (obf-05, obf-06, obf-07,
obf-14, obf-15) and Invoke-Obfuscation's technique catalogue:

  · powershell.char_array_assembly    — `[char]105+[char]101+[char]120` → `iex`
  · powershell.format_string_assembly — `'{1}{0}' -f 'ex','i'`         → `iex`
  · powershell.string_concat          — `'ie'+'x'`                     → `iex`
  · powershell.variable_indirection   — `$a='iex'; &$a $x`             → `iex $x`
  · powershell.join_split_fold        — `-join`/`-split` static folds
  · powershell.stdin_pipe             — `echo … | powershell -c -`     → peel + reconstruct

Static-only rules (owner-locked, same as CMD sub-engine):
  · No interpreter invocation.  Every reconstruction is a static
    string transform derived from language grammar rules.
  · Provenance mandatory.
  · A variable is resolvable ONLY if it's SET to a literal earlier
    in the same script.  Runtime state is never assumed.
  · Char-code arithmetic is folded ONLY when the entire expression
    is a chain of `[char]<int>` (and `+`) — no arbitrary math.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .types import (
    Capability, CapabilityKind, DecodedLayer, Provenance,
    ReconstructionResult, now_iso,
)
from .registry import CapabilityRegistry


ENGINE_VERSION = "0.3.0-gate2c"


# ══════════════════════════════════════════════════════════════════
# Capabilities
# ══════════════════════════════════════════════════════════════════
_CAPS: dict[str, Capability] = {
    "powershell.char_array_assembly": Capability(
        name        = "powershell.char_array_assembly",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "powershell",
        version     = "0.1.0",
        description = "Fold `[char]<n>+[char]<m>+…` character-code chains "
                      "into their literal string.",
    ),
    "powershell.format_string_assembly": Capability(
        name        = "powershell.format_string_assembly",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "powershell",
        version     = "0.1.0",
        description = "Statically resolve `'{n}…{m}' -f 'a','b','c'` "
                      "format-string function assembly.",
    ),
    "powershell.string_concat": Capability(
        name        = "powershell.string_concat",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "powershell",
        version     = "0.1.0",
        description = "Fold adjacent quoted-string concatenations "
                      "(`'ie'+'x'`) into their result.",
    ),
    "powershell.variable_indirection": Capability(
        name        = "powershell.variable_indirection",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "powershell",
        version     = "0.1.0",
        description = "Substitute `&$var` and `$var` references when "
                      "the variable is bound to a literal earlier in "
                      "the same script.",
    ),
    "powershell.join_split_fold": Capability(
        name        = "powershell.join_split_fold",
        kind        = CapabilityKind.DEOBFUSCATOR,
        language    = "powershell",
        version     = "0.1.0",
        description = "Fold `-join` / `-split` when the array operand "
                      "is a static literal.",
    ),
    "powershell.stdin_pipe": Capability(
        name        = "powershell.stdin_pipe",
        kind        = CapabilityKind.PARSER,
        language    = "powershell",
        version     = "0.1.0",
        description = "Peel `echo <text> | powershell -c -` (stdin-fed "
                      "PowerShell) so the actual command becomes the "
                      "canonical payload.",
    ),
    # ── Gate 2D · inline base64 fold ──
    "powershell.base64_string_decode": Capability(
        name        = "powershell.base64_string_decode",
        kind        = CapabilityKind.DECODER,
        language    = "powershell",
        version     = "0.1.0",
        description = "Decode `[Convert]::FromBase64String('<literal>')` "
                      "inline; also folds `[Text.Encoding]::UTF8.GetString"
                      "([Convert]::FromBase64String('<literal>'))` shape. "
                      "Delegates to `services.decoder.base` for the "
                      "actual Base64 codec (Plane-A migration begun).",
    ),
}


# ══════════════════════════════════════════════════════════════════
# Gate 2D · inline Base64 fold  `[Convert]::FromBase64String('<b64>')`
# ══════════════════════════════════════════════════════════════════
# Match `[Convert]::FromBase64String('<literal>')` (single or double
# quoted; case-insensitive; whitespace tolerant).  When wrapped in
# `[Text.Encoding]::UTF8.GetString(…)` we still match the inner and
# leave the wrapper — the decoded literal replaces the whole
# invocation with a quoted-string result.
_PS_B64_INLINE_RE = re.compile(
    r"""(?ix)
    (?:\[(?:System\.)?Text\.Encoding\]::(?:UTF8|Unicode|ASCII)\.GetString\s*\(\s*)?
    \[(?:System\.)?Convert\]::FromBase64String
    \s*\(\s*
    (?:'([A-Za-z0-9+/=]+)'|"([A-Za-z0-9+/=]+)")
    \s*\)
    (?:\s*\))?
    """
)


def _run_ps_base64(raw: str,
                   parent_id: str,
                   layer_index: int) -> Optional[DecodedLayer]:
    """Fold PowerShell inline `FromBase64String('<literal>')` patterns
    into the decoded string.  Delegates the actual codec to
    `services.decoder.base` (Plane-A)."""
    from .base import decode_base64_as_string
    subs: list[tuple[str, str]] = []
    def _fold(match: re.Match) -> str:
        lit = match.group(1) if match.group(1) is not None else match.group(2)
        if lit is None:
            return match.group(0)
        decoded = decode_base64_as_string(lit)
        if decoded is None:
            return match.group(0)
        quoted = "'" + decoded.replace("'", "''") + "'"
        subs.append((match.group(0)[:60], quoted[:80]))
        return quoted
    new_text = _PS_B64_INLINE_RE.sub(_fold, raw)
    if not subs or new_text == raw:
        return None
    cap = _CAPS["powershell.base64_string_decode"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.base64_string_decode",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"decoded {len(subs)} inline base64 literal(s)",
    )


# ══════════════════════════════════════════════════════════════════
# 1 · character-array reconstruction  [char]<n>+[char]<m>+…
# ══════════════════════════════════════════════════════════════════
# Match sequences of `[char]<int>` joined by `+` (whitespace tolerant).
# Case-insensitive on `char`. Reject sequences with only one element
# (a single [char]65 is legitimate PS, not obfuscation).
_CHAR_CHAIN_RE = re.compile(
    r"(?ix)"
    r"(?:\[char\]\s*(\d{1,4})\s*\+\s*){1,}"     # ≥1 `[char]N+`
    r"\[char\]\s*(\d{1,4})"                     # final `[char]M`
)
_CHAR_ELEM_RE = re.compile(r"(?i)\[char\]\s*(\d{1,4})")


def _run_char_array(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    subs: list[tuple[str, str]] = []
    def _fold(match: re.Match) -> str:
        chunk = match.group(0)
        nums  = [int(n) for n in _CHAR_ELEM_RE.findall(chunk)]
        try:
            out = "".join(chr(n) for n in nums if 0 <= n < 0x110000)
        except (ValueError, OverflowError):
            return chunk
        # Emit quoted string so subsequent passes see a literal.
        quoted = "'" + out.replace("'", "''") + "'"
        subs.append((chunk, quoted))
        return quoted
    new_text = _CHAR_CHAIN_RE.sub(_fold, raw)
    if not subs:
        return None
    cap = _CAPS["powershell.char_array_assembly"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.char_array_assembly",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = "folded " + ", ".join(f"[{a[:32]}…]→{b}" for a, b in subs[:5]),
    )


# ══════════════════════════════════════════════════════════════════
# 2 · format-string function assembly   '{n}{m}' -f 'a','b'
# ══════════════════════════════════════════════════════════════════
_FORMAT_RE = re.compile(
    r"""(?x)
    (?:['"])                                # opening quote
    ((?:\{\d+\}[^'"]*)+)                    # template with {N} placeholders
    (?:['"])                                # closing quote
    \s*-f\s*                                # -f operator
    ((?:['"][^'"]*['"](?:\s*,\s*)?)+)       # comma-separated string args
    """
)
_ARG_STR_RE = re.compile(r"""['"]([^'"]*)['"]""")


def _run_format_string(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    subs: list[tuple[str, str]] = []
    def _fold(match: re.Match) -> str:
        tmpl = match.group(1)
        args = _ARG_STR_RE.findall(match.group(2))
        # Fold the template with args; if any {N} is out-of-range, bail.
        try:
            out = re.sub(
                r"\{(\d+)\}",
                lambda m: args[int(m.group(1))]
                            if int(m.group(1)) < len(args) else m.group(0),
                tmpl)
        except Exception:
            return match.group(0)
        if "{" in out:      # unresolved placeholder — treat as failure
            return match.group(0)
        quoted = "'" + out.replace("'", "''") + "'"
        subs.append((match.group(0), quoted))
        return quoted
    new_text = _FORMAT_RE.sub(_fold, raw)
    if not subs:
        return None
    cap = _CAPS["powershell.format_string_assembly"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.format_string_assembly",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = "folded " + "; ".join(f"{a[:40]}…→{b}" for a, b in subs[:5]),
    )


# ══════════════════════════════════════════════════════════════════
# 3 · string concatenation fold   'ie'+'x'  → 'iex'
# ══════════════════════════════════════════════════════════════════
_STR_CONCAT_RE = re.compile(
    r"(?:'([^']*)'|\"([^\"]*)\")\s*\+\s*"
    r"(?:'([^']*)'|\"([^\"]*)\")"
)


def _run_string_concat(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    subs: list[tuple[str, str]] = []
    def _fold(match: re.Match) -> str:
        parts = [g for g in match.groups() if g is not None]
        out   = "".join(parts)
        quoted = "'" + out.replace("'", "''") + "'"
        subs.append((match.group(0), quoted))
        return quoted
    new_text = raw
    for _ in range(4):    # multiple passes to fold chains
        nt = _STR_CONCAT_RE.sub(_fold, new_text)
        if nt == new_text:
            break
        new_text = nt
    if not subs:
        return None
    cap = _CAPS["powershell.string_concat"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.string_concat",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"folded {len(subs)} concat expression(s)",
    )


# ══════════════════════════════════════════════════════════════════
# 4 · variable indirection    $a='iex'; &$a $x  → 'iex' $x
# ══════════════════════════════════════════════════════════════════
# Simple assignment: $name = '<literal>'  or  $name="<literal>"
_PS_ASSIGN_RE = re.compile(
    r"\$([A-Za-z_][A-Za-z_0-9]*)\s*=\s*"
    r"(?:'([^']*)'|\"([^\"]*)\")"
)
# Uses: `$name` or `&$name`
_PS_USE_RE = re.compile(r"&?\$([A-Za-z_][A-Za-z_0-9]*)\b")


def _run_variable_indirection(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    # Left-to-right walk gathering literal assignments; use them for
    # subsequent references.
    assignments: dict[str, str] = {}
    for m in _PS_ASSIGN_RE.finditer(raw):
        name = m.group(1)
        val  = m.group(2) if m.group(2) is not None else m.group(3)
        if val is not None and name.upper() not in ("_", "NULL", "TRUE", "FALSE"):
            assignments[name] = val
    if not assignments:
        return None
    subs = 0
    def _repl(match: re.Match) -> str:
        nonlocal subs
        # Skip if this IS the assignment we recorded.
        full = match.group(0)
        name = match.group(1)
        if name not in assignments:
            return full
        subs += 1
        replacement = assignments[name]
        # Emit as quoted literal (preserve invocation syntax).
        quoted = "'" + replacement.replace("'", "''") + "'"
        return quoted
    # Walk carefully: skip the ASSIGNMENT sites; only replace
    # subsequent references.
    parts: list[str] = []
    i = 0
    while True:
        m = _PS_ASSIGN_RE.search(raw, pos=i)
        if not m:
            parts.append(_PS_USE_RE.sub(_repl, raw[i:]))
            break
        # Emit up to (and including) the assignment site unchanged.
        parts.append(raw[i:m.end()])
        i = m.end()
    new_text = "".join(parts)
    if subs == 0 or new_text == raw:
        return None
    cap = _CAPS["powershell.variable_indirection"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.variable_indirection",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "MEDIUM",
        notes          = f"resolved {subs} variable reference(s) "
                         f"from {len(assignments)} literal assignment(s)",
    )


# ══════════════════════════════════════════════════════════════════
# 5 · -join / -split fold
# ══════════════════════════════════════════════════════════════════
# `('a','b','c') -join ''`  →  'abc'
_JOIN_RE = re.compile(
    r"""(?x)
    \(
    \s*
    ((?:['"][^'"]*['"](?:\s*,\s*)?){2,})    # ≥2 comma-separated strings
    \s*
    \)
    \s*-join\s*
    (?:['"]([^'"]*)['"])
    """
)


def _run_join_split(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    subs: list[tuple[str, str]] = []
    def _fold(match: re.Match) -> str:
        parts = _ARG_STR_RE.findall(match.group(1))
        sep   = match.group(2)
        out   = sep.join(parts)
        quoted = "'" + out.replace("'", "''") + "'"
        subs.append((match.group(0), quoted))
        return quoted
    new_text = _JOIN_RE.sub(_fold, raw)
    if not subs:
        return None
    cap = _CAPS["powershell.join_split_fold"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.join_split_fold",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(new_text),
        input_preview  = raw[:256],
        output         = new_text,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = f"folded {len(subs)} -join expression(s)",
    )


# ══════════════════════════════════════════════════════════════════
# 6 · stdin-piped PowerShell    echo <text> | powershell -c -
# ══════════════════════════════════════════════════════════════════
_STDIN_PIPE_RE = re.compile(
    r"""(?ix)
    ^\s*
    (?:echo|write-output|write-host)
    \s+
    (?:['"]([^'"]*)['"]|(\S.*?))            # payload (quoted or bare)
    \s*\|\s*
    (?:powershell(?:\.exe)?|pwsh(?:\.exe)?)
    \s+-c\s+-
    \s*$
    """
)


def _run_stdin_pipe(raw: str, parent_id: str, layer_index: int) -> Optional[DecodedLayer]:
    m = _STDIN_PIPE_RE.match(raw)
    if not m:
        return None
    payload = m.group(1) if m.group(1) is not None else m.group(2)
    if payload is None:
        return None
    cap = _CAPS["powershell.stdin_pipe"]
    return DecodedLayer(
        layer_index    = layer_index,
        stage          = "powershell.stdin_pipe",
        language       = "powershell",
        bytes_in       = len(raw),
        bytes_out      = len(payload),
        input_preview  = raw[:256],
        output         = payload,
        capability     = cap,
        provenance     = Provenance(
            decoded_from    = parent_id,
            capability_name = cap.name,
            engine_version  = ENGINE_VERSION,
            recorded_at     = now_iso(),
        ),
        confidence     = "HIGH",
        notes          = "peeled stdin-piped PowerShell",
    )


# ══════════════════════════════════════════════════════════════════
# register_all + reconstruct
# ══════════════════════════════════════════════════════════════════
def register_all(registry: CapabilityRegistry) -> None:
    if registry.get("powershell.char_array_assembly") is not None:
        return
    registry.register(_CAPS["powershell.stdin_pipe"],             _run_stdin_pipe)
    registry.register(_CAPS["powershell.char_array_assembly"],    _run_char_array)
    registry.register(_CAPS["powershell.format_string_assembly"], _run_format_string)
    registry.register(_CAPS["powershell.string_concat"],          _run_string_concat)
    registry.register(_CAPS["powershell.join_split_fold"],        _run_join_split)
    registry.register(_CAPS["powershell.variable_indirection"],   _run_variable_indirection)
    registry.register(_CAPS["powershell.base64_string_decode"],   _run_ps_base64)


def reconstruct(raw: str, parent_id: str) -> ReconstructionResult:
    """PowerShell reconstruction pass.  Deterministic ordering:
        1. stdin_pipe (peel) →
        2. char_array_assembly →
        3. format_string_assembly →
        4. string_concat →
        5. join_split_fold →
        6. variable_indirection.
    Multiple passes because folds can expose new folds.
    """
    layers: list[DecodedLayer] = []
    current = raw
    stdin_layer = _run_stdin_pipe(current, parent_id, layer_index=0)
    if stdin_layer is not None:
        layers.append(stdin_layer)
        current = stdin_layer.output

    for _pass in range(3):
        progress = False
        for runner_fn in (_run_char_array, _run_format_string,
                          _run_string_concat, _run_join_split,
                          _run_variable_indirection,
                          _run_ps_base64):
            layer = runner_fn(current, parent_id, layer_index=len(layers))
            if layer is not None:
                layers.append(layer)
                current = layer.output
                progress = True
        if not progress:
            break

    return ReconstructionResult(
        raw_input          = raw,
        final              = current,
        layers             = layers,
        unresolved_reasons = [],
        partial            = False,
        engine_version     = ENGINE_VERSION,
        static_only_verified = True,
    )


__all__ = ["reconstruct", "register_all"]
