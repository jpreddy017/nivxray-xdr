"""NivXRay PowerShell Deterministic Deobfuscator (2026-07-25).

Recursive, deterministic transformation engine. Runs safe .NET-style
operations (String.Format, Join, Convert.ToInt16, Base64, char array
reconstruction, octal / hex / decimal decoders) until no further
reversible transformation remains OR a true execution boundary is hit.

Contract (locked with SOC user 2026-07-25):
    • Safe operations only — NEVER execute Invoke-Expression, ScriptBlocks,
      Reflection.Assembly.Load, Add-Type, COM, WMI, Win32 APIs.
    • Every transformation is logged as a stage: {technique, evidence,
      before_snippet, after_snippet, offset}.
    • Recursion capped at MAX_STAGES to prevent runaway loops on adversarial
      input.
    • Deterministic — same input → same output → same stage chain.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field, asdict


MAX_STAGES = 20


# ── Alias table (safe deterministic renames) ─────────────────────
_ALIASES = {
    r"\biex\b":  "Invoke-Expression",
    r"\biwr\b":  "Invoke-WebRequest",
    r"\birm\b":  "Invoke-RestMethod",
    r"\bsaps\b": "Start-Process",
    r"\bgv\b":   "Get-Variable",
    r"\bgc\b":   "Get-Content",
    r"\bsv\b":   "Set-Variable",
    r"\bsal\b":  "Set-Alias",
    r"\bni\b":   "New-Item",
    r"\bgci\b":  "Get-ChildItem",
    r"\bgps\b":  "Get-Process",
    r"\bgsv\b":  "Get-Service",
}


@dataclass
class Stage:
    n: int
    technique: str          # analyst-facing label
    evidence: str           # what pattern was matched
    before: str             # snippet before transformation (≤ 200 chars)
    after: str              # snippet after transformation (≤ 200 chars)
    offset: int = 0         # position in the payload where the transform applied

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeobfuscationReport:
    original:       str
    final:          str
    stages:         list[Stage] = field(default_factory=list)
    stopped_reason: str = ""    # boundary hit | max_stages | fixed_point
    boundary_op:    str = ""    # e.g. "Invoke-Expression" | "" if none

    def to_dict(self) -> dict:
        return {
            "original":       self.original[:2000],
            "final":          self.final,
            "stages":         [s.to_dict() for s in self.stages],
            "stopped_reason": self.stopped_reason,
            "boundary_op":    self.boundary_op,
        }


# ── Format-string resolver ───────────────────────────────────────
# Match `'fmt' -f 'a','b','c'` — simpler regex, no catastrophic backtracking
_FORMAT_RE = re.compile(
    r"(['\"])([^'\"]*?\{\d+\}[^'\"]*?)\1"       # 'fmt with {N} placeholders'
    r"\s*-f\s*"
    r"((?:\s*(['\"])[^'\"]*?\4\s*,?\s*)+)",
    re.DOTALL,
)


def _resolve_format(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    """Replace `'fmt' -f 'a','b','c'` occurrences with the folded string."""
    def _repl(m: re.Match) -> str:
        fmt = m.group(2)
        args_blob = m.group(3)
        # Extract each simple quoted arg
        strs = [g[1] for g in re.findall(r"(['\"])([^'\"]*?)\1", args_blob)]
        try:
            def _sub(mm):
                idx_s = mm.group(1)
                idx = int(idx_s.split(",")[0].split(":")[0])
                return strs[idx] if 0 <= idx < len(strs) else mm.group(0)
            folded = re.sub(r"\{(\d+(?:,[^{}]*)?(?::[^{}]*)?)\}", _sub, fmt)
        except Exception:
            return m.group(0)
        return f"'{folded}'"
    new_txt, count = _FORMAT_RE.subn(_repl, txt)
    if count and new_txt != txt:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve .NET string format",
            evidence=f"Matched {count} `-f` format expression(s).",
            before=txt[:200], after=new_txt[:200],
        ))
        return new_txt, True
    return txt, False


# ── String concat `'a' + 'b'` ────────────────────────────────────
_CONCAT_RE = re.compile(r"(['\"])([^'\"]*?)\1\s*\+\s*(['\"])([^'\"]*?)\3")


def _resolve_concat(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for _ in range(10):
        new_txt, count = _CONCAT_RE.subn(
            lambda m: f"'{m.group(2)}{m.group(4)}'", txt)
        if not count:
            break
        txt = new_txt
        changed = True
    if changed:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve string concatenation",
            evidence="Merged `'a' + 'b'` literals.",
            before="", after=txt[:200],
        ))
    return txt, changed


# ── Backtick escape strip ────────────────────────────────────────
def _resolve_backticks(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    new_txt = re.sub(r"`([a-zA-Z_])", r"\1", txt)
    if new_txt != txt:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve backtick escapes",
            evidence="Stripped PowerShell backtick escapes.",
            before=txt[:200], after=new_txt[:200],
        ))
        return new_txt, True
    return txt, False


# ── Alias expansion ──────────────────────────────────────────────
def _resolve_aliases(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for pat, full in _ALIASES.items():
        new_txt = re.sub(pat, full, txt, flags=re.IGNORECASE)
        if new_txt != txt:
            txt = new_txt
            changed = True
    if changed:
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Resolve cmdlet aliases",
            evidence="Expanded PowerShell aliases (iex→Invoke-Expression, etc.).",
            before="", after=txt[:200],
        ))
    return txt, changed


# ── Numeric char-array reconstruction (octal/hex/decimal) ────────
# Matches things like:
#   (127,162,151,164,145) | %{ [char]([Convert]::ToInt16(([string]$_),8)) }
#   (0x57, 0x72, 0x69) | %{ [char]$_ }
#   [char[]](87,114,105,116,101)
_NUM_LIST_RE = re.compile(
    r"\(\s*((?:[0-9a-fA-Fx]+\s*,\s*){2,}[0-9a-fA-Fx]+)\s*\)"
)


def _parse_number(tok: str, base: int) -> int | None:
    tok = tok.strip()
    try:
        if tok.lower().startswith("0x"):
            return int(tok, 16)
        return int(tok, base)
    except Exception:
        return None


def _resolve_numeric_char_reconstruction(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    """Detect (n1, n2, …) coupled with a `[char]([Convert]::ToInt16(…,BASE))`
    or `[char[]](…)` construction, fold the array into a literal string."""
    # Find all `(N1,N2,N3,…)` numeric lists and check their context for a
    # `[char]` / `Convert::ToInt16(...,BASE)` marker within 200 chars.
    changed = False
    for m in list(_NUM_LIST_RE.finditer(txt)):
        list_text = m.group(1)
        raw_tokens = [t.strip() for t in list_text.split(",") if t.strip()]
        # Peek ±200 chars for base indicator
        ctx = txt[max(0, m.start() - 300): m.end() + 300]
        base = None
        technique = None
        if re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*8\s*\)", ctx, re.I | re.S):
            base = 8;  technique = "Octal ASCII reconstruction"
        elif re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*16\s*\)", ctx, re.I | re.S):
            base = 16; technique = "Hex ASCII reconstruction"
        elif re.search(r"convert\]::toint(?:16|32)\s*\(.*?,\s*2\s*\)", ctx, re.I | re.S):
            base = 2;  technique = "Binary ASCII reconstruction"
        elif re.search(r"\[char\s*\[\s*\]\s*\]", ctx, re.I) or \
             re.search(r"\|\s*%\s*\{\s*\[char\]", ctx, re.I):
            base = 10; technique = "Decimal char[] reconstruction"
        if base is None:
            continue
        # Decode each token in the chosen base
        chars: list[str] = []
        for tok in raw_tokens:
            n = _parse_number(tok, base)
            if n is None or not (0 <= n < 0x110000):
                chars = []
                break
            try:
                chars.append(chr(n))
            except Exception:
                chars = []; break
        if not chars:
            continue
        recovered = "".join(chars)
        # Replace the WHOLE construction (list + surrounding pipeline) with the
        # recovered string literal wrapped in quotes.
        # We look for the enclosing `( … ) | %{ … } ` or `[char[]](…)` — take
        # the outermost of the two markers around the list.
        span_start, span_end = m.start(), m.end()
        # Extend to swallow the `| %{ ... }` tail if present
        tail = re.match(r"\s*\|\s*%\s*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", txt[span_end:], re.S)
        if tail:
            span_end += tail.end()
        # Extend backward for `[char[]]` prefix
        head_prefix = re.search(r"\[char(?:\[\s*\])?\s*\]\s*$", txt[:span_start], re.I)
        if head_prefix:
            span_start = head_prefix.start()
        replacement = f"'{recovered}'"
        txt = txt[:span_start] + replacement + txt[span_end:]
        stages.append(Stage(
            n=len(stages) + 1,
            technique=technique,
            evidence=(f"Recovered {len(recovered)} chars from a "
                       f"{len(raw_tokens)}-element base-{base} integer array."),
            before=list_text[:200],
            after=recovered[:200],
            offset=span_start,
        ))
        changed = True
        break   # Restart from top of loop — text has shifted
    return txt, changed


# ── [Convert]::FromBase64String("...") ───────────────────────────
_B64_STATIC_RE = re.compile(
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([A-Za-z0-9+/=]{8,})\1\s*\)",
    re.IGNORECASE,
)


def _resolve_static_base64(txt: str, stages: list[Stage]) -> tuple[str, bool]:
    changed = False
    for m in list(_B64_STATIC_RE.finditer(txt)):
        blob = m.group(2)
        try:
            raw = base64.b64decode(blob, validate=False)
        except binascii.Error:
            continue
        # Try to interpret as text — UTF-8 first (safest default for text
        # payloads wrapped in `[System.Text.Encoding]::UTF8.GetString(...)`),
        # then UTF-16LE (PowerShell canonical for -EncodedCommand), then ASCII.
        decoded = None
        for enc in ("utf-8", "utf-16-le", "ascii"):
            try:
                decoded = raw.decode(enc, errors="strict")
                break
            except Exception:
                continue
        if decoded is None:
            continue
        # Skip if replacement produces junk
        if len(decoded) < 3 or not any(c.isalpha() for c in decoded):
            continue
        replacement = f"'{decoded}'"
        txt = txt[:m.start()] + replacement + txt[m.end():]
        stages.append(Stage(
            n=len(stages) + 1,
            technique="Decode Base64 payload",
            evidence=(f"Statically evaluated `[Convert]::FromBase64String` on a "
                       f"{len(blob)}-char blob."),
            before=blob[:80], after=decoded[:200],
        ))
        changed = True
        break
    return txt, changed


# ── Boundary detection ───────────────────────────────────────────
_BOUNDARY_RE = re.compile(
    r"\b(invoke-expression|iex|invoke-command|start-process|"
    r"add-type|reflection\.assembly|new-object\s+system\.reflection|"
    r"comobject|wmiobject|com\.activate)\b",
    re.IGNORECASE,
)


def _detect_boundary(txt: str) -> str | None:
    m = _BOUNDARY_RE.search(txt)
    return m.group(1) if m else None


# ── Public entrypoint ────────────────────────────────────────────
def deobfuscate(script: str) -> DeobfuscationReport:
    """Run the recursive deterministic decode loop."""
    r = DeobfuscationReport(original=script or "", final=script or "")
    if not script:
        r.stopped_reason = "empty input"
        return r
    current = script
    for _ in range(MAX_STAGES):
        prev = current
        current, _ = _resolve_backticks(current, r.stages)
        current, _ = _resolve_format(current, r.stages)
        current, _ = _resolve_concat(current, r.stages)
        current, _ = _resolve_numeric_char_reconstruction(current, r.stages)
        current, _ = _resolve_static_base64(current, r.stages)
        current, _ = _resolve_aliases(current, r.stages)
        if current == prev:
            r.stopped_reason = "fixed_point (no further deterministic transforms)"
            break
    else:
        r.stopped_reason = f"max_stages ({MAX_STAGES}) reached"

    # After the loop, check if a true execution boundary remains
    boundary = _detect_boundary(current)
    if boundary:
        r.boundary_op = boundary
        if r.stopped_reason.startswith("fixed_point"):
            r.stopped_reason = (
                f"execution boundary — `{boundary}` present; further evaluation "
                "would require running PowerShell (intentionally skipped).")
    r.final = current
    return r
