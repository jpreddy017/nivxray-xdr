"""NivXRay — Automated payload extraction & sanitization.

Prevents decoding failures caused by programming-syntax tokens (brackets,
variable declarations, cmdlet names) contaminating the raw data payload.

Given a text block containing an encapsulated encoded string (e.g. a PowerShell
`[System.Convert]::FromBase64String('...')` call or a bash
`echo 'aGVs...' | base64 -d` line), returns the raw payload string suitable for
direct feed into a downstream decoder recipe.

Rule spec:
  1. IDENTIFY ENCAPSULATION SYMBOLS — single/double quotes, PowerShell here-strings.
  2. DATA-STRING ISOLATION —
        * Pattern 1 (quoted):   /(?<=['\"])[A-Za-z0-9+/]{30,}(={0,2})(?=['\"])/
        * Pattern 2 (generic):  /\b[A-Za-z0-9+/]{40,}(={0,2})\b/
     Return the LONGEST match.
  3. STRIP WRAPPERS — remove PowerShell / Bash markers, brackets, parens, `$`.
  4. OUTPUT — a single, uninterrupted base64-alphabet-only string.
"""
from __future__ import annotations
import re
from typing import Optional

# Base64 alphabet only (no whitespace)
_B64_ALPHA_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# JWT shape: header.payload.signature (base64url, dot-separated).
# JWTs are a legitimate structured format — do NOT strip their segments.
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*$")

# Pattern 1 — the longest base64-run inside a matched quote pair.
# We accept ≥20 chars (down from the 30-char rule) because quotes are a
# high-confidence encapsulation signal — false positives are rare inside a
# matched pair AND we still enforce the strict base64 alphabet.
_QUOTED_RE = re.compile(
    r"(?:'|\"|@'|@\")\s*([A-Za-z0-9+/]{12,}={0,2})\s*(?:'|\"|'@|\"@)",
)

# Pattern 2 — generic fallback: any base64 alphabet run of ≥40 chars
_GENERIC_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")

# Fully-qualified or defanged URL — used by the final fallback to avoid
# collapsing command-line tokens into a bogus "base64 blob" when a real
# IOC is present in the input (e.g. `bitsadmin /transfer j1 http://…`).
_URL_IN_TEXT = re.compile(
    r"https?://[^\s'\"<>]+|hxxps?://[^\s'\"<>]+",
    re.IGNORECASE,
)

# Programming-syntax markers to strip when we DON'T find a quoted payload —
# gives the generic pattern a cleaner buffer to run against.
_WRAPPERS = [
    r"\[System\.Convert\]::FromBase64String",
    r"\[Byte\[\]\]",
    r"\[System\.Text\.Encoding\][\w:.()\"']+",
    r"-EncodedCommand",
    r"-encoded(?:command)?\b",
    r"-enc\b",
    r"-ec\b",
    r"-e\b",
    r"-nop\b",
    r"-noni?\b",
    r"-w\s+hidden",
    r"-windowstyle\s+hidden",
    r"-executionpolicy\s+bypass",
    r"\bpowershell(?:\.exe)?\b",
    r"\bpwsh(?:\.exe)?\b",
    r"\bIEX\b",
    r"\bInvoke-Expression\b",
    r"\becho\s+",
    r"\|\s*base64\s*-d\b",
    r"\|\s*bash\b",
    r"\|\s*sh\b",
    r"\beval\b",
    r"\$var_code",
    r"\$[A-Za-z_]\w*",           # any $variable
    r"[\[\](){}]",               # brackets/parens/braces
]
_WRAPPER_RE = re.compile("|".join(_WRAPPERS), re.IGNORECASE)


def _is_clean_base64(text: str) -> bool:
    """True iff every char in `text` (whitespace-stripped) is a base64 char."""
    s = re.sub(r"\s+", "", text)
    return bool(s) and bool(_B64_ALPHA_RE.match(s))


# ---------------------------------------------------------------------------
# Multi-stage helpers — used by the recursive decode-and-route pipeline to
# re-scan the OUTPUT of a previous decoder for further nested payloads.
# ---------------------------------------------------------------------------

def find_all_base64_spans(text: str, min_len: int = 20) -> list:
    """Return every base64 span (quoted-first, then generic) sorted by length DESC.

    Used to chain e.g. `base64 → gzip → *inner* base64 → xor` where the second
    base64 lives INSIDE the decompressed PowerShell body.
    """
    if not text:
        return []
    hits = []
    for m in _QUOTED_RE.finditer(text):
        s = m.group(1)
        if len(s) >= min_len and _is_clean_base64(s):
            hits.append(s)
    # generic fallback — only fill in gaps the quoted rule missed
    for m in _GENERIC_RE.finditer(text):
        s = m.group(1)
        if len(s) >= max(min_len, 40) and _is_clean_base64(s) and s not in hits:
            hits.append(s)
    # de-dupe while preserving order, then sort by len desc for LIFO consumption
    seen = set(); out = []
    for h in hits:
        if h not in seen:
            seen.add(h); out.append(h)
    out.sort(key=len, reverse=True)
    return out


# Match XOR keys inside common obfuscator patterns. We recognise:
#   PowerShell:  -bxor 35      (int)
#                -bxor 0x23    (hex)
#                -bxor 'A'     (single-char string)
#   Python/JS:   ^ 0x35        (inside a loop body)
#   C/asm:       xor eax, 0x35 / xor byte ptr [rax], 0x35
#   Analyst-provided hint:     # xor-key 0x35  |  // xor-key 42  |  ; xor key = 0x2A
_XOR_PATTERNS = [
    re.compile(r"-bxor\s+0x([0-9A-Fa-f]{1,2})\b"),                # -bxor 0x35
    re.compile(r"-bxor\s+(\d{1,3})\b"),                            # -bxor 35
    re.compile(r"-bxor\s+['\"](.)['\"]"),                          # -bxor 'A'
    re.compile(r"\^\s*0x([0-9A-Fa-f]{1,2})\b"),                    # ^ 0x35
    re.compile(r"\bxor\s+(?:byte\s+ptr\s*)?\[?\w+\]?\s*,\s*0x([0-9A-Fa-f]{1,2})\b", re.I),
    # Analyst-provided key hints in code comments — very common when an
    # analyst extracts a partial payload and annotates the key OOB.
    re.compile(r"(?:#|//|;)\s*xor[\s\-_]*key\s*[:=]?\s*0x([0-9A-Fa-f]{1,2})\b", re.I),
    re.compile(r"(?:#|//|;)\s*xor[\s\-_]*key\s*[:=]?\s*(\d{1,3})\b", re.I),
]


def find_xor_key(text: str):
    """Parse an XOR key from PowerShell / JS / asm-flavoured obfuscator syntax.

    Returns an int in [0..255] or ``None``. Sample real-world triggers:
      $var_code[$x] = $var_code[$x] -bxor 35
      $b -bxor 0x2A
      xor eax, 0x35
    """
    if not text:
        return None
    for pat in _XOR_PATTERNS:
        m = pat.search(text)
        if not m:
            continue
        raw = m.group(1)
        try:
            # single-char case (came from a quoted literal)
            if len(raw) == 1 and not raw.isdigit():
                return ord(raw) & 0xFF
            # Decimal vs hex — patterns that ALWAYS capture a decimal group
            # begin with either `-bxor\s+(\d` OR carry the `xor-key ... \d`
            # comment shape. Both cases have the marker `\d{1,3})\b` at the
            # END of the pattern. Every other pattern captures a hex digit
            # group.
            is_decimal = pat.pattern.endswith(r"(\d{1,3})\b") or pat.pattern.endswith(r"(\d{1,3}\b")
            v = int(raw, 10) if is_decimal else int(raw, 16)
            if 0 <= v <= 255:
                return v
        except ValueError:
            continue
    return None


def sanitize_encapsulated_payload(text: str) -> Optional[str]:
    """Extract the raw base64 payload from an encapsulated script snippet.

    Returns:
      - The longest clean base64-alphabet-only string suitable for decoding, OR
      - ``None`` if no candidate can be extracted with confidence.

    The rule ONLY runs if the input is NOT already clean base64. Clean inputs
    pass through untouched (returning ``None`` — the caller keeps the original).
    """
    if not text:
        return None

    stripped = text.strip()

    # JWT-shape? Leave it alone — jwt-decode handles it as a whole.
    if _JWT_RE.match(stripped):
        return None

    # Fast-path: input is already clean base64 (whitespace tolerated).
    if _is_clean_base64(stripped):
        return None

    # ── ASCII-decimal stream detector ────────────────────────────────────
    # A comma / whitespace-separated stream of small ints is NOT a base64
    # payload — the sanitizer's last-resort collapse (`[,\s;`]` stripped)
    # would otherwise glue every token into one giant digit run that later
    # gets mis-classified as base64. Bail out early so the ascii-decimal
    # candidate can fire in the magic decoder.
    _tokens = re.findall(r"\d+", stripped)
    if len(_tokens) >= 8:
        realistic = sum(1 for t in _tokens if 0 <= int(t) <= 255)
        # Everything that ISN'T a digit must be whitespace, comma, semicolon
        # or bracket — the shape of an obfuscated integer list.
        non_digit = re.sub(r"\d+", "", stripped)
        non_digit_clean = re.sub(r"[\s,;()\[\]{}|]+", "", non_digit)
        if (
            realistic / len(_tokens) >= 0.80
            and len(non_digit_clean) < 4    # essentially just separators
        ):
            return None

    # ── URL-present guard ─────────────────────────────────────────────────
    # If the ORIGINAL text contains a URL / defanged URL, we NEVER isolate a
    # base64 span — the wrapper text carries the primary IOC and the caller
    # (extract-url / regex-based IOC extractor) needs to see it verbatim.
    # This prevents "key blob" false positives when analyst notes embed both
    # a base64 key AND a plaintext URL (aes_cbc_analyst / rc4_analyst).
    if _URL_IN_TEXT.search(text):
        return None

    # Step 2 — try quoted-pattern extraction FIRST (highest fidelity).
    quoted_hits = _QUOTED_RE.findall(text)
    if quoted_hits:
        best = max(quoted_hits, key=len)
        if _is_clean_base64(best):
            return best

    # Step 3 — strip common wrapper syntax, then try generic pattern.
    scrubbed = _WRAPPER_RE.sub(" ", text)
    generic_hits = _GENERIC_RE.findall(scrubbed)
    if generic_hits:
        best = max(generic_hits, key=len)
        if _is_clean_base64(best):
            return best

    # Final fallback — collapse whitespace + drop obvious separators, then look
    # for a large base64 run.
    collapsed = re.sub(r"[\s,;`]", "", scrubbed)
    generic_hits2 = _GENERIC_RE.findall(collapsed)
    if generic_hits2:
        best = max(generic_hits2, key=len)
        if _is_clean_base64(best):
            return best

    return None
