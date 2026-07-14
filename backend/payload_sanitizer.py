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

# Pattern 1 — the longest base64-run inside a matched quote pair.
# We accept ≥20 chars (down from the 30-char rule) because quotes are a
# high-confidence encapsulation signal — false positives are rare inside a
# matched pair AND we still enforce the strict base64 alphabet.
_QUOTED_RE = re.compile(
    r"(?:'|\"|@'|@\")\s*([A-Za-z0-9+/]{20,}={0,2})\s*(?:'|\"|'@|\"@)",
)

# Pattern 2 — generic fallback: any base64 alphabet run of ≥40 chars
_GENERIC_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")

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

    # Fast-path: input is already clean base64 (whitespace tolerated).
    if _is_clean_base64(stripped):
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
