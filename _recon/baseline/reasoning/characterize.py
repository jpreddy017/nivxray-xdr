"""NivXRay reasoning — Phase 1: Input Characterization.

Classify raw text into one of a fixed set of profiles + attach priors
(candidate operations most likely to succeed).

Kinds:
    structured_container   Binary magic (gzip/zlib/lzma/bzip2/pe/elf) present.
    encoded_blob           Base64 / hex / base32 / base85 / ascii-decimal.
    text_like              Mostly letters + punctuation, low entropy.
                           This is where substitution ciphers live.
    script_wrapper         Contains a script wrapper (PowerShell, JS, VB, bash)
                           with an obvious payload inside.
    mixed                  Everything else — default to full candidate race.

The classification is DETERMINISTIC and CHEAP; it is used to *bias*
candidate ordering, not to overrule it. Base64 detection still fires
independently in magic_decoder for any input.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class InputProfile:
    kind: str
    entropy: float
    length: int
    letter_ratio: float
    digit_ratio: float
    punct_ratio: float
    space_ratio: float
    non_printable_ratio: float
    upper_ratio: float
    priors: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "kind": self.kind, "entropy": round(self.entropy, 3),
            "length": self.length,
            "letter_ratio": round(self.letter_ratio, 3),
            "digit_ratio": round(self.digit_ratio, 3),
            "punct_ratio": round(self.punct_ratio, 3),
            "space_ratio": round(self.space_ratio, 3),
            "non_printable_ratio": round(self.non_printable_ratio, 3),
            "upper_ratio": round(self.upper_ratio, 3),
            "priors": self.priors,
            "reasons": self.reasons,
        }


_SCRIPT_MARKERS = re.compile(
    r"(?:powershell|-enc(?:odedcommand)?|\$env:|FromBase64String|"
    r"Invoke-Expression|IEX|\bfunction\b|\bvar\s+\w+\s*=|"
    r"<script|eval\s*\(|atob\s*\(|new-object|net\.webclient|"
    r"cmd(?:\.exe)?\s+/c|for\s*/[flrd]\s|@echo\s+off)",
    re.IGNORECASE,
)

_BASE64_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")
_HEX_ALPHABET = re.compile(r"^[0-9a-fA-F\s]+$")
_BASE32_ALPHABET = re.compile(r"^[A-Z2-7=\s]+$", re.IGNORECASE)
_ASCII_DECIMAL = re.compile(r"^[\d\s,]+$")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    N = len(text)
    return -sum((c / N) * math.log2(c / N) for c in freq.values())


def characterize(text: str) -> InputProfile:
    if not text:
        return InputProfile(kind="empty", entropy=0.0, length=0,
                            letter_ratio=0.0, digit_ratio=0.0,
                            punct_ratio=0.0, space_ratio=0.0,
                            non_printable_ratio=0.0, upper_ratio=0.0,
                            priors=[], reasons=["empty"])
    L = len(text)
    letters = sum(1 for c in text if c.isalpha())
    digits = sum(1 for c in text if c.isdigit())
    spaces = sum(1 for c in text if c.isspace())
    punct = sum(1 for c in text if not c.isalnum() and not c.isspace() and c.isprintable())
    non_printable = sum(1 for c in text if not c.isprintable() and c not in "\r\n\t")
    uppers = sum(1 for c in text if c.isupper())
    ent = _entropy(text)
    profile = InputProfile(
        kind="mixed", entropy=ent, length=L,
        letter_ratio=letters / L, digit_ratio=digits / L,
        punct_ratio=punct / L, space_ratio=spaces / L,
        non_printable_ratio=non_printable / L,
        upper_ratio=uppers / max(letters, 1),
    )

    raw = text
    stripped = text.strip()

    # ── Binary container magic ─────────────────────────────────────
    if raw.startswith("\x1f\x8b"):
        profile.kind = "structured_container"
        profile.priors = ["gzip-decompress"]
        profile.reasons.append("gzip-magic")
        return profile
    if raw.startswith("\x78\x9c") or raw.startswith("\x78\xda") or raw.startswith("\x78\x01"):
        profile.kind = "structured_container"
        profile.priors = ["zlib-decompress"]
        profile.reasons.append("zlib-magic")
        return profile
    if raw.startswith("\xfd7zXZ"):
        profile.kind = "structured_container"
        profile.priors = ["lzma-decompress"]
        profile.reasons.append("lzma-magic")
        return profile
    if raw.startswith("BZh"):
        profile.kind = "structured_container"
        profile.priors = ["bzip2-decompress"]
        profile.reasons.append("bzip2-magic")
        return profile
    if raw.startswith("MZ") or raw.startswith("\x7fELF"):
        profile.kind = "structured_container"
        profile.priors = ["shellcode-terminal"]
        profile.reasons.append("pe-elf-magic")
        return profile

    # ── Script wrapper detection ────────────────────────────────────
    if _SCRIPT_MARKERS.search(text):
        profile.kind = "script_wrapper"
        profile.priors = ["extract-payload", "powershell-encoded",
                          "powershell-deobfuscate"]
        profile.reasons.append("script-marker")
        return profile

    compact = re.sub(r"\s+", "", stripped)

    # ── Encoded blob (base64/hex/base32/ascii-decimal) ─────────────
    # Rules to AVOID misclassifying prose:
    #   - Prose has spaces + short words; encoded blobs typically don't.
    #   - Prose has vowels; hex blobs (a-f only) either fail or have very few
    #     English words present.
    #   - Base32/Base64 encoded_blob requires HIGH entropy (real base64 sits
    #     around 5.5-6.0 bits/byte) — plain English is < 4.8.
    n_words = len(re.findall(r"\b[A-Za-z]{2,}\b", stripped))
    # Consider "has whitespace" as a strong negative signal for encoded_blob:
    # real base64/hex payloads may have whitespace from line-wrapping, but
    # prose typically has 1 space per 5-7 chars vs. base64's rare whitespace.
    high_space = profile.space_ratio > 0.10 and n_words >= 4

    if compact and len(compact) >= 16 and not high_space:
        if _HEX_ALPHABET.match(stripped) and len(compact) % 2 == 0:
            profile.kind = "encoded_blob"
            profile.priors = ["hex-decode"]
            profile.reasons.append("hex-alphabet")
            return profile
        # Base32 (must NOT contain 0,1,8,9,+,/,-)
        if (_BASE32_ALPHABET.match(stripped)
                and not re.search(r"[019+/\-a-z]", compact)
                and len(compact) % 8 in (0, 2, 4, 5, 7)
                and ent >= 4.2):
            profile.kind = "encoded_blob"
            profile.priors = ["base32-decode"]
            profile.reasons.append("base32-alphabet")
            return profile
        if _BASE64_ALPHABET.match(stripped) and ent >= 4.5:
            profile.kind = "encoded_blob"
            profile.priors = ["base64-decode"]
            profile.reasons.append("base64-alphabet")
            return profile
        # ASCII decimal codes (space or comma separated)
        if _ASCII_DECIMAL.match(stripped):
            profile.kind = "encoded_blob"
            profile.priors = ["ascii-decimal-decode"]
            profile.reasons.append("ascii-decimal-stream")
            return profile

    # ── Text-like — the KEY new branch for linguistic candidates ────
    # Heuristic: mostly letters + whitespace + typical punctuation,
    # low entropy (natural language ≈ 4.0-4.8), and NOT already
    # unambiguously encoded. This is where ROT-N, Atbash, Caesar,
    # and single-byte XOR live.
    #
    # STRICT gates to avoid misclassifying base64/hex:
    #   1. Must have SOME whitespace OR punctuation (natural text does).
    #   2. Digit ratio must be low (< 8%). Base64 has ~14% digits.
    #   3. Uppercase ratio must be < 55% (base64 is roughly 50-50 upper/lower).
    #   4. Compact length ≥ 16 base64/hex-shaped strings without whitespace
    #      already exited above.
    has_text_shape = (profile.space_ratio > 0.02
                      or profile.punct_ratio > 0.02
                      or L < 16)
    if (profile.letter_ratio + profile.space_ratio >= 0.55
            and profile.non_printable_ratio < 0.05
            and profile.digit_ratio < 0.08
            and profile.upper_ratio < 0.55
            and ent < 5.5
            and has_text_shape):
        profile.kind = "text_like"
        profile.priors = ["rot-n-brute", "atbash", "reverse", "xor-single-byte"]
        profile.reasons.append("text-shape")
        return profile

    # Everything else = mixed — deterministic pipeline handles it as today.
    profile.priors = []
    profile.reasons.append("mixed-shape")
    return profile
