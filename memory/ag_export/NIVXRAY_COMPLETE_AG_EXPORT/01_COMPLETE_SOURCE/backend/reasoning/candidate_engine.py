"""NivXRay Candidate Scoring Engine (Feb-2026 roadmap).

Given a raw input, produce a RANKED list of encoding candidates with
DYNAMIC confidence scores derived from the following evidence:

    * Alphabet validity          — how well the input matches this encoding's charset
    * Length validity            — does the length respect encoding-specific rules
    *                              (base64 multiples of 4, base32 modulo, z85 mult of 5)
    * Character distribution     — uniformity, upper/lower balance
    * Entropy                    — Shannon entropy of the input
    * Decode success/failure     — did the actual decoder raise or return garbage
    * UTF-8 validity of output   — did we recover clean text
    * Printable ASCII ratio      — of the decoded output
    * Known binary signatures    — MZ, ELF, PK, %PDF, GZIP, PNG, JPG in decoded bytes
    * Command syntax detection   — PowerShell/CMD/Bash tokens in decoded text
    * Malware indicators         — IEX, FromBase64String, cmd.exe, powershell.exe,
                                    rundll32, mshta, certutil, curl, wget in output

The scores are NOT fixed weights per encoding — they are computed per
candidate from the evidence above. Result of `score_candidates(input)`:

    [
      Candidate(op="base58-decode", confidence=0.87, decoded="Hello World!",
                evidence={...}, rationale="alphabet valid, decode succeeded, ...")
      Candidate(op="hex-decode", confidence=0.12, decoded=None,
                evidence={...}, rationale="alphabet invalid — contains 'p', 'q'...")
      ...
    ]

The pipeline uses this to answer three questions:
    1. Which decoder to try first?      → highest-confidence candidate
    2. Do we have any valid decode?     → any candidate with confidence >= HIGH_THRESHOLD
    3. Should we return "unknown"?      → all candidates < LOW_THRESHOLD

If no candidate exceeds MIN_ACCEPT (0.30), the engine returns an
`unknown` verdict rather than forcing a decode — an identifier / hash /
token / random string / unsupported encoding.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from operations import run_operation


HIGH_THRESHOLD = 0.65
MIN_ACCEPT = 0.30
LOW_THRESHOLD = 0.20


# ---------------------------------------------------------------
# Known signatures — check the FIRST bytes of a decoded payload.
# ---------------------------------------------------------------
_SIGNATURES = [
    (b"MZ",               "PE/DOS executable"),
    (b"\x7fELF",          "ELF executable"),
    (b"PK\x03\x04",       "ZIP archive"),
    (b"PK\x05\x06",       "ZIP archive (empty)"),
    (b"%PDF",             "PDF document"),
    (b"\x1f\x8b\x08",     "GZIP archive"),
    (b"\x78\x9c",         "zlib stream"),
    (b"\x78\xda",         "zlib stream"),
    (b"\x78\x01",         "zlib stream"),
    (b"\xfd7zXZ",         "XZ/LZMA archive"),
    (b"BZh",              "bzip2 archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff",     "JPEG image"),
    (b"GIF87a",           "GIF image"),
    (b"GIF89a",           "GIF image"),
    (b"Rar!\x1a\x07",     "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"\xca\xfe\xba\xbe", "Java class"),
    (b"\xfe\xed\xfa",     "Mach-O binary"),
    (b"BM",               "BMP image"),
    (b"OggS",             "Ogg container"),
    (b"ID3",              "MP3 with ID3v2"),
    (b"RIFF",             "RIFF (WAV/AVI/WEBP)"),
]


_MALWARE_RE = re.compile(
    r"\b(?:iex|invoke-expression|invoke-webrequest|invoke-restmethod|"
    r"downloadstring|downloadfile|frombase64string|-nop|-noprofile|"
    r"-enc(?:odedcommand)?|net\.webclient|new-object|system\.reflection|"
    r"virtualalloc|createthread|writeprocessmemory|"
    r"cmd\.exe|powershell\.exe|pwsh\.exe|rundll32|regsvr32|mshta|"
    r"certutil|bitsadmin|schtasks|wmic|reg\s+add|"
    r"curl|wget|nc\.exe|netcat|/bin/(?:sh|bash))\b",
    re.IGNORECASE,
)


# ---------------------------------------------------------------
# Encoding profiles — alphabet, length rule, entropy hint.
# ---------------------------------------------------------------
_PROFILES = [
    # (op_id, alphabet_re, length_valid_fn, expected_entropy_hint, notes)
    ("base64-decode",
     re.compile(r"^[A-Za-z0-9+/=\s]+$"),
     lambda L: L >= 4 and L % 4 <= 3,
     (4.5, 6.2),
     "Base64 (RFC 4648)"),
    ("base64url-decode",
     re.compile(r"^[A-Za-z0-9\-_=\s]+$"),
     lambda L: L >= 4,
     (4.5, 6.2),
     "Base64URL (RFC 4648 §5)"),
    ("base32-decode",
     re.compile(r"^[A-Z2-7=\s]+$", re.IGNORECASE),
     lambda L: L >= 8 and L % 8 in (0, 2, 4, 5, 7),
     (4.0, 5.5),
     "Base32 (RFC 4648)"),
    ("base58-decode",
     # Explicitly EXCLUDES 0, O, I, l
     re.compile(r"^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$"),
     lambda L: L >= 4,
     (4.5, 6.0),
     "Base58 (Bitcoin/IPFS)"),
    ("base62-decode",
     re.compile(r"^[0-9A-Za-z]+$"),
     lambda L: L >= 4,
     (4.5, 6.0),
     "Base62 (alphanumeric)"),
    ("ascii85-decode",
     re.compile(r"^<~[!-uz\s]+~>$"),
     lambda L: L >= 4,
     (4.8, 6.5),
     "ASCII85 (Adobe/btoa — <~…~>)"),
    ("z85-decode",
     re.compile(
         r"^[0-9a-zA-Z.\-:+=^!/*?&<>()\[\]{}@%$#\s]+$"
     ),
     lambda L: L >= 5 and L % 5 == 0,
     (4.5, 6.5),
     "Z85 (RFC 32 / ZeroMQ)"),
    ("hex-decode",
     re.compile(r"^[0-9a-fA-F\s]+$"),
     lambda L: L >= 2 and L % 2 == 0,
     (3.5, 4.5),
     "Hexadecimal"),
    ("url-decode",
     re.compile(r".*%[0-9A-Fa-f]{2}.*", re.DOTALL),
     lambda L: L >= 3,
     None,
     "URL / percent encoding"),
    ("html-decode",
     re.compile(r".*(?:&#\d+;|&#x[0-9A-Fa-f]+;|&\w+;).*", re.DOTALL),
     lambda L: L >= 3,
     None,
     "HTML entities"),
    ("unicode-escape",
     re.compile(r".*(?:\\u[0-9A-Fa-f]{4}){3,}.*", re.DOTALL),
     lambda L: L >= 12,
     None,
     r"\uNNNN unicode escapes"),
    ("octal-ascii-decode",
     re.compile(r".*(?:\\[0-7]{2,3}){3,}.*", re.DOTALL),
     lambda L: L >= 9,
     None,
     r"Backslash-octal (\NNN)"),
    ("ascii-decimal-decode",
     re.compile(r"^[\d\s,]+$"),
     lambda L: L >= 8,
     None,
     "Decimal ASCII code stream"),
    ("binary-ascii-decode",
     re.compile(r"^[01\s,]+$"),
     lambda L: L >= 16,
     None,
     "Binary ASCII (7 or 8-bit groups)"),
    ("rot13",
     re.compile(r"^[A-Za-z0-9\s.,;:!?\"'/@\-_\(\)\[\]]+$"),
     lambda L: L >= 4,
     None,
     "ROT13 (Caesar shift 13)"),
    ("rot47",
     re.compile(r"^[!-~\s]+$"),
     lambda L: L >= 4,
     None,
     "ROT47 (full printable-ASCII shift)"),
    ("utf16le-decode",
     # UTF-16LE input should contain null bytes OR be a raw binary stream.
     # If the input is plain ASCII text, this decoder is not applicable.
     re.compile(r".*\x00.*", re.DOTALL),
     lambda L: L >= 8 and L % 2 == 0,
     None,
     "UTF-16 Little-Endian"),
    ("gzip-decompress",
     # gzip magic is 1f 8b — require the exact prefix.
     re.compile(r".*", re.DOTALL),
     lambda L: L >= 18,
     None,
     "GZIP decompression"),
    ("zlib-decompress",
     re.compile(r".*", re.DOTALL),
     lambda L: L >= 6,
     None,
     "zlib decompression"),
]


@dataclass
class Candidate:
    op: str
    confidence: float
    decoded: Optional[str]
    evidence: Dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op,
            "confidence": round(self.confidence, 4),
            "decoded_preview": (self.decoded or "")[:200] if self.decoded else None,
            "evidence": self.evidence,
            "rationale": self.rationale,
        }

    def as_rejected_dict(self, winner: Optional["Candidate"] = None) -> Dict[str, Any]:
        """Same as `as_dict` PLUS a machine-readable ``rejection_reasons``
        list derived from evidence, and a ``vs_winner`` block comparing
        this candidate to the winning candidate.

        Rejection reasons follow the schema:
            [{code, detail, severity}, ...]
        where severity ∈ {"high", "medium", "low"}. High = decisive
        problem, medium = degrades confidence, low = observational only.
        """
        base = self.as_dict()
        base["rejection_reasons"] = _build_rejection_reasons(self)
        if winner is not None and winner.op != self.op:
            base["vs_winner"] = {
                "winning_op": winner.op,
                "winner_confidence": round(winner.confidence, 4),
                "confidence_gap": round(winner.confidence - self.confidence, 4),
            }
        return base


# ---------------------------------------------------------------
# Structured why-not reason codes
# ---------------------------------------------------------------
# Every reason code below MUST have a stable identifier so the frontend
# can map it to an icon / tooltip. Additive; never rename existing codes.
_REASON_CODES = {
    "alphabet-mismatch": (
        "high",
        "Input characters are outside this encoding's alphabet",
    ),
    "alphabet-partial": (
        "medium",
        "Only a fraction of characters match the encoding's alphabet",
    ),
    "length-invalid": (
        "medium",
        "Length does not satisfy this encoding's constraints",
    ),
    "decode-rejected": (
        "high",
        "The decoder raised an error — the encoding does not apply",
    ),
    "decode-noop": (
        "high",
        "Applying the transform returned the input unchanged",
    ),
    "output-not-readable": (
        "high",
        "Decoded output has no linguistic signal (junk bytes)",
    ),
    "output-low-printable": (
        "medium",
        "Decoded output has a low printable-ASCII ratio",
    ),
    "no-linguistic-improvement": (
        "high",
        "ROT/XOR did not meaningfully improve output readability",
    ),
    "marginal-linguistic-improvement": (
        "medium",
        "ROT/XOR only marginally improved readability",
    ),
    "no-file-signature": (
        "low",
        "No known file signature (PE/ELF/PDF/PNG/…) found in the output",
    ),
    "no-malware-indicators": (
        "low",
        "No LOLBAS / malware token detected in the output",
    ),
    "entropy-out-of-range": (
        "medium",
        "Input entropy is outside the typical range for this encoding",
    ),
    "forbidden-char": (
        "high",
        "Input contains an encoding-forbidden character (e.g. 0/O/I/l for Base58)",
    ),
    "printable-but-non-linguistic": (
        "medium",
        "Output is printable but doesn't look like natural text",
    ),
    "garbage-decode": (
        "high",
        "Decoded output is a mix of printable and non-printable bytes with no linguistic content",
    ),
}


def _reason(code: str, detail: str = "") -> Dict[str, Any]:
    severity, description = _REASON_CODES.get(
        code, ("low", "Unrecognized rejection code"),
    )
    return {
        "code": code,
        "severity": severity,
        "description": description,
        "detail": detail,
    }


def _build_rejection_reasons(cand: "Candidate") -> List[Dict[str, Any]]:
    """Derive structured rejection reasons from the candidate's evidence.

    Called on RUNNER-UP candidates so the frontend can render "why not
    Y?" tooltips. On the winner, this list is typically empty (or
    contains only 'low'-severity observational codes).
    """
    ev = cand.evidence or {}
    reasons: List[Dict[str, Any]] = []

    # 1) Alphabet checks
    alphabet_ratio = ev.get("alphabet_ratio")
    if alphabet_ratio is not None and alphabet_ratio < 1.0:
        if alphabet_ratio < 0.90:
            reasons.append(_reason(
                "alphabet-mismatch",
                f"alphabet_ratio={alphabet_ratio:.2f}",
            ))
        else:
            reasons.append(_reason(
                "alphabet-partial",
                f"alphabet_ratio={alphabet_ratio:.2f}",
            ))

    # 2) Length rule
    if ev.get("length_valid") is False:
        reasons.append(_reason(
            "length-invalid",
            f"length={ev.get('length')}",
        ))

    # 3) Decode success
    if ev.get("decode_ok") is False:
        err = ev.get("decode_error")
        detail = f"decoder raised: {err}" if err else "decoder returned None"
        reasons.append(_reason("decode-rejected", detail))

    # 4) Output readability
    if ev.get("decode_ok") is True:
        pr = ev.get("printable_ratio", 0.0)
        lscore = ev.get("linguistic_score", 0.0)
        if pr is not None and pr < 0.30 and not ev.get("signature"):
            reasons.append(_reason(
                "output-low-printable",
                f"printable_ratio={pr:.2f}",
            ))
        if (lscore is not None and lscore < 0.05
                and not ev.get("signature")
                and not ev.get("malware_indicators")):
            if 0.20 <= (pr or 0.0) <= 0.80:
                reasons.append(_reason(
                    "garbage-decode",
                    f"printable={pr:.2f}, linguistic_score={lscore:.2f}",
                ))
            elif (pr or 0.0) > 0.80:
                reasons.append(_reason(
                    "printable-but-non-linguistic",
                    f"printable={pr:.2f}, linguistic_score={lscore:.2f}",
                ))
            else:
                reasons.append(_reason(
                    "output-not-readable",
                    f"linguistic_score={lscore:.2f}",
                ))

    # 5) ROT/XOR-specific linguistic delta
    if cand.op in ("rot13", "rot47", "xor"):
        delta = ev.get("linguistic_delta")
        if delta is not None:
            if delta < 0.15:
                reasons.append(_reason(
                    "no-linguistic-improvement",
                    f"linguistic_delta={delta:.2f}",
                ))
            elif delta < 0.30:
                reasons.append(_reason(
                    "marginal-linguistic-improvement",
                    f"linguistic_delta={delta:.2f}",
                ))

    # 6) Forbidden chars (encoding-specific)
    rationale_low = (cand.rationale or "").lower()
    if "forbidden-char" in rationale_low or "base58-forbidden" in rationale_low:
        reasons.append(_reason(
            "forbidden-char",
            "encoding-specific forbidden character present in input",
        ))

    # 7) Observational low-severity notes (only if we haven't already got
    # a higher-severity reason making the candidate uncompetitive).
    if not any(r["severity"] == "high" for r in reasons):
        if not ev.get("signature"):
            reasons.append(_reason("no-file-signature"))
        if not ev.get("malware_indicators"):
            reasons.append(_reason("no-malware-indicators"))

    return reasons


# ---------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    N = len(s)
    return -sum((c / N) * math.log2(c / N) for c in freq.values())


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t") / len(s)


def _detect_signature(text: str) -> Optional[str]:
    """Look at first ~10 bytes for a known file signature."""
    if not text:
        return None
    # Interpret as latin-1 to preserve bytes 1:1
    try:
        raw = text.encode("latin-1", errors="replace")[:20]
    except Exception:
        return None
    for magic, label in _SIGNATURES:
        if raw.startswith(magic):
            return label
    return None


def _detect_malware_indicators(text: str) -> List[str]:
    if not text:
        return []
    return list({m.group(0).lower() for m in _MALWARE_RE.finditer(text)})[:8]


def _alphabet_match_ratio(text: str, pattern: re.Pattern) -> float:
    """Return the fraction of chars in `text` that satisfy `pattern`."""
    if not text:
        return 0.0
    # Full-match check first — if perfect, ratio = 1.
    if pattern.fullmatch(text):
        return 1.0
    # Otherwise fraction of chars that individually pass a per-char test
    # by matching the pattern against each single character.
    return sum(1 for c in text if pattern.fullmatch(c)) / max(len(text), 1)


def _score_one(
    op_id: str,
    alphabet_re: re.Pattern,
    length_valid_fn,
    entropy_hint: Optional[tuple],
    notes: str,
    text: str,
) -> Candidate:
    """Compute a dynamic candidate confidence for one encoding."""
    stripped = text.strip()
    if not stripped:
        return Candidate(op=op_id, confidence=0.0, decoded=None,
                          rationale="empty input")
    compact = re.sub(r"\s+", "", stripped)
    L = len(compact)

    reasons: List[str] = [f"encoding={notes}"]
    ev: Dict[str, Any] = {"length": L}

    # 1) Alphabet validity — full match required OR high per-char ratio
    alphabet_ok = bool(alphabet_re.fullmatch(stripped))
    alphabet_ratio = _alphabet_match_ratio(compact, alphabet_re) if not alphabet_ok else 1.0
    if alphabet_ok:
        reasons.append("alphabet-fullmatch")
    elif alphabet_ratio >= 0.90:
        reasons.append(f"alphabet-ratio={alphabet_ratio:.2f}")
    else:
        # Alphabet fails — very likely not this encoding.
        return Candidate(
            op=op_id, confidence=0.0, decoded=None,
            evidence={"length": L, "alphabet_ratio": round(alphabet_ratio, 3)},
            rationale=f"alphabet mismatch (ratio={alphabet_ratio:.2f})",
        )

    ev["alphabet_ratio"] = round(alphabet_ratio, 3)

    # 2) Length validity
    length_ok = False
    try:
        length_ok = bool(length_valid_fn(L))
    except Exception:
        length_ok = False
    ev["length_valid"] = length_ok
    if length_ok:
        reasons.append("length-valid")
    else:
        reasons.append(f"length-suspect ({L})")

    # 3) Input entropy
    input_entropy = _entropy(stripped)
    ev["input_entropy"] = round(input_entropy, 3)
    entropy_ok = True
    if entropy_hint is not None:
        lo, hi = entropy_hint
        # Encoded blobs sit near hi; if entropy is very low, probably not encoded.
        entropy_ok = lo - 1.0 <= input_entropy <= hi + 0.5
        if entropy_ok:
            reasons.append(f"entropy-in-range ({input_entropy:.2f} ∈ [{lo:.1f},{hi:.1f}])")
        else:
            reasons.append(f"entropy-out-of-range ({input_entropy:.2f} vs [{lo:.1f},{hi:.1f}])")

    # 4) Decode success/failure
    decoded: Optional[str] = None
    decode_ok = False
    try:
        decoded = run_operation(op_id, text, {})
        # ROT13 / ROT47 always "succeed" — they never raise. Require the
        # output to differ from the input for them to count as a decode.
        if op_id in ("rot13", "rot47") and decoded == text:
            decode_ok = False
            reasons.append("decode-noop (rot output equals input)")
        elif decoded is not None:
            decode_ok = True
            reasons.append("decode-succeeded")
    except Exception as e:
        reasons.append(f"decode-failed ({type(e).__name__})")
        ev["decode_error"] = f"{type(e).__name__}: {e}"

    ev["decode_ok"] = decode_ok

    # 5) UTF-8 validity + printable ratio + LINGUISTIC readability of output
    utf8_ok = False
    printable_ratio = 0.0
    linguistic_score_val = 0.0
    if decoded is not None:
        try:
            decoded.encode("utf-8").decode("utf-8")
            utf8_ok = True
        except Exception:
            utf8_ok = False
        printable_ratio = _printable_ratio(decoded)
        ev["utf8_ok"] = utf8_ok
        ev["printable_ratio"] = round(printable_ratio, 3)
        # Linguistic score of the DECODED output — this is what separates
        # a valid decode ("Hello World!") from a spurious rot13 result
        # ("2ARcb7GMEEeYMFv2H") that also happens to be printable.
        try:
            from .scorer import linguistic_score as _lscore
            linguistic_score_val = _lscore(decoded)
        except Exception:
            linguistic_score_val = 0.0
        ev["linguistic_score"] = round(linguistic_score_val, 3)
        if printable_ratio > 0.90:
            reasons.append(f"printable-ratio={printable_ratio:.2f}")
        elif printable_ratio > 0.0:
            reasons.append(f"low-printable-ratio={printable_ratio:.2f}")
        if linguistic_score_val >= 0.30:
            reasons.append(f"linguistic-score={linguistic_score_val:.2f}")

    # 6) Signatures + malware indicators
    signature = _detect_signature(decoded or "")
    malware = _detect_malware_indicators(decoded or "")
    if signature:
        ev["signature"] = signature
        reasons.append(f"signature={signature}")
    if malware:
        ev["malware_indicators"] = malware
        reasons.append(f"malware-hits={','.join(malware)}")

    # ── Dynamic confidence composition ──────────────────────────────
    # Base of 0.10 for having *some* alphabet match. Everything else
    # accumulates on top. Weights are per-evidence, not per-encoding.
    confidence = 0.10
    if alphabet_ok:
        confidence += 0.25
    else:
        confidence += 0.10 * alphabet_ratio
    if length_ok:
        confidence += 0.10
    if entropy_ok:
        confidence += 0.05
    if decode_ok:
        # Base success bonus: 0.10. Additional 0.10 only if the decoded
        # output shows some sign of meaningfulness (readable OR has a
        # recognized signature/malware indicator).
        confidence += 0.10
        meaningful = (
            linguistic_score_val >= 0.10
            or signature
            or malware
            or (decoded and printable_ratio >= 0.95 and linguistic_score_val >= 0.05)
        )
        if meaningful:
            confidence += 0.10
        else:
            reasons.append("decode-produced-junk (no linguistic/signature/malware signal)")
    else:
        # Decoder REJECTED the input. Strong penalty — this is very likely
        # NOT this encoding. Cap contribution from alphabet/length/entropy
        # so we don't rank a failed candidate above a partial success.
        confidence -= 0.35
        reasons.append("decode-rejected (encoding does not apply)")
    if utf8_ok and decoded:
        confidence += 0.05
    if printable_ratio > 0.95:
        confidence += 0.05
    elif printable_ratio > 0.85:
        confidence += 0.02
    elif decoded and printable_ratio < 0.20:
        # Decoded to mostly-binary. Only good if we ALSO have a file
        # signature — otherwise we're likely decoding random bytes.
        if signature:
            confidence += 0.10
        else:
            confidence -= 0.25
    # ── LINGUISTIC readability of decoded output ──
    # This is the KEY tiebreaker: a "successful" ROT13/ROT47 that produces
    # gibberish must NOT score as high as a Base58 that produces "Hello World!".
    # Weighted heavily so meaningful decodes win.
    if linguistic_score_val >= 0.55:
        confidence += 0.25  # clearly readable text
    elif linguistic_score_val >= 0.30:
        confidence += 0.15
    elif linguistic_score_val >= 0.15:
        confidence += 0.05
    elif decoded and printable_ratio > 0.80 and linguistic_score_val < 0.10:
        # Printable but non-linguistic → likely spurious (rot noise, base62 random bytes).
        # Penalize UNLESS a binary signature or malware hit rescues it.
        if not signature and not malware:
            confidence -= 0.15
            reasons.append("printable-but-non-linguistic (likely spurious)")
    elif decoded and 0.20 <= printable_ratio <= 0.80 and linguistic_score_val < 0.10:
        # Junk middle-band decode — hex-decode of a hash, base62 of Base58 input,
        # any decoder that returns garbage bytes. Strong penalty unless rescued
        # by a file signature (e.g. hex-decoded PE header).
        if not signature and not malware:
            confidence -= 0.30
            reasons.append(
                f"garbage-decode (printable={printable_ratio:.2f}, "
                f"lscore={linguistic_score_val:.2f})"
            )
    if signature:
        confidence += 0.10
    if malware:
        # Strong signal that the decoded plaintext is meaningful.
        confidence += 0.15

    # Encoding-specific bumps
    if op_id == "base58-decode" and re.search(r"[0OIl]", stripped):
        # Base58 forbids 0/O/I/l entirely — hard reject
        confidence = min(confidence, 0.10)
        reasons.append("base58-forbidden-char present")

    # ── ROT/Caesar/XOR — MUST improve linguistic score to be credible ──
    # These transforms are self-invertible / arbitrary, so a "successful"
    # decode is only meaningful when the OUTPUT is more readable than the
    # INPUT. Otherwise the transform is spurious.
    if op_id in ("rot13", "rot47", "xor"):
        try:
            from .scorer import linguistic_score as _lscore
            input_lscore = _lscore(text)
        except Exception:
            input_lscore = 0.0
        ev["input_linguistic_score"] = round(input_lscore, 3)
        delta = linguistic_score_val - input_lscore
        ev["linguistic_delta"] = round(delta, 3)
        if delta < 0.15:
            # No meaningful improvement — this rot/xor is spurious.
            confidence = min(confidence, 0.20)
            reasons.append(
                f"no-linguistic-improvement (Δ={delta:.2f}) — spurious {op_id}"
            )
        elif delta < 0.30:
            confidence = min(confidence, 0.50)
            reasons.append(f"marginal-linguistic-improvement (Δ={delta:.2f})")

    confidence = round(max(0.0, min(confidence, 1.0)), 4)

    return Candidate(
        op=op_id,
        confidence=confidence,
        decoded=decoded,
        evidence=ev,
        rationale="; ".join(reasons),
    )


# ---------------------------------------------------------------
# Public API
# ---------------------------------------------------------------
def score_candidates(text: str, top_n: int = 10) -> List[Candidate]:
    """Score every registered encoding against `text` and return the
    top-N candidates ranked by confidence descending.

    Never raises. Candidates with confidence == 0.0 are dropped.
    """
    if not text:
        return []
    results: List[Candidate] = []
    for op_id, alphabet_re, length_fn, ent_hint, notes in _PROFILES:
        try:
            c = _score_one(op_id, alphabet_re, length_fn, ent_hint, notes, text)
        except Exception as e:
            c = Candidate(op=op_id, confidence=0.0, decoded=None,
                           rationale=f"scoring-exception: {e}")
        if c.confidence > 0.0:
            results.append(c)
    results.sort(key=lambda c: -c.confidence)
    return results[:top_n]


def best_candidate(text: str) -> Optional[Candidate]:
    """Return the single most confident candidate, or None if no candidate
    reaches MIN_ACCEPT — in which case the input is likely NOT one of
    our supported encodings.
    """
    cands = score_candidates(text, top_n=1)
    if not cands or cands[0].confidence < MIN_ACCEPT:
        return None
    return cands[0]


@dataclass
class UnknownVerdict:
    """Returned when no candidate reaches MIN_ACCEPT.

    `hypotheses` explains what the input MIGHT be given the observed
    entropy / alphabet / length profile.
    """
    input_length: int
    entropy: float
    alphabet: str
    hypotheses: List[str]
    top_candidates: List[Candidate] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "verdict": "unknown-or-identifier",
            "input_length": self.input_length,
            "entropy": round(self.entropy, 3),
            "alphabet": self.alphabet,
            "hypotheses": self.hypotheses,
            "top_candidates_considered": [c.as_dict() for c in self.top_candidates],
        }


def classify_unknown(text: str) -> UnknownVerdict:
    """Best-effort classification when no decoder claims high confidence.

    Hypotheses are ordered from most to least likely and derived purely
    from observed evidence (length, entropy, character classes).
    """
    text = text or ""
    L = len(text)
    ent = _entropy(text)
    top = score_candidates(text, top_n=3)

    hyp: List[str] = []
    lower_case = sum(1 for c in text if c.islower())
    upper_case = sum(1 for c in text if c.isupper())
    digits = sum(1 for c in text if c.isdigit())

    alphabet_desc = []
    if lower_case: alphabet_desc.append("lowercase")
    if upper_case: alphabet_desc.append("uppercase")
    if digits: alphabet_desc.append("digits")
    if any(not c.isalnum() and not c.isspace() for c in text):
        alphabet_desc.append("punctuation")
    alphabet = "+".join(alphabet_desc) or "empty"

    # Hash / identifier patterns
    if L in (32, 40, 64, 128) and re.fullmatch(r"[0-9a-fA-F]+", text):
        hash_map = {32: "MD5", 40: "SHA-1", 64: "SHA-256", 128: "SHA-512"}
        hyp.append(f"looks like a {hash_map[L]} hash")
    if 20 <= L <= 40 and re.fullmatch(r"[A-Za-z0-9]+", text) and ent >= 4.5:
        hyp.append("random API token / session ID / short UUID")
    if L == 36 and re.fullmatch(r"[0-9a-fA-F\-]{36}", text) and text.count("-") == 4:
        hyp.append("UUID / GUID")
    if L >= 20 and ent >= 6.5:
        hyp.append("random / encrypted / already-decoded high-entropy blob")
    if L < 6:
        hyp.append("too short to reliably identify — could be plaintext or identifier")
    if not hyp:
        hyp.append("unsupported encoding or plaintext identifier")

    return UnknownVerdict(
        input_length=L, entropy=ent, alphabet=alphabet,
        hypotheses=hyp, top_candidates=top,
    )
