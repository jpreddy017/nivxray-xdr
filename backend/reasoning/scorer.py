"""NivXRay reasoning — linguistic scorer.

Two-tier design (per user's 3C spec):
  1. **Keyword hits** — highest signal. English common words, PowerShell/CMD
     keywords, LOLBAS-oid tokens, URL/JSON/HTML markers. Weighted heavy.
  2. **English bigram model** — cheap n-gram frequency table (top-256 bigrams
     from a standard English corpus). Tiebreaker for cases where keywords
     don't fire (short strings, plain prose).

The final `linguistic_score(text)` returns a scalar in [0.0, 1.0].

Design rules:
  - Deterministic, offline, zero deps beyond stdlib.
  - Symmetric: score of empty / gibberish / pure noise ≈ 0.
  - Score of clean English or a recognizable command ≈ ≥ 0.55.
  - Score of encoded/base64/hex/random blob ≈ ≤ 0.25.
"""
from __future__ import annotations

import math
import re
from typing import Any, Dict


# ------------------------------------------------------------------ #
# Keyword dictionaries
# ------------------------------------------------------------------ #
_COMMON_ENGLISH = set(
    """
    the be to of and a in that have i it for not on with he as you do at this
    but his by from they we say her she or an will my one all would there their
    what so up out if about who get which go me when make can like time no just
    him know take people into year your good some could them see other than then
    now look only come its over think also back after use two how our work first
    well way even new want because any these give day most us
    """.split()
)

# Malware / DFIR analyst-facing keywords. Hitting one of these on a decoded
# candidate is a STRONG signal we peeled the right layer.
_ANALYST_KEYWORDS = set(
    """
    powershell pwsh cmd bash zsh sh iex invoke expression command downloader
    downloadstring downloadfile downloaddata webclient webrequest bitstransfer
    frombase64string convertfrom nop noprofile enc encodedcommand hidden
    invoke-webrequest invoke-restmethod new-object system reflection assembly
    virtualalloc createthread writeprocessmemory getprocaddress loadlibrary
    kernel32 ntdll advapi32 mimikatz cobaltstrike meterpreter beacon empire
    nishang lolbas certutil bitsadmin mshta rundll32 regsvr32 wmic schtasks
    reg add reg query wmic whoami hostname ipconfig uname systeminfo net user
    net group net view net use net localgroup net share tasklist qwinsta
    quser query session curl wget nc netcat ssh scp sftp ftp telnet ping
    tracert nslookup dig host arp route netstat nbtstat
    http https url domain ip ipv4 ipv6 mail email password user admin login
    file open close create delete run start stop server client key token
    secret cert cred config attack exploit payload shellcode backdoor rootkit
    trojan phish encode decode encrypt decrypt malware ransomware stealer
    """.split()
)

# Short 2-3 char keyword tokens (case-insensitive substring hits). Kept
# separate because they'd swamp _ANALYST_KEYWORDS with false positives
# under whole-word matching.
_SHORT_TOKENS = ("IEX", "IE_X", "AMSI", "GPO", "UAC", "PDB", "PID", "TID", "RVA")


# ------------------------------------------------------------------ #
# Small English bigram frequency table (top-64 by relative frequency)
# Source: pruned from Peter Norvig's `count_2l.txt` / Cornell corpus.
# Numbers are relative log-probabilities normalized to [0.0, 1.0].
# ------------------------------------------------------------------ #
_BIGRAM_WEIGHTS: Dict[str, float] = {
    "th": 1.00, "he": 0.98, "in": 0.92, "er": 0.90, "an": 0.88, "re": 0.85,
    "on": 0.83, "at": 0.82, "en": 0.80, "nd": 0.79, "ti": 0.78, "es": 0.77,
    "or": 0.76, "te": 0.75, "of": 0.74, "ed": 0.73, "is": 0.72, "it": 0.71,
    "al": 0.70, "ar": 0.69, "st": 0.68, "to": 0.67, "nt": 0.66, "ng": 0.65,
    "se": 0.64, "ha": 0.63, "as": 0.62, "ou": 0.61, "io": 0.60, "le": 0.59,
    "ve": 0.58, "co": 0.57, "me": 0.56, "de": 0.55, "hi": 0.54, "ri": 0.53,
    "ro": 0.52, "ic": 0.51, "ne": 0.50, "ea": 0.49, "ra": 0.48, "ce": 0.47,
    "li": 0.46, "ch": 0.45, "ll": 0.44, "be": 0.43, "ma": 0.42, "si": 0.41,
    "om": 0.40, "ur": 0.39, "ca": 0.38, "el": 0.37, "ta": 0.36, "la": 0.35,
    "ns": 0.34, "di": 0.33, "fo": 0.32, "ho": 0.31, "pe": 0.30, "ec": 0.29,
    "pr": 0.28, "no": 0.27, "ct": 0.26, "us": 0.25, "ac": 0.24, "ot": 0.23,
    "il": 0.22, "tr": 0.21, "ly": 0.20, "nc": 0.19, "et": 0.18, "ut": 0.17,
    "ss": 0.16, "so": 0.15, "rt": 0.14, "ad": 0.13, "wi": 0.12, "sa": 0.11,
    "id": 0.10, "we": 0.09,
}

_WORD_RE = re.compile(r"[A-Za-z][A-Za-z']{1,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]{16,}$")
_BASE64_ONLY = re.compile(r"^[A-Za-z0-9+/=]{16,}$")


def _bigram_frequency(text: str) -> float:
    """Return an average bigram-weight score over [0, 1]."""
    letters = "".join(c.lower() for c in text if c.isalpha())
    if len(letters) < 3:
        return 0.0
    total = 0.0
    n = 0
    for i in range(len(letters) - 1):
        bg = letters[i : i + 2]
        total += _BIGRAM_WEIGHTS.get(bg, 0.0)
        n += 1
    return total / max(n, 1)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    N = len(text)
    return -sum((c / N) * math.log2(c / N) for c in freq.values())


def _keyword_hits(text: str) -> Dict[str, int]:
    hits = {"english": 0, "analyst": 0, "short": 0}
    words = _WORD_RE.findall(text.lower())
    for w in words:
        if w in _COMMON_ENGLISH:
            hits["english"] += 1
        if w in _ANALYST_KEYWORDS:
            hits["analyst"] += 1
    for tok in _SHORT_TOKENS:
        if tok.lower() in text.lower():
            hits["short"] += 1
    return hits


def score_breakdown(text: str) -> Dict[str, Any]:
    """Full breakdown — used by explainer + tests."""
    if not text or not isinstance(text, str):
        return {
            "score": 0.0, "keyword_score": 0.0, "bigram_score": 0.0,
            "printable_ratio": 0.0, "entropy": 0.0, "length": 0,
            "hits": {"english": 0, "analyst": 0, "short": 0},
            "reasons": ["empty"],
        }
    L = len(text)
    if L > 200_000:
        return {
            "score": 0.0, "keyword_score": 0.0, "bigram_score": 0.0,
            "printable_ratio": 0.0, "entropy": 0.0, "length": L,
            "hits": {"english": 0, "analyst": 0, "short": 0},
            "reasons": ["too-long"],
        }

    stripped = text.strip()

    # Fast rejections — pure hex / base64 blobs get NEAR-ZERO linguistic score
    # (they might still be valid downstream data, but they're not linguistically
    # meaningful to a human reader).
    encoded_penalty = 0.0
    reasons = []
    if _HEX_ONLY.match(stripped):
        encoded_penalty = 0.85
        reasons.append("pure-hex-blob")
    elif _BASE64_ONLY.match(stripped):
        encoded_penalty = 0.75
        reasons.append("pure-base64-blob")

    printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in "\r\n\t")
    printable_ratio = printable / max(L, 1)

    hits = _keyword_hits(text)
    word_count = max(len(_WORD_RE.findall(text)), 1)

    # Keyword tier — cap contribution so a single analyst keyword doesn't
    # produce a 1.0 score. Each analyst hit is worth 0.35, capped total 0.70.
    keyword_score = min(
        0.35 * hits["analyst"] + 0.10 * hits["english"] / word_count
        + 0.05 * hits["short"],
        0.85,
    )
    if _URL_RE.search(text):
        keyword_score = min(keyword_score + 0.20, 0.85)
        reasons.append("url")

    # Bigram tier — capped at 0.55 so it can't shadow keyword hits.
    bigram_score = min(_bigram_frequency(text) * 0.65, 0.55)

    # Combine — sum with a printable-ratio prefactor, then subtract encoded
    # penalty. Never negative.
    combined = keyword_score + bigram_score * (0.4 + 0.6 * (1 - encoded_penalty))
    combined *= max(printable_ratio, 0.20)
    combined = max(combined - encoded_penalty, 0.0)

    ent = _entropy(text)
    # Extreme entropy (7.5+) is a strong "still encoded / random" signal.
    if ent >= 7.5 and printable_ratio < 0.95:
        combined *= 0.35
        reasons.append(f"high-entropy={ent:.2f}")

    combined = round(min(combined, 1.0), 4)
    if hits["analyst"]:
        reasons.append(f"analyst-hits={hits['analyst']}")
    if hits["english"]:
        reasons.append(f"english-hits={hits['english']}")
    return {
        "score": combined,
        "keyword_score": round(keyword_score, 4),
        "bigram_score": round(bigram_score, 4),
        "printable_ratio": round(printable_ratio, 4),
        "entropy": round(ent, 3),
        "length": L,
        "hits": hits,
        "reasons": reasons,
    }


def linguistic_score(text: str) -> float:
    """Convenience — return only the scalar score."""
    return score_breakdown(text)["score"]
