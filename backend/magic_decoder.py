"""NivXRay — "Magic" recursive auto-decoder (CyberChef-parity).

Given a payload, tries every plausible decode operation, scores the output,
and recursively expands the best branches. Returns the top-N final results
sorted by score, plus the ordered recipe that produced each.

Scoring heuristics combine:
  - printable-ASCII ratio       (0-1)  — reward readable text
  - english-word density        (0-1)  — reward real words in the output
  - structure signatures        (bonus)  — JSON/HTML/URL/PS keywords/PE header/hex/utf-16
  - length sanity               (0-1)  — punish very short or absurdly long output
  - obfuscation entropy penalty (0-1)  — penalize very high entropy (still encrypted/random)

Time-boxed: max_depth (default 4) × max_branches (default 3), fully synchronous
and finishes in < 400 ms for typical inputs.
"""
from __future__ import annotations
import base64
import binascii
import math
import re
from typing import Any, Dict, List, Optional, Tuple

from operations import run_operation

# Small dictionary of common English words — used for word-density scoring.
_COMMON_WORDS = set("""
the be to of and a in that have i it for not on with he as you do at this but his by from they we
say her she or an will my one all would there their what so up out if about who get which go me
when make can like time no just him know take people into year your good some could them see other
than then now look only come its over think also back after use two how our work first well way
even new want because any these give day most us http https url domain ip ipv4 ipv6 mail email
password user admin login exit exec eval file open close create delete run start stop server client
key token secret cert cred config error debug info true false null void class function return
value string object list array count size length name host port script command process malware
attack exploit payload shellcode backdoor rootkit trojan phish encode decode encrypt decrypt
base64 hex url html json xml powershell bash python microsoft windows linux system network
""".split())

# Signatures that give big scoring bonuses.
_JSON_START = re.compile(r"^\s*[\[{]")
_URL_RE     = re.compile(r"https?://[^\s\"'<>]+")
_PS_KWORDS  = re.compile(r"\b(IEX|Invoke-Expression|Invoke-WebRequest|Net\.WebClient|DownloadString|DownloadFile|Add-MpPreference|New-Object|System\.Reflection|VirtualAlloc|CreateThread)\b", re.IGNORECASE)
_HTML_RE    = re.compile(r"<(?:html|body|script|iframe|div|a\s|meta|link)\b", re.IGNORECASE)
_PE_HEADER  = re.compile(r"^\s*MZ.{50,120}This program (?:cannot|must)", re.DOTALL)
_UTF16_HINT = re.compile(r"(?:[ -~]\x00){10,}")
_HEX_BLOB   = re.compile(r"^[0-9a-fA-F]{20,}$")


# =============================================================================
# Scoring
# =============================================================================
def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq: Dict[int, int] = {}
    for x in b:
        freq[x] = freq.get(x, 0) + 1
    return -sum((c / len(b)) * math.log2(c / len(b)) for c in freq.values())


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode("utf-8", errors="replace")
    printable = sum(1 for x in b if 32 <= x < 127 or x in (9, 10, 13))
    return printable / len(b)


def _english_density(s: str) -> float:
    words = re.findall(r"[A-Za-z][A-Za-z']{2,}", s.lower())
    if not words:
        return 0.0
    hits = sum(1 for w in words if w in _COMMON_WORDS)
    return hits / max(len(words), 1)


def _structure_bonus(s: str) -> Tuple[float, List[str]]:
    bonuses: List[str] = []
    total = 0.0
    if _JSON_START.match(s) and s.count("{") + s.count("[") >= 1:
        total += 0.20; bonuses.append("json-shape")
    if _URL_RE.search(s):
        total += 0.20; bonuses.append("url")
    if _PS_KWORDS.search(s):
        total += 0.35; bonuses.append("ps-keywords")
    if _HTML_RE.search(s):
        total += 0.15; bonuses.append("html")
    if _PE_HEADER.match(s):
        total += 0.30; bonuses.append("pe-header")
    if _UTF16_HINT.search(s):
        total += 0.20; bonuses.append("utf16-embedded")
    return total, bonuses


def score_output(s: str) -> Dict[str, Any]:
    """Return a scalar `score` (higher = better) plus a breakdown."""
    if not s:
        return {"score": 0.0, "reasons": ["empty"]}
    if len(s) > 200_000:
        return {"score": 0.0, "reasons": ["output-too-large"]}
    pr = _printable_ratio(s)
    ed = _english_density(s)
    ent = _entropy(s.encode("utf-8", errors="replace"))
    sb, bonuses = _structure_bonus(s)
    # normalize entropy penalty: 3.5-6 = healthy natural text, 6.5+ = likely still-encoded
    ent_penalty = max(0.0, (ent - 6.2) / 2.0)  # 0 at 6.2, ~1 at 8.2
    ent_penalty = min(ent_penalty, 0.35)
    # size sanity — prefer 20 to 20000 chars
    L = len(s)
    if L < 8:
        size_score = 0.1
    elif L > 20000:
        size_score = 0.5
    else:
        size_score = 1.0
    score = (0.30 * pr) + (0.30 * ed) + (0.15 * size_score) + sb - ent_penalty
    reasons = []
    if pr > 0.9: reasons.append(f"printable={pr:.2f}")
    if ed > 0.03: reasons.append(f"english-density={ed:.2f}")
    reasons.extend(bonuses)
    if ent_penalty > 0.05: reasons.append(f"entropy-penalty={ent_penalty:.2f} (entropy={ent:.2f})")
    return {
        "score": round(score, 4),
        "printable": round(pr, 3),
        "english": round(ed, 3),
        "entropy": round(ent, 3),
        "size": L,
        "reasons": reasons,
    }


# =============================================================================
# Candidate op selection
# =============================================================================
# Each candidate returns a list of (op_id, args) tuples to try given the input.
def _pick_candidates(payload: str) -> List[Dict[str, Any]]:
    cands: List[Dict[str, Any]] = []
    s = payload.strip()
    if not s:
        return cands
    # Base64 detection
    b64only = re.sub(r"\s+", "", s)
    if b64only and re.fullmatch(r"[A-Za-z0-9+/=_-]+", b64only) and len(b64only) >= 8:
        cands.append({"op": "base64-decode", "args": {}})
        cands.append({"op": "utf16-be-decode", "args": {}})
        cands.append({"op": "utf32-le-decode", "args": {}})
    # UTF-16LE hint — half the bytes are 0x00 in alternating positions
    if _UTF16_HINT.search(s) or "\x00" in s:
        cands.append({"op": "utf16le-decode", "args": {}})
    # Hex detection (≥ 20 chars, even length)
    if _HEX_BLOB.match(b64only) and len(b64only) % 2 == 0:
        cands.append({"op": "hex-decode", "args": {}})
    # URL-encoded
    if re.search(r"%[0-9A-Fa-f]{2}", s):
        cands.append({"op": "url-decode", "args": {}})
    # HTML entities
    if "&#" in s or re.search(r"&\w+;", s):
        cands.append({"op": "html-decode", "args": {}})
    # ROT13
    if re.fullmatch(r"[A-Za-z\s.,!?\"'\-]{10,}", s):
        cands.append({"op": "rot13", "args": {}})
    # PowerShell -EncodedCommand
    if re.search(r"-e(?:c|nc|ncoded(?:command)?)?\s+[A-Za-z0-9+/=\s]{16,}", s, re.IGNORECASE):
        cands.append({"op": "powershell-encoded", "args": {}})
    # JS charcode
    if "String.fromCharCode" in s:
        cands.append({"op": "js-charcode-decode", "args": {}})
    # JS \x-escapes
    if re.search(r"\\x[0-9a-fA-F]{2}", s):
        cands.append({"op": "js-hex-strings-decode", "args": {}})
    # gzip-ish (0x1f8b) detected via base64/hex → try base64 → gzip-decompress? handled by base64 first
    # ASCII85
    if s.startswith("<~") and s.endswith("~>"):
        cands.append({"op": "ascii85-decode", "args": {}})
    # JWT
    if re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", s):
        cands.append({"op": "jwt-decode", "args": {}})
    # Refang defanged IOCs
    if re.search(r"hxxps?://|\[\.\]|\[dot\]|\[at\]", s, re.IGNORECASE):
        cands.append({"op": "refang-iocs", "args": {}})
    return cands


# =============================================================================
# Recursive search
# =============================================================================
def magic_decode(payload: str, max_depth: int = 4, max_branches: int = 3,
                 min_score_delta: float = 0.05, top_n: int = 3) -> Dict[str, Any]:
    """Return the top-N final decode chains sorted by score.

    Each result: {chain: [{op, args}, ...], output, score_breakdown, path_scores}
    """
    from payload_sanitizer import sanitize_encapsulated_payload

    # THUMB RULE: ISOLATE THE PAYLOAD STRING FIRST — strip script wrappers.
    isolated = sanitize_encapsulated_payload(payload)
    working = isolated if isolated else payload
    isolation_note = None
    if isolated and isolated != payload.strip():
        isolation_note = f"Isolated {len(isolated)}-char base64 payload from script wrapper"

    initial_score = score_output(working)
    best_results: List[Dict[str, Any]] = []

    def _walk(cur: str, chain: List[Dict[str, Any]], depth: int, path_scores: List[float]):
        # Record the current state as a candidate result too — decoding can peak
        # partway through then degrade.
        sb = score_output(cur)
        best_results.append({
            "chain": list(chain),
            "output": cur,
            "score_breakdown": sb,
            "path_scores": list(path_scores) + [sb["score"]],
        })
        if depth >= max_depth:
            return
        cands = _pick_candidates(cur)[:max_branches]
        for c in cands:
            try:
                nxt = run_operation(c["op"], cur, c["args"])
            except Exception:
                continue
            if not nxt or nxt == cur:
                continue
            nsb = score_output(nxt)
            if nsb["score"] < sb["score"] - 0.30:  # branch massively regressed — prune
                continue
            _walk(nxt, chain + [c], depth + 1, path_scores + [sb["score"]])

    _walk(working, [], 0, [])

    # Deduplicate by (output snippet + chain length) and keep top-N
    seen = set()
    dedup: List[Dict[str, Any]] = []
    for r in sorted(best_results, key=lambda x: -x["score_breakdown"]["score"]):
        k = (r["output"][:200], len(r["chain"]))
        if k in seen:
            continue
        seen.add(k)
        # Prepend the isolation step to every chain so the analyst can see the wrapper strip
        if isolation_note:
            r = {**r, "chain": [{"op": "extract-payload", "args": {}}] + r["chain"]}
        dedup.append(r)
        if len(dedup) >= top_n:
            break

    return {
        "initial_score": initial_score,
        "candidates_explored": len(best_results),
        "isolation_note": isolation_note,
        "top_results": dedup,
    }
