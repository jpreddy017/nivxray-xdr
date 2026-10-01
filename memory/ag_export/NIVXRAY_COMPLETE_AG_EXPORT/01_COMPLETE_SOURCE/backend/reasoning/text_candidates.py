"""NivXRay reasoning — Phase 2: Text-mode candidate generator.

For inputs classified as ``text_like`` by ``characterize``, generate a
ranked set of linguistic-hypothesis candidates and score each by the
linguistic delta it produces:

    ROT-N (n=1..25)     single-alphabet Caesar shift, both directions
    Atbash              A↔Z, B↔Y, …
    Reverse             s[::-1]
    XOR single-byte     brute 1..255 on printable output

Scoring rule (per user spec):
    delta = linguistic_score(candidate_output) - linguistic_score(input)
Candidates with delta ≤ 0 are dropped — no transformation is applied
that doesn't improve linguistic meaningfulness.

Ties (delta within TIE_THRESHOLD) surface both candidates for optional
LLM arbitration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .scorer import linguistic_score, score_breakdown

TIE_THRESHOLD = 0.05


@dataclass
class Candidate:
    """Standardized decoder plugin contract (Feb-2026 spec)."""
    op: str
    args: Dict[str, Any]
    output: str
    input_score: float
    output_score: float
    delta: float
    reasons: List[str] = field(default_factory=list)
    breakdown: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "op": self.op, "args": self.args,
            "output": self.output, "input_score": self.input_score,
            "output_score": self.output_score, "delta": round(self.delta, 4),
            "reasons": self.reasons, "breakdown": self.breakdown,
        }


def _rot_n(text: str, n: int) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + n) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + n) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)


def _atbash(text: str) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(chr(219 - ord(c)))  # 219 = 'a' + 'z'
        elif "A" <= c <= "Z":
            out.append(chr(155 - ord(c)))  # 155 = 'A' + 'Z'
        else:
            out.append(c)
    return "".join(out)


def _xor_single_byte(text: str, key: int) -> Optional[str]:
    """XOR each byte with `key`. Returns None if result isn't mostly printable."""
    try:
        raw = text.encode("latin-1", errors="replace")
    except Exception:
        return None
    xored = bytes(b ^ key for b in raw)
    try:
        s = xored.decode("utf-8")
    except UnicodeDecodeError:
        try:
            s = xored.decode("latin-1")
        except Exception:
            return None
    printable = sum(1 for c in s if 32 <= ord(c) < 127 or c in "\r\n\t")
    if not s or printable / max(len(s), 1) < 0.85:
        return None
    return s


def text_candidates(
    text: str,
    min_delta: float = 0.05,
    top_n: int = 5,
    include_xor: bool = True,
) -> List[Candidate]:
    """Return the top-N linguistically-improving candidates on `text`.

    Only candidates whose linguistic-score DELTA (output - input) exceeds
    `min_delta` are returned. Sorted descending by delta.
    """
    if not text or len(text) < 3:
        return []

    input_score = linguistic_score(text)

    # Feb-2026 · Guard against ROT-N/Atbash/Caesar false positives on inputs
    # that are ALREADY meaningful filesystem paths, executable references,
    # or shell command lines. These would get "improved" into gibberish
    # (e.g. C:\temp\1.exe → R:\itbe\1.tmt) simply because the substitution
    # cipher happens to raise the trigram score by chance.
    import re as _re
    if _re.search(
        r"(?:[A-Za-z]:\\\\|[A-Za-z]:/|/(?:etc|usr|var|home|tmp|bin|proc)/|"
        r"\.(?:exe|dll|ps1|bat|cmd|vbs|js|sh|py|hta|scr|jar|elf)(?:\s|$)|"
        r"HK(?:LM|CU|CR)\\\\|"
        r"\\\\WINDOWS\\\\|\\\\Windows\\\\|\\\\ProgramData\\\\|\\\\Users\\\\)",
        text,
        _re.IGNORECASE,
    ):
        # Filesystem-path-like input — skip the alphabet-cipher family entirely.
        # Fall through to XOR (still safe — XOR-1 on printable paths produces
        # non-printable output that gets rejected by _xor_single_byte).
        _skip_alphabet_ciphers = True
    else:
        _skip_alphabet_ciphers = False

    cands: List[Candidate] = []

    # ── ROT-N brute (n=1..25) ────────────────────────────────────────
    # ROT13 is the most common but attackers use arbitrary shifts too.
    if not _skip_alphabet_ciphers:
        for n in range(1, 26):
            try:
                out = _rot_n(text, n)
            except Exception:
                continue
            if out == text:
                continue
            bd = score_breakdown(out)
            delta = bd["score"] - input_score
            if delta < min_delta:
                continue
            cands.append(Candidate(
                op="rot13" if n == 13 else "rot-n",
                args={"shift": n} if n != 13 else {},
                output=out,
                input_score=round(input_score, 4),
                output_score=round(bd["score"], 4),
                delta=delta,
                reasons=[f"rot{n}-shift"] + bd.get("reasons", [])[:3],
                breakdown=bd,
            ))

    # ── Atbash ───────────────────────────────────────────────────────
    # ── Atbash ───────────────────────────────────────────────────────
    if not _skip_alphabet_ciphers:
        try:
            out = _atbash(text)
            if out != text:
                bd = score_breakdown(out)
                delta = bd["score"] - input_score
                if delta >= min_delta:
                    cands.append(Candidate(
                        op="atbash", args={}, output=out,
                        input_score=round(input_score, 4),
                        output_score=round(bd["score"], 4),
                        delta=delta,
                        reasons=["atbash-substitution"] + bd.get("reasons", [])[:3],
                        breakdown=bd,
                    ))
        except Exception:
            pass

    # ── Reverse ──────────────────────────────────────────────────────
    try:
        out = text[::-1]
        if out != text:
            bd = score_breakdown(out)
            delta = bd["score"] - input_score
            if delta >= min_delta:
                cands.append(Candidate(
                    op="reverse", args={}, output=out,
                    input_score=round(input_score, 4),
                    output_score=round(bd["score"], 4),
                    delta=delta,
                    reasons=["reverse-string"] + bd.get("reasons", [])[:3],
                    breakdown=bd,
                ))
    except Exception:
        pass

    # ── Single-byte XOR brute (only for shorter buffers) ─────────────
    if include_xor and len(text) <= 4096:
        for k in range(1, 256):
            out = _xor_single_byte(text, k)
            if not out or out == text:
                continue
            bd = score_breakdown(out)
            delta = bd["score"] - input_score
            if delta < min_delta:
                continue
            cands.append(Candidate(
                op="xor", args={"key": f"0x{k:02x}"}, output=out,
                input_score=round(input_score, 4),
                output_score=round(bd["score"], 4),
                delta=delta,
                reasons=[f"xor-key-0x{k:02x}"] + bd.get("reasons", [])[:3],
                breakdown=bd,
            ))

    cands.sort(key=lambda c: -c.delta)
    return cands[:top_n]
