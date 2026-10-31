"""Corrupted-payload detector.

Some payloads look decodable at a glance (right prefix, right header, right
length ballpark) but are structurally impossible to decompress or decode.
Attackers and CTF authors sometimes fabricate these to trip up analysts and
AI-based decoders. Google-AI-style tools tend to HALLUCINATE plausible
output for such payloads — NivXRay must instead emit a clear, evidence-
based "payload is corrupt" verdict.

Detection heuristics (each carries an evidence field for UI display):

  1. BASE64_IMPOSSIBLE_LEN     — length is 4n+1 (mathematically impossible)
  2. GZIP_HEADER_VALID_BODY_BAD — gzip magic OK, deflate fails end-of-block
  3. GZIP_SYNTHETIC_HEADER      — mtime=0 + os=0xff (fabricated fingerprint)
  4. LOW_ENTROPY_FAUX_COMPRESSED — body entropy far below real deflate range
  5. IMPOSSIBLE_PADDING         — > 2 trailing `=`
"""
from __future__ import annotations
import base64
import math
import re
import zlib
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


_GZIP_MAGIC = b"\x1f\x8b\x08"
_REAL_DEFLATE_ENTROPY_FLOOR = 7.60  # empirical; real gzip ≥ 7.9, floor with safety margin


def _shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _looks_like_pure_b64(text: str) -> bool:
    s = re.sub(r"\s+", "", text)
    if len(s) < 40:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", s))


def _extract_b64_from_text(text: str) -> Optional[str]:
    """If the payload IS base64 (pure or wrapped), extract it. Otherwise None."""
    s = text.strip()
    if _looks_like_pure_b64(s):
        return re.sub(r"\s+", "", s)
    m = re.search(r'FromBase64String\s*\(\s*["\']([^"\']+)["\']', text)
    if m:
        return m.group(1)
    # Longest b64-looking substring ≥ 100 chars
    candidates = re.findall(r"[A-Za-z0-9+/=_-]{100,}", text)
    return max(candidates, key=len) if candidates else None


def detect_corrupt_payload(text: str) -> Optional[Dict[str, Any]]:
    """Return a diagnostic dict if the payload is structurally corrupt.

    Returns None if the payload looks OK (or isn't b64/gzip at all).

    Return shape::
        {
          "severity":  "high" | "medium" | "low",
          "family":    "gzip" | "base64" | ...,
          "reasons":   [ {code, message, evidence}, ... ],
          "verdict":   short one-line human summary,
          "recommendation": specific next step for the analyst,
        }
    """
    b64_body = _extract_b64_from_text(text)
    if not b64_body:
        return None

    reasons: List[Dict[str, str]] = []

    # ── Check 1: length ────────────────────────────────────────────────
    L = len(b64_body)
    if L % 4 == 1:
        reasons.append({
            "code": "BASE64_IMPOSSIBLE_LEN",
            "message": "Base64 length is 4n+1 — mathematically impossible for real base64.",
            "evidence": f"len={L}, len mod 4 = 1 (valid base64 is 4n, 4n+2, or 4n+3)",
        })

    # ── Check 2: too many trailing = ───────────────────────────────────
    trailing_eq = len(b64_body) - len(b64_body.rstrip("="))
    if trailing_eq > 2:
        reasons.append({
            "code": "IMPOSSIBLE_PADDING",
            "message": f"Base64 has {trailing_eq} trailing '=' — max legal is 2.",
            "evidence": f"trailing_pad={trailing_eq}",
        })

    # ── Try to decode (tolerate any padding + drop stray chars) ─────────
    raw = b""
    try:
        raw = base64.b64decode(b64_body + "=" * (-L % 4), validate=False)
    except Exception:
        # For 4n+1 length or other structural corruption, drop the last char
        # and retry. We only care about getting SOME bytes so we can inspect
        # the gzip header and body.
        for salvage in (b64_body[:-1], b64_body[:-2], b64_body[:-3]):
            try:
                raw = base64.b64decode(salvage + "=" * (-len(salvage) % 4), validate=False)
                if raw:
                    break
            except Exception:
                continue
        if not raw:
            reasons.append({
                "code": "BASE64_DECODE_FAIL",
                "message": "Base64 refuses to decode even after tolerant repair attempts.",
                "evidence": f"length={L}, no salvage strategy produced bytes",
            })

    # ── Check 3: gzip header valid, body malformed ──────────────────────
    if raw.startswith(_GZIP_MAGIC):
        # Real deflate should decompress at least partially with a streaming inflator
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            inflated = d.decompress(raw)
            try:
                inflated += d.flush()
            except zlib.error:
                pass
            if len(inflated) < 8:
                reasons.append({
                    "code": "GZIP_HEADER_VALID_BODY_BAD",
                    "message": "Gzip header is valid but the deflate body produces <8 bytes — the compressed stream is structurally invalid.",
                    "evidence": f"raw_bytes={len(raw)}, inflated_bytes={len(inflated)}",
                })
        except zlib.error as e:
            emsg = str(e)
            reasons.append({
                "code": "GZIP_HEADER_VALID_BODY_BAD",
                "message": "Gzip magic bytes are correct but the deflate body is not valid compressed data.",
                "evidence": f"zlib error: {emsg[:180]}",
            })

        # ── Check 4: synthetic gzip fingerprint ─────────────────────────
        if len(raw) >= 10:
            # gzip header layout: 1f 8b 08 <flg> <mtime x4> <xfl> <os>
            mtime = int.from_bytes(raw[4:8], "little")
            os_byte = raw[9]
            xfl = raw[8]
            if mtime == 0 and os_byte == 0xFF and xfl == 0x00:
                reasons.append({
                    "code": "GZIP_SYNTHETIC_HEADER",
                    "message": "Gzip header has mtime=0, xfl=0, os=0xFF — canonical 'synthetic' fingerprint. Real tools set mtime and OS.",
                    "evidence": f"mtime=0 xfl=0x00 os=0xff (real gzip has real mtime + os in 0-13)",
                })

        # ── Check 5: entropy sanity ─────────────────────────────────────
        body = raw[10:]
        if len(body) >= 64:
            ent = _shannon_entropy(body)
            if ent < _REAL_DEFLATE_ENTROPY_FLOOR:
                reasons.append({
                    "code": "LOW_ENTROPY_FAUX_COMPRESSED",
                    "message": f"Deflate body entropy is {ent:.3f} bits/byte — well below real deflate floor (~7.9). This is NOT genuine compressed data.",
                    "evidence": f"entropy={ent:.3f} bits/byte, floor={_REAL_DEFLATE_ENTROPY_FLOOR}",
                })

    if not reasons:
        return None

    # Prioritize the most damning reason
    severity = "high" if any(r["code"] in {"BASE64_IMPOSSIBLE_LEN",
                                            "GZIP_HEADER_VALID_BODY_BAD",
                                            "BASE64_DECODE_FAIL"} for r in reasons) else "medium"
    verdict_lines = {
        "BASE64_IMPOSSIBLE_LEN":         "Payload was truncated or has a stray character (base64 length is mathematically impossible).",
        "GZIP_HEADER_VALID_BODY_BAD":    "Payload has a valid gzip header but the compressed body is corrupt — cannot decode.",
        "GZIP_SYNTHETIC_HEADER":         "Payload has a fabricated gzip fingerprint (mtime=0, os=0xff) — likely hand-crafted, not real malware output.",
        "LOW_ENTROPY_FAUX_COMPRESSED":   "Payload looks like gzip but the body entropy is too low to be genuine compressed data.",
        "BASE64_DECODE_FAIL":            "Payload cannot be base64-decoded even with padding repair.",
        "IMPOSSIBLE_PADDING":            "Payload has too many trailing '=' characters — corrupted at transport.",
    }
    top = reasons[0]["code"]
    return {
        "severity": severity,
        "family": "gzip" if raw.startswith(_GZIP_MAGIC) else "base64",
        "reasons": reasons,
        "verdict": verdict_lines.get(top, "Payload is structurally corrupt — cannot decode."),
        "recommendation": (
            "Re-copy the ORIGINAL payload from its source (email, PCAP, memory dump). "
            "Do NOT trust AI-generated 'decoded output' from other tools — they may be "
            "hallucinating plausible content based on the header alone. If your source "
            "genuinely produced this blob, it is either fabricated (CTF trap / decoy) or "
            "was mangled by an intermediate transform (URL-encoding, HTML entities, "
            "whitespace collapse, or a copy-paste truncation)."
        ),
    }
