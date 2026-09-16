"""
Layer Integrity Validator + Predictive Planner
================================================

Runs mathematical structural checks on the output of each decode layer
BEFORE it is fed to the next. Provides:

  1. `validate(text, layer_type)` — per-layer health verdict + reason
  2. `plan_next(text)`            — predicts the next most likely decoder
                                    based on structural signatures (regex
                                    heuristics + cheap byte-level fingerprints)
  3. `full_trace(chain_output)`   — validates the entire chain, node by node,
                                    marks failed transitions, and salvages
                                    where possible.

The planner is fast — no LLM calls, pure regex + entropy scoring — so it can
run on every keystroke in the workspace INPUT panel for real-time hints.
"""
from __future__ import annotations
import base64
import binascii
import re
from typing import Any, Dict, List, Optional
from collections import Counter


# ── Layer Validators ───────────────────────────────────────────────────────

def validate_base64(text: str) -> Dict[str, Any]:
    """Check if `text` is a valid base64 blob."""
    stripped = re.sub(r"\s+", "", text)
    if not stripped:
        return {"valid": False, "reason": "empty input", "salvage": None}
    charset_ok = bool(re.fullmatch(r"[A-Za-z0-9+/=_\-]+", stripped))
    if not charset_ok:
        bad_chars = set(stripped) - set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
        return {"valid": False, "reason": f"non-base64 chars: {sorted(bad_chars)[:5]}", "salvage": None}
    pad_stripped = stripped.rstrip("=")
    length_mod = len(pad_stripped) % 4
    if length_mod == 1:
        return {"valid": False, "reason": f"length {len(pad_stripped)} = 4k+1 (base64 impossible)",
                "salvage": pad_stripped[:-1] + "=" * (-(len(pad_stripped) - 1) % 4)}
    if length_mod in (2, 3):
        return {"valid": True, "reason": f"length {len(pad_stripped)} = 4k+{length_mod} (padding required)",
                "salvage": pad_stripped + "=" * (-length_mod % 4)}
    return {"valid": True, "reason": f"length {len(pad_stripped)} = 4k (no padding needed)", "salvage": None}


def validate_hex(text: str) -> Dict[str, Any]:
    stripped = re.sub(r"[\s\\x0]", "", text.lower())
    if not stripped:
        return {"valid": False, "reason": "empty input", "salvage": None}
    charset_ok = bool(re.fullmatch(r"[0-9a-f]+", stripped))
    if not charset_ok:
        bad = set(stripped) - set("0123456789abcdef")
        return {"valid": False, "reason": f"non-hex chars: {sorted(bad)[:5]}", "salvage": None}
    if len(stripped) % 2 != 0:
        return {"valid": False, "reason": f"odd length ({len(stripped)}) — hex needs pairs",
                "salvage": stripped[:-1]}
    return {"valid": True, "reason": f"{len(stripped)} hex chars → {len(stripped)//2} bytes", "salvage": None}


def validate_url_encoded(text: str) -> Dict[str, Any]:
    escapes = re.findall(r"%(.{0,2})", text)
    if not escapes:
        return {"valid": False, "reason": "no %-escapes found", "salvage": None}
    bad = [e for e in escapes if len(e) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", e)]
    if bad:
        return {"valid": False, "reason": f"malformed %-escape: {bad[:3]}", "salvage": None}
    return {"valid": True, "reason": f"{len(escapes)} valid %-escapes", "salvage": None}


def validate_utf16le(raw: bytes) -> Dict[str, Any]:
    if len(raw) % 2 != 0:
        return {"valid": False, "reason": f"byte count {len(raw)} is odd (UTF-16 needs pairs)",
                "salvage": raw[:-1]}
    try:
        dec = raw.decode("utf-16-le", errors="strict")
        pr = sum(1 for c in dec if c.isprintable() or c in "\n\r\t") / max(len(dec), 1)
        if pr < 0.80:
            return {"valid": False, "reason": f"printable ratio {pr:.0%} < 80%", "salvage": None}
        return {"valid": True, "reason": f"{len(dec)} chars, {pr:.0%} printable", "salvage": None}
    except UnicodeDecodeError as e:
        return {"valid": False, "reason": f"UTF-16LE decode error: {e}", "salvage": None}


def validate_gzip(raw: bytes) -> Dict[str, Any]:
    if len(raw) < 3 or raw[:2] != b"\x1f\x8b":
        return {"valid": False, "reason": "missing gzip magic (1f 8b)", "salvage": None}
    return {"valid": True, "reason": "gzip magic OK", "salvage": None}


def validate_hex_family(text: str) -> Dict[str, Any]:
    """Detect KHEX/XHEX/trailing-marker family with marker consistency check."""
    variants = [
        (r"\\([a-z])([0-9a-z<>?]{2})",  "leading-backslash (\\<M>HH)"),
        (r"([0-9a-z<>?]{2})([a-z])\\",  "trailing-backslash (HH<M>\\)"),
        (r"([a-z])([0-9a-z<>?]{2})\\",  "middle (<M>HH\\)"),
    ]
    for pat, label in variants:
        matches = re.findall(pat, text)
        if len(matches) >= 20:
            markers = Counter(m[0] if len(m[0]) == 1 else m[1] for m in matches)
            top, top_count = markers.most_common(1)[0]
            consistency = top_count / len(matches)
            if consistency >= 0.70:
                return {"valid": True,
                        "reason": f"{len(matches)} tokens · variant={label} · marker='{top}' · consistency={consistency:.0%}",
                        "salvage": None}
    return {"valid": False, "reason": "no hex-family pattern detected", "salvage": None}


# ── Predictive Planner ─────────────────────────────────────────────────────

def plan_next(text: str, max_hints: int = 5) -> List[Dict[str, Any]]:
    """Analyse `text` and return ranked list of likely-next-decoder hints.

    Returns list of {op, confidence, reason, suggested_button}.
    """
    hints: List[Dict[str, Any]] = []
    if not text or not text.strip():
        return hints

    stripped = text.strip()
    lower = stripped.lower()

    # ─── PowerShell -EncodedCommand ──────────────────────────────────────
    if re.search(r"powershell(\.exe)?\s+.*-e(nc(oded(command)?)?)?\s+[A-Za-z0-9+/=]{8,}", lower):
        hints.append({
            "op": "powershell-encoded",
            "confidence": 0.98,
            "reason": "PowerShell `-EncodedCommand` detected (base64+UTF-16LE)",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── CMD /c wrapper ───────────────────────────────────────────────────
    if re.search(r"\bcmd(\.exe)?\s+/c\b", lower):
        hints.append({
            "op": "cmd-deobfuscate",
            "confidence": 0.85,
            "reason": "CMD `/c` wrapper detected",
            "suggested_button": "SMART DECODE",
        })
    # ─── Base64 blob (non-wrapped) ────────────────────────────────────────
    b64_blobs = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", stripped)
    if b64_blobs and not hints:  # only if not already suggested via wrapper
        largest = max(b64_blobs, key=len)
        v = validate_base64(largest)
        hints.append({
            "op": "base64-decode",
            "confidence": 0.90 if v["valid"] else 0.65,
            "reason": f"Base64 blob ({len(largest)} chars) — {v['reason']}",
            "suggested_button": "SMART DECODE",
        })
    # ─── Hex escape / \xNN ────────────────────────────────────────────────
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", stripped)) >= 8:
        hints.append({
            "op": "js-unescape",
            "confidence": 0.90,
            "reason": "\\xNN hex-escape stream detected",
            "suggested_button": "SMART DECODE",
        })
    # ─── URL-encoded ──────────────────────────────────────────────────────
    if len(re.findall(r"%[0-9a-fA-F]{2}", stripped)) >= 8:
        hints.append({
            "op": "url-decode",
            "confidence": 0.88,
            "reason": "URL-encoded (%NN) sequences detected",
            "suggested_button": "SMART DECODE",
        })
    # ─── KHEX / XHEX family ───────────────────────────────────────────────
    hexfam = validate_hex_family(stripped)
    if hexfam["valid"]:
        hints.append({
            "op": "hexfamily-unmap",
            "confidence": 0.92,
            "reason": f"KHEX/XHEX family: {hexfam['reason']}",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── PowerShell obfuscation markers ───────────────────────────────────
    if any(m in stripped for m in ("[char[]]", "-join", ".Split(", ".Replace(", "`", "iex")):
        hints.append({
            "op": "powershell-deobfuscate",
            "confidence": 0.75,
            "reason": "PowerShell syntactic obfuscation markers found",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── HTML entities ────────────────────────────────────────────────────
    if len(re.findall(r"&(?:amp|lt|gt|quot|#x?[0-9a-fA-F]+);", stripped)) >= 4:
        hints.append({
            "op": "html-decode",
            "confidence": 0.85,
            "reason": "HTML entity references detected",
            "suggested_button": "SMART DECODE",
        })
    # ─── Reverse shell primitives ────────────────────────────────────────
    if re.search(r"/dev/tcp/[\d\.]+/\d+|mkfifo.*nc|socket\.socket.*dup2", lower):
        hints.append({
            "op": "reverse-shell-detect",
            "confidence": 0.95,
            "reason": "Reverse-shell primitive detected (/dev/tcp, mkfifo, or Python socket)",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── Download-and-execute cradle (curl/wget → bash/sh/iex/eval) ────────
    if re.search(r"\b(curl|wget|iwr|invoke-webrequest)\b.*(-fsSL|-o\s|-O\s|http)", lower) or \
       re.search(r"\b(curl|wget)\b.*\|\s*(bash|sh|iex|python|perl|eval)", lower):
        hints.append({
            "op": "download-cradle-detect",
            "confidence": 0.95,
            "reason": "Download-and-execute cradle detected (curl/wget → shell/interpreter)",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── LOLBAS binaries ──────────────────────────────────────────────────
    lolbas_hits = [b for b in ("certutil", "bitsadmin", "mshta", "regsvr32", "wmic", "rundll32", "msiexec")
                   if b in lower]
    if lolbas_hits:
        hints.append({
            "op": "lolbas-scan",
            "confidence": 0.80,
            "reason": f"LOLBAS binary detected: {', '.join(lolbas_hits)}",
            "suggested_button": "AUTO INVESTIGATE",
        })
    # ─── Plain PowerShell script (no wrappers/encoding) → analyst-review ──
    if not hints and re.search(r"\b(Get-|Set-|New-|Remove-|Invoke-|Write-|Where-Object|ForEach-Object|Select-)\w+\b", stripped):
        hints.append({
            "op": "plain-powershell-review",
            "confidence": 0.70,
            "reason": "Plain PowerShell cmdlet detected — no obfuscation, review IOCs",
            "suggested_button": "ANALYZE + OSINT",
        })
    # ─── Nothing looks encoded — likely plaintext ─────────────────────────
    if not hints:
        entropy = _shannon_entropy(stripped[:2048])
        if entropy > 4.5:
            hints.append({
                "op": "extract-strings",
                "confidence": 0.55,
                "reason": f"High entropy ({entropy:.1f}) — likely encrypted/compressed binary",
                "suggested_button": "MAGIC",
            })
        else:
            hints.append({
                "op": "extract-iocs",
                "confidence": 0.40,
                "reason": f"Low entropy ({entropy:.1f}) — likely plaintext; extract IOCs",
                "suggested_button": "ANALYZE + OSINT",
            })

    hints.sort(key=lambda h: h["confidence"], reverse=True)
    return hints[:max_hints]


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits/char."""
    if not s:
        return 0.0
    freq = Counter(s)
    total = len(s)
    import math
    return -sum((c / total) * math.log2(c / total) for c in freq.values() if c > 0)


# ── Full-Chain Trace Validator ─────────────────────────────────────────────

def full_trace(steps: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Given a list of {op, output} steps, validate each transition.

    Returns:
      {
        "layers": [{op, output_len, validation, health, salvage_applied}, ...],
        "overall_health": "green|amber|red",
        "failed_layer": None | int (index of first failure),
      }
    """
    layers = []
    failed_layer = None
    overall = "green"
    for i, step in enumerate(steps):
        op = step.get("op", "?")
        out = step.get("output", "")
        # Infer expected next-layer type from op name
        expected = _infer_expected_type(op)
        validation = _dispatch_validator(expected, out)
        health = "✅" if validation["valid"] else "🔴"
        if not validation["valid"]:
            if failed_layer is None:
                failed_layer = i
            overall = "amber" if validation.get("salvage") else "red"
        layers.append({
            "index": i,
            "op": op,
            "output_len": len(out) if isinstance(out, str) else len(out) if isinstance(out, bytes) else 0,
            "expected_type": expected,
            "validation": validation,
            "health": health,
        })
    return {"layers": layers, "overall_health": overall, "failed_layer": failed_layer}


def _infer_expected_type(op: str) -> str:
    op = op.lower()
    if "base64" in op or "b64" in op:
        return "base64"
    if "hex" in op and "family" not in op:
        return "hex"
    if "url" in op:
        return "url"
    if "utf16" in op or "utf-16" in op:
        return "utf16"
    if "gzip" in op or "gunzip" in op:
        return "gzip"
    if "hexfamily" in op or "khex" in op or "xhex" in op:
        return "hex_family"
    return "text"


def _dispatch_validator(expected: str, out: Any) -> Dict[str, Any]:
    if isinstance(out, bytes):
        text = out.decode("latin-1", errors="replace")
        raw = out
    else:
        text = str(out or "")
        raw = text.encode("latin-1", errors="replace")
    if expected == "base64":
        return validate_base64(text)
    if expected == "hex":
        return validate_hex(text)
    if expected == "url":
        return validate_url_encoded(text)
    if expected == "utf16":
        return validate_utf16le(raw)
    if expected == "gzip":
        return validate_gzip(raw)
    if expected == "hex_family":
        return validate_hex_family(text)
    # Plaintext — sanity check on printability
    pr = sum(1 for c in text if c.isprintable() or c in "\n\r\t") / max(len(text), 1)
    return {"valid": pr >= 0.85, "reason": f"printable ratio {pr:.0%}", "salvage": None}
