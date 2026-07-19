"""Base64 decoder plugin — reference implementation of the plugin contract."""
import base64 as _b64
import re

from . import register

_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")


def detect(text: str) -> float:
    s = re.sub(r"\s", "", text or "")
    if len(s) < 8: return 0.0
    if not _ALPHABET.match(s): return 0.0
    mod = len(s) % 4
    if mod == 1: return 0.2                          # invalid length
    if not re.search(r"[A-Za-z]", s): return 0.3     # all-digit is more likely decimal
    return 0.85


def decode(text: str) -> str:
    s = re.sub(r"\s", "", text or "")
    pad = (-len(s)) % 4
    try:
        return _b64.b64decode(s + "=" * pad, validate=False).decode("utf-8", errors="replace")
    except Exception:
        # URL-safe variant
        return _b64.urlsafe_b64decode(s + "=" * pad).decode("utf-8", errors="replace")


register("base64-decode", "Base64 Decode", "encoding", detect, decode)
