"""Pre-decode content fingerprint — lightweight features visible WITHOUT decoding.

These features let us match a raw payload to a KB archetype BEFORE we've spent
compute on decoding it. All features are deterministic and cheap (< 1 ms).
"""
from __future__ import annotations
import math
import re
from typing import Dict, Any


_BASE64_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _length_bucket(n: int) -> str:
    for boundary, label in ((64, "xs"), (256, "s"), (1024, "m"), (4096, "l"), (16384, "xl")):
        if n <= boundary:
            return label
    return "xxl"


def compute_signals(raw: str) -> Dict[str, Any]:
    """Return a compact fingerprint dict — one row per raw payload."""
    r = raw or ""
    r_lc = r.lower()
    n = len(r)

    b64 = sum(1 for ch in r if ch in _BASE64_CHARS)
    return {
        "length":            n,
        "length_bucket":     _length_bucket(n),
        "entropy":           round(_shannon_entropy(r), 3),
        "b64_density":       round(b64 / n, 3) if n else 0.0,

        # Content markers (pre-decode)
        "has_powershell":    "powershell" in r_lc or "iex(" in r_lc,
        "has_encoded_cmd":   "-encodedcommand" in r_lc or "-enc " in r_lc,
        "has_iwr":           "iwr " in r_lc or "invoke-webrequest" in r_lc,
        "has_downloadstr":   "downloadstring" in r_lc or "downloaddata" in r_lc,
        "has_gzip_prefix":   r.startswith("H4sI"),   # base64 of 1f 8b 08 ...
        "has_zlib_prefix":   r.startswith("eJ")      or r.startswith("eN"),   # base64 of 78 xx
        "has_utf16le_hint":  bool(re.match(r"^[A-Za-z0-9+/=]{16,}$", r)) and b64 > n * 0.9,
        "has_curl_pipe":     "curl " in r_lc and ("| bash" in r_lc or "|bash" in r_lc or "| sh" in r_lc),
        "has_wget_pipe":     "wget " in r_lc and ("| bash" in r_lc or "|sh" in r_lc or "| sh" in r_lc),
        "has_bash_prefix":   r_lc.lstrip().startswith("bash ") or r_lc.lstrip().startswith("/bin/"),
        "has_mshta":         "mshta" in r_lc,
        "has_certutil":      "certutil" in r_lc,
        "has_rundll32":      "rundll32" in r_lc,
        "has_regsvr32":      "regsvr32" in r_lc,
        "has_hex_stream":    bool(re.search(r"(\\x[0-9a-fA-F]{2}){8,}", r)),
        "has_unicode_esc":   bool(re.search(r"(\\u[0-9a-fA-F]{4}){4,}", r)),
        "has_url_encoded":   r_lc.count("%") >= 4 and bool(re.search(r"%[0-9a-fA-F]{2}", r)),
        "has_html_entities": bool(re.search(r"&#[0-9]{2,4};", r)),
        "has_defanged":      "hxxp" in r_lc or "[.]" in r_lc or "[@]" in r_lc,
        "has_reg_persist":   "hkcu\\software\\microsoft\\windows\\currentversion\\run" in r_lc,
        "has_charcode":      "fromcharcode" in r_lc,
    }


def signal_kind(sig: Dict[str, Any]) -> str:
    """Return a coarse KIND label — used to match against KB archetypes."""
    if sig.get("has_powershell"):
        if sig.get("has_encoded_cmd"):     return "ps-encoded"
        if sig.get("has_iwr") or sig.get("has_downloadstr"):
            return "ps-downloader"
        if sig.get("has_gzip_prefix") or sig.get("has_zlib_prefix"):
            return "ps-compressed"
        return "ps-generic"
    if sig.get("has_curl_pipe") or sig.get("has_wget_pipe"):
        return "linux-pipe-shell"
    if sig.get("has_bash_prefix"):
        return "linux-bash"
    if sig.get("has_certutil"): return "lolbin-certutil"
    if sig.get("has_mshta"):    return "lolbin-mshta"
    if sig.get("has_rundll32"): return "lolbin-rundll32"
    if sig.get("has_regsvr32"): return "lolbin-regsvr32"
    if sig.get("has_reg_persist"): return "windows-persistence"
    if sig.get("has_gzip_prefix"): return "b64-gzip"
    if sig.get("has_zlib_prefix"): return "b64-zlib"
    if sig.get("has_hex_stream"):  return "hex-stream"
    if sig.get("has_unicode_esc"): return "unicode-escape"
    if sig.get("has_url_encoded"): return "url-encoded"
    if sig.get("has_html_entities"): return "html-entities"
    if sig.get("has_defanged"):    return "defanged-ioc"
    if sig.get("has_charcode"):    return "js-charcode"
    return "unknown"


# Default chain priors — fallback when no KB match & no history frequency yet
DEFAULT_CHAIN_PRIORS: Dict[str, list] = {
    "ps-encoded":          [["powershell-encoded"], ["powershell-encoded", "powershell-deobfuscate"]],
    "ps-compressed":       [["base64-gzip"], ["base64-zlib"], ["base64-decode", "gzip-decompress"]],
    "ps-downloader":       [["powershell-deobfuscate"]],
    "ps-generic":          [["powershell-deobfuscate"]],
    "linux-pipe-shell":    [["url-decode"]],
    "linux-bash":          [["url-decode"]],
    "lolbin-certutil":     [["url-decode"], ["refang-iocs"]],
    "lolbin-mshta":        [["url-decode"]],
    "b64-gzip":            [["base64-gzip"], ["base64-decode", "gzip-decompress"]],
    "b64-zlib":            [["base64-zlib"], ["base64-decode", "zlib-decompress"]],
    "hex-stream":          [["hex-decode"], ["js-hex-strings-decode"]],
    "unicode-escape":      [["unicode-escape"]],
    "url-encoded":         [["url-decode"]],
    "html-entities":       [["html-decode"]],
    "defanged-ioc":        [["refang-iocs"]],
    "js-charcode":         [["js-charcode-decode"], ["js-charcode"]],
    "windows-persistence": [["refang-iocs"]],
}
