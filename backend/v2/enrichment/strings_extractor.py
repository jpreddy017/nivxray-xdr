"""Strings & artifact extractor for recovered decoder payloads.

Runs deterministically on the final `AnalystReport.output` (plus every
trace-step preview) to surface analyst-grade artefacts that the raw
Orchestrator does not itself expose:

  • ASCII printable strings  ≥ MIN_LEN  (like GNU `strings`)
  • UTF-16LE printable strings (Windows binaries)
  • HTTP User-Agent values   (regex on printable output)
  • Interesting single-line artefacts (URLs, file paths, registry keys,
    e-mail, HTTP hostnames, PowerShell cmdlets)

Zero LLM / zero heuristic verdicts — this only surfaces what is
literally present in the recovered bytes.
"""
from __future__ import annotations

import re
from typing import Iterable

# Minimum readable run length before we surface a string.
MIN_LEN = 5
# Cap per chain so a huge binary payload doesn't drown the report.
MAX_STRINGS = 60

_PRINTABLE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_LEN)
_UTF16_LE  = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_LEN)

# ── Detectors that fire on any printable output ─────────────────
_UA_RE      = re.compile(
    r"(Mozilla/\d(?:\.\d)?\s*\([^)\r\n\x00]{5,300}\)"
    r"(?:\s+[^\s\r\n\x00]{1,80}){0,10})",
)
_URL_RE     = re.compile(r"https?://[^\s\"'<>\x00]{4,200}")
_HOSTNAME   = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,4}"
                          r"[a-z]{2,10}\b", re.I)
_IPV4       = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL      = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{2,255}\."
                          r"[A-Za-z]{2,20}\b")
_WIN_PATH   = re.compile(r"[A-Za-z]:\\[\\A-Za-z0-9._$~()@ \-]{3,200}")
_UNIX_PATH  = re.compile(r"/(?:etc|tmp|var|usr|home|bin|opt|root)/"
                          r"[A-Za-z0-9._/\-]{2,200}")
_REG_KEY    = re.compile(r"HK(?:CU|LM|CR|U|CC)\\[\\A-Za-z0-9._ \-]{3,200}")
_PS_CMDLET  = re.compile(r"\b(?:Invoke-\w+|New-Object|Get-\w+|Set-\w+|"
                          r"Start-\w+|IEX|Add-Type|DownloadString)\b")


def _dedupe_keep_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it in seen:
            continue
        seen.add(it)
        out.append(it)
    return out


def _looks_noisy(s: str) -> bool:
    """Drop obvious garbage — repeated single chars, all-same-byte
    runs, etc. Keeps things like `XtKFQF` and `hnethwiniThLw&` while
    rejecting `AAAAAAAA` or `\x00\x00\x00\x00`."""
    if len(set(s)) <= 2:
        return True
    if len(s) < MIN_LEN:
        return True
    # Reject strings that are >90% a single char
    from collections import Counter
    top_freq = max(Counter(s).values())
    if top_freq / len(s) > 0.9:
        return True
    return False


def extract_strings_from_bytes(data: bytes) -> list[str]:
    """GNU-`strings`-like extractor: ASCII + UTF-16LE runs of MIN_LEN+."""
    out: list[str] = []
    for m in _PRINTABLE.finditer(data):
        s = m.group(0).decode("ascii", errors="ignore")
        if not _looks_noisy(s):
            out.append(s)
    for m in _UTF16_LE.finditer(data):
        s = m.group(0).decode("utf-16-le", errors="ignore")
        if s and not _looks_noisy(s):
            out.append(s)
    return _dedupe_keep_order(out)[:MAX_STRINGS]


def extract_from_text(text: str) -> dict[str, list[str]]:
    """Run every artefact detector against a text blob and return a
    dict of {category: [values]}. Duplicates are removed, order preserved."""
    if not text:
        return {}
    return {
        "user_agents": _dedupe_keep_order(_UA_RE.findall(text))[:12],
        "urls":        _dedupe_keep_order(_URL_RE.findall(text))[:32],
        "hostnames":   _dedupe_keep_order(_HOSTNAME.findall(text))[:32],
        "ipv4":        _dedupe_keep_order(_IPV4.findall(text))[:32],
        "emails":      _dedupe_keep_order(_EMAIL.findall(text))[:16],
        "file_paths": (_dedupe_keep_order(_WIN_PATH.findall(text))
                       + _dedupe_keep_order(_UNIX_PATH.findall(text)))[:32],
        "registry":    _dedupe_keep_order(_REG_KEY.findall(text))[:16],
        "powershell_cmdlets": _dedupe_keep_order(_PS_CMDLET.findall(text))[:24],
    }


def enrich_report(report_output: str, trace_previews: list[str]) -> dict:
    """Aggregate every artefact + string extractor across the final
    Orchestrator output and each trace-step preview. Returns a compact
    dict suitable for embedding in `decode_pipeline.chains[i]` and the
    top-level FinalIncidentSummary IOCs."""
    combined_text = "\n".join(filter(None, [report_output, *trace_previews]))
    payload_bytes = combined_text.encode("latin-1", errors="ignore")
    strings = extract_strings_from_bytes(payload_bytes)
    artefacts = extract_from_text(combined_text)
    # Prune empty buckets to keep the payload lean.
    artefacts = {k: v for k, v in artefacts.items() if v}
    return {
        "strings":   strings,
        "artefacts": artefacts,
    }
