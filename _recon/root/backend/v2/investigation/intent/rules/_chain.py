"""Shared behaviour-chain primitives.

Generic, evidence-driven detection of the canonical
"Download → Write to disk → Execute" chain. The primitives here are
deliberately *behaviour-oriented*: they do not care whether the
downloader is ``certutil``, ``Invoke-WebRequest``, ``curl``, ``wget``,
``Start-BitsTransfer`` or ``WebClient.DownloadFile``; and they do not
care whether the executor is ``Start-Process``, ``Invoke-Item``,
``cmd /c``, the cmd ``start`` builtin, the PowerShell call operator
``&``, or a bare invocation of the dropped filename.

The intent layer and the analyst report both consume this module so
IOC extraction and intent detection stay in lock-step.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ── Shared file-token grammar ──────────────────────────────────
# A "file token" is either:
#   • a single-/double-quoted string,
#   • an ``$env:VAR\...`` expression,
#   • a Windows absolute path (``C:\...``),
#   • or a bare filename with a known executable/script extension.
# We deliberately restrict bare filenames to known extensions so we
# never emit generic strings as file IOCs.
_FILE_TOKEN = (
    r"(?:"
    r"['\"]([^'\"\n]{1,400})['\"]"
    r"|"
    r"(\$env:[A-Za-z_]+(?:\\[^\s;|`\"']+)+)"
    r"|"
    r"([A-Za-z]:\\[^\s;|`\"']+)"
    r"|"
    r"([A-Za-z0-9._\-]+\.(?:exe|dll|ps1|bat|cmd|com|vbs|js|hta|scr|msi|jar|apk|elf))"
    r")"
)

# ── Every deterministic "download → destination" grammar ───────
# Each entry captures the download DESTINATION (local file path or
# filename) as ``_FILE_TOKEN`` alternation. The origin is recorded
# so evidence can name the primitive that produced the destination.
_DEST_PATTERNS: list[tuple[re.Pattern, str]] = [
    # PowerShell parameter form: -OutFile / -Destination / -FilePath / -LiteralPath
    (re.compile(r"(?i)-(?:OutFile|Destination|FilePath|LiteralPath)[ \t]+" + _FILE_TOKEN),
     "parameter"),
    # .NET WebClient.DownloadFile(url, destination) — 2nd positional.
    (re.compile(r"(?i)\bDownloadFile[ \t]*\([ \t]*"
                r"(?:['\"][^'\"]*['\"]|\$[A-Za-z_]\w*)[ \t]*,[ \t]*" + _FILE_TOKEN),
     "downloadfile"),
    # LOLBin: ``certutil -urlcache [-split] [-f] URL DEST``.
    (re.compile(r"(?i)\bcertutil(?:\.exe)?\b[^\n]{0,200}?\bhttps?://\S+[ \t]+" + _FILE_TOKEN),
     "certutil"),
    # LOLBin: ``bitsadmin /transfer NAME [/DOWNLOAD] URL DEST``.
    (re.compile(r"(?i)\bbitsadmin(?:\.exe)?\b[^\n]{0,200}?\bhttps?://\S+[ \t]+" + _FILE_TOKEN),
     "bitsadmin"),
    # LOLBin: ``curl URL -o DEST`` / ``curl URL --output DEST``.
    (re.compile(r"(?i)\bcurl(?:\.exe)?\b[^\n]{0,200}?[ \t]-(?:o|-output)[ \t]+" + _FILE_TOKEN),
     "curl"),
    # LOLBin: ``wget URL -O DEST``.
    (re.compile(r"(?i)\bwget(?:\.exe)?\b[^\n]{0,200}?[ \t]-O[ \t]+" + _FILE_TOKEN),
     "wget"),
]


@dataclass(frozen=True)
class DownloadDestination:
    """A destination file explicitly named by a download primitive.

    Attributes:
        raw     — the token exactly as captured (may be a full path).
        base    — the last path segment (bare filename).
        origin  — human-readable name of the primitive that named it
                  (``parameter``, ``certutil``, ``curl`` …). Used in
                  evidence rationales so the analyst can trace back
                  which downloader chose the destination.
    """
    raw:    str
    base:   str
    origin: str


def _normalise(tok: str) -> str:
    return (tok or "").strip().strip("'").strip('"').rstrip(";,")


def _basename(path: str) -> str:
    p = path.replace("/", "\\")
    return p.rsplit("\\", 1)[-1]


def find_download_destinations(text: str) -> list[DownloadDestination]:
    """Return every destination path/filename named by a download
    primitive in ``text``. Deduplicates by (raw, origin)."""
    out: list[DownloadDestination] = []
    seen: set[tuple[str, str]] = set()
    for pat, origin in _DEST_PATTERNS:
        for m in pat.finditer(text or ""):
            tok = next((g for g in m.groups() if g), "")
            raw = _normalise(tok)
            if not raw:
                continue
            base = _basename(raw)
            key = (raw, origin)
            if key in seen:
                continue
            seen.add(key)
            out.append(DownloadDestination(raw=raw, base=base, origin=origin))
    return out


# ── Standalone-invocation grammar ──────────────────────────────
# Given a specific destination filename (bare ``a.exe`` or full path),
# detect whether it is INVOKED elsewhere in the payload — i.e. it
# appears at the start of a command, right after a shell separator
# (``;``, ``&``, ``&&``, ``||``, ``|``, newline, backtick), or as the
# target of ``start`` (cmd builtin), ``cmd /c``, ``&`` (PowerShell
# call operator), or ``Start-Process`` / ``Invoke-Item``.
_INVOKER_TEMPLATES: list[str] = [
    # After a shell separator (or start of line) — bare invocation.
    r"(?im)(?:^|[;&|\n\r`{])[ \t]*['\"]?__NEEDLE__['\"]?(?=[ \t;&|<>\n\r`]|$)",
    # Cmd shell ``start`` builtin.
    r"(?i)\bstart\b[ \t]+(?:/[a-z]+[ \t]+)*['\"]?__NEEDLE__['\"]?",
    # ``cmd /c <target>``.
    r"(?i)\bcmd(?:\.exe)?\b[ \t]+/c[ \t]+['\"]?__NEEDLE__['\"]?",
    # PowerShell call operator ``& <target>``.
    r"(?im)(?:^|[;\n\r`{|])[ \t]*&[ \t]+['\"]?__NEEDLE__['\"]?",
    # ``Start-Process`` / ``Invoke-Item`` — already caught elsewhere,
    # but included so the chain-detector can attribute the exact hit.
    r"(?i)\b(?:Start-Process|Invoke-Item)\b[ \t]+(?:-FilePath[ \t]+)?['\"]?__NEEDLE__['\"]?",
]


def _needle_re(needle: str) -> str:
    """Regex-escape ``needle`` and add a right-side word-boundary so
    ``a.exe`` does not match ``a.exeloader.exe``."""
    return re.escape(needle) + r"\b"


def is_invoked(text: str, needle: str) -> tuple[bool, str]:
    """Return ``(True, snippet)`` when ``needle`` is invoked as a
    standalone command / execution target in ``text``, else
    ``(False, "")``. ``needle`` should be either the bare filename or
    the full path — both should be tried by the caller.
    """
    if not needle:
        return (False, "")
    n = _needle_re(needle)
    for tpl in _INVOKER_TEMPLATES:
        m = re.search(tpl.replace("__NEEDLE__", n), text or "")
        if m:
            return (True, m.group(0).strip())
    return (False, "")


__all__ = [
    "DownloadDestination",
    "find_download_destinations",
    "is_invoked",
]
