"""
UIL · Input classifier (2026-03-02)
────────────────────────────────────
Detect what an analyst input REALLY is, from either raw bytes or
raw text plus an optional filename.  Deterministic.  Zero LLM.

Returns a canonical InputKind enum.  Unknown types default to
`plain_text`; the mixed-input splitter downstream refines further.

Detection order matters: binary sniffs first (magic bytes), then
structured text (JSON/YAML/XML/STIX), then domain-specific text
formats (YARA/Sigma/EML), then IOC-shape heuristics, then command
shells, then bare URLs, and finally plain_text as the catch-all.
"""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
import re


class InputKind(str, Enum):
    # ── Text formats ─────────────────────────────────────────────
    PLAIN_TEXT       = "plain_text"
    COMMAND          = "command"
    POWERSHELL       = "powershell"
    BASH             = "bash"
    PYTHON           = "python"
    JAVASCRIPT       = "javascript"
    VBSCRIPT         = "vbscript"
    BATCH            = "batch"
    URL              = "url"
    IOC_LIST         = "ioc_list"
    CSV              = "csv"
    JSON             = "json"
    XML              = "xml"
    YAML             = "yaml"
    STIX             = "stix"
    OPENIOC          = "openioc"
    YARA             = "yara"
    SIGMA            = "sigma"
    # ── Binary / rich formats (detected but preprocessor pending)
    EMAIL_EML        = "email_eml"
    EMAIL_MSG        = "email_msg"
    PDF              = "pdf"
    DOCX             = "docx"
    PPTX             = "pptx"
    XLSX             = "xlsx"
    IMAGE            = "image"
    ZIP_ARCHIVE      = "zip_archive"
    SEVEN_Z          = "seven_z"
    RAR_ARCHIVE      = "rar_archive"
    ISO              = "iso"
    EVTX             = "evtx"
    PCAP             = "pcap"
    PE_BINARY        = "pe_binary"
    ELF_BINARY       = "elf_binary"
    MACHO_BINARY     = "macho_binary"
    APK              = "apk"
    # ── Meta
    MIXED            = "mixed"
    EMPTY            = "empty"


KIND_LABEL = {
    InputKind.PLAIN_TEXT: "Plain text",
    InputKind.COMMAND:    "Command line",
    InputKind.POWERSHELL: "PowerShell",
    InputKind.BASH:       "Bash shell script",
    InputKind.PYTHON:     "Python source",
    InputKind.JAVASCRIPT: "JavaScript",
    InputKind.VBSCRIPT:   "VBScript",
    InputKind.BATCH:      "Windows batch",
    InputKind.URL:        "URL",
    InputKind.IOC_LIST:   "IOC list",
    InputKind.CSV:        "CSV",
    InputKind.JSON:       "JSON",
    InputKind.XML:        "XML",
    InputKind.YAML:       "YAML",
    InputKind.STIX:       "STIX bundle",
    InputKind.OPENIOC:    "OpenIOC",
    InputKind.YARA:       "YARA rule",
    InputKind.SIGMA:      "Sigma rule",
    InputKind.EMAIL_EML:  "Email (.eml)",
    InputKind.EMAIL_MSG:  "Email (.msg)",
    InputKind.PDF:        "PDF document",
    InputKind.DOCX:       "Word document",
    InputKind.PPTX:       "PowerPoint",
    InputKind.XLSX:       "Excel workbook",
    InputKind.IMAGE:      "Image",
    InputKind.ZIP_ARCHIVE:"ZIP archive",
    InputKind.SEVEN_Z:    "7-Zip archive",
    InputKind.RAR_ARCHIVE:"RAR archive",
    InputKind.ISO:        "ISO image",
    InputKind.EVTX:       "Windows Event Log",
    InputKind.PCAP:       "Packet capture",
    InputKind.PE_BINARY:  "Windows PE binary",
    InputKind.ELF_BINARY: "Linux ELF binary",
    InputKind.MACHO_BINARY:"macOS Mach-O",
    InputKind.APK:        "Android APK",
    InputKind.MIXED:      "Mixed input",
    InputKind.EMPTY:      "Empty input",
}


# ── Magic-byte table for binary sniffing ──────────────────────────
_MAGIC = [
    (b"%PDF-",              InputKind.PDF),
    (b"PK\x03\x04",         InputKind.ZIP_ARCHIVE),   # refined below (docx/pptx/xlsx/apk)
    (b"7z\xBC\xAF\x27\x1C", InputKind.SEVEN_Z),
    (b"Rar!\x1A\x07",       InputKind.RAR_ARCHIVE),
    (b"MZ",                 InputKind.PE_BINARY),
    (b"\x7FELF",            InputKind.ELF_BINARY),
    (b"\xCA\xFE\xBA\xBE",   InputKind.MACHO_BINARY),  # fat mach-o
    (b"\xCF\xFA\xED\xFE",   InputKind.MACHO_BINARY),  # mach-o 64
    (b"\xFE\xED\xFA\xCE",   InputKind.MACHO_BINARY),  # mach-o 32
    (b"CD001",              InputKind.ISO),           # not at offset 0 but often present
    (b"ElfFile\x00",        InputKind.EVTX),
    (b"\xD4\xC3\xB2\xA1",   InputKind.PCAP),
    (b"\xA1\xB2\xC3\xD4",   InputKind.PCAP),
    (b"\x0A\x0D\x0D\x0A",   InputKind.PCAP),          # pcapng
    (b"\xFF\xD8\xFF",       InputKind.IMAGE),          # jpeg
    (b"\x89PNG",            InputKind.IMAGE),
    (b"GIF8",               InputKind.IMAGE),
    (b"BM",                 InputKind.IMAGE),          # bmp
    (b"RIFF",               InputKind.IMAGE),          # webp / wav — refined by extension
    (b"\xD0\xCF\x11\xE0",   InputKind.EMAIL_MSG),      # Outlook .msg / older Office (needs ext)
]


def _sniff_binary(head: bytes,
                    filename: Optional[str]) -> Optional[InputKind]:
    for magic, kind in _MAGIC:
        if head.startswith(magic):
            # PK\x03\x04 covers zip AND office AND apk — refine by ext.
            if kind is InputKind.ZIP_ARCHIVE and filename:
                lo = filename.lower()
                if lo.endswith(".docx"): return InputKind.DOCX
                if lo.endswith(".pptx"): return InputKind.PPTX
                if lo.endswith(".xlsx"): return InputKind.XLSX
                if lo.endswith(".apk"):  return InputKind.APK
                if lo.endswith(".jar"):  return InputKind.ZIP_ARCHIVE
            # Outlook .msg is CFB — same magic as legacy Office.
            if kind is InputKind.EMAIL_MSG and filename:
                lo = filename.lower()
                if not lo.endswith(".msg"):
                    return InputKind.PLAIN_TEXT
            # RIFF is webp or wav
            if kind is InputKind.IMAGE and magic == b"RIFF":
                if len(head) >= 12 and head[8:12] not in (b"WEBP",):
                    return None
            return kind
    return None


# ── Text-shape probes ─────────────────────────────────────────────
_RE_ONLY_URL      = re.compile(r"^\s*(?:https?|ftp|ftps|smb|s3)://\S+\s*$", re.I)
_RE_ONLY_URL_MULTI = re.compile(r"^(?:\s*(?:https?|ftp|ftps|smb|s3)://\S+\s*\n?)+$", re.I)
_RE_HASH          = re.compile(r"^[A-Fa-f0-9]+$")
_RE_IPV4          = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_YARA          = re.compile(r"^\s*(?:import\s+\"[^\"]+\"\s*\n)*\s*rule\s+\w+", re.M)
_RE_SIGMA_TITLE   = re.compile(r"^title:\s*\S", re.M)
_RE_SIGMA_DETECT  = re.compile(r"^detection:\s*$", re.M)
_RE_PS            = re.compile(r"(?i)\b(powershell(\.exe)?\b|\-EncodedCommand|Invoke-Expression|IEX\b|Get-\w+|New-Object)")
_RE_BASH          = re.compile(r"^\s*#!.*/(?:bash|sh|zsh)\b|^\s*(?:curl|wget|sudo|apt-get|yum|chmod|chown|export)\s")
_RE_BATCH         = re.compile(r"(?i)^\s*@echo\b|^\s*setlocal\b|^\s*cmd(\.exe)?\s|/c\s+")
_RE_PY            = re.compile(r"^\s*(?:import\s+\w+|from\s+\w+\s+import|def\s+\w+\s*\(|class\s+\w+\s*[:(])", re.M)
_RE_JS            = re.compile(r"^\s*(?:const|let|var|function\*?)\s+\w+|^\s*document\.|^\s*window\.", re.M)
_RE_VBS           = re.compile(r"(?i)\b(Set\s+\w+\s*=\s*CreateObject|WScript\.\w+|Dim\s+\w+)")
_RE_CMD_HEAD      = re.compile(
    r"(?i)^\s*(cmd|powershell|pwsh|bash|sh|zsh|curl|wget|reg|sc|schtasks|"
    r"wmic|net\s|nslookup|ping|tar|zip|unzip|7z|rar|rundll32|regsvr32|"
    r"certutil|bitsadmin|mshta|msiexec|attrib|whoami|systeminfo)\b")
_RE_URL_ANY       = re.compile(r"(?:https?|ftp|smb|s3)://\S+", re.I)


def classify(payload: Union[bytes, str],
              filename: Optional[str] = None) -> InputKind:
    """Return the canonical InputKind for `payload`.

    `payload` may be bytes (uploaded file) or str (pasted text).
    `filename` refines detection when the same magic covers multiple
    formats (e.g. PK\\x03\\x04 → docx/pptx/xlsx/apk).
    """
    # ── Binary?  Sniff first 16 bytes. ────────────────────────────
    if isinstance(payload, (bytes, bytearray)):
        b = bytes(payload)
        if not b:
            return InputKind.EMPTY
        kind = _sniff_binary(b[:32], filename)
        if kind:
            return kind
        # No magic hit — try to decode as text.
        try:
            payload = b.decode("utf-8", "strict")
        except UnicodeDecodeError:
            try:
                payload = b.decode("latin-1")
            except Exception:
                return InputKind.PLAIN_TEXT  # unknown binary → treat as opaque

    text = (payload or "").strip()
    if not text:
        return InputKind.EMPTY

    # ── Structured text (JSON / YAML / XML / STIX) ────────────────
    lower = text.lower()
    if text.startswith("{") or text.startswith("["):
        # crude JSON detection
        if '"type"' in lower and '"stix' in lower:
            return InputKind.STIX
        if text.rstrip().endswith(("}", "]")):
            return InputKind.JSON
    if text.startswith("<?xml") or text.startswith("<"):
        if "ioc:indicator" in lower or "<openioc" in lower:
            return InputKind.OPENIOC
        return InputKind.XML

    # ── YARA / Sigma ──────────────────────────────────────────────
    if _RE_YARA.search(text):
        return InputKind.YARA
    if _RE_SIGMA_TITLE.search(text) and _RE_SIGMA_DETECT.search(text):
        return InputKind.SIGMA

    # ── Email raw ────────────────────────────────────────────────
    # RFC 5322 sniff — `From:` / `Subject:` headers at line start
    # anywhere in the first 4 KB.  Must come BEFORE the YAML probe
    # because email headers look like key:value pairs to a naive
    # detector.
    head = text[:4096]
    if (re.search(r"(?im)^From:\s+\S+@\S+", head) and
          re.search(r"(?im)^Subject:\s+\S", head)):
        return InputKind.EMAIL_EML

    # ── Single-line probes ────────────────────────────────────────
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) == 1:
        line = lines[0]
        if _RE_ONLY_URL.match(line):        return InputKind.URL
        if _RE_HASH.match(line) and len(line) in (32, 40, 64, 128):
            return InputKind.IOC_LIST
        if _RE_IPV4.match(line):            return InputKind.IOC_LIST
        if _RE_PS.search(line):             return InputKind.POWERSHELL
        if _RE_BATCH.search(line):          return InputKind.BATCH
        if _RE_BASH.search(line):           return InputKind.BASH
        if _RE_CMD_HEAD.search(line):       return InputKind.COMMAND
        return InputKind.PLAIN_TEXT

    # ── Multi-line probes ────────────────────────────────────────
    if _RE_ONLY_URL_MULTI.match(text):
        return InputKind.URL
    if _RE_PY.search(text):     return InputKind.PYTHON
    if _RE_JS.search(text):     return InputKind.JAVASCRIPT
    if _RE_VBS.search(text):    return InputKind.VBSCRIPT
    if _RE_PS.search(text):     return InputKind.POWERSHELL
    if _RE_BASH.search(text):   return InputKind.BASH
    if _RE_BATCH.search(text):  return InputKind.BATCH

    # CSV — comma-heavy lines, all similar column count.
    if _looks_like_csv(text):   return InputKind.CSV

    # IOC list — mostly hashes/ips/domains/urls.
    if _looks_like_ioc_list(lines):
        return InputKind.IOC_LIST

    # YAML — key: value lines, no braces.
    if _looks_like_yaml(text):  return InputKind.YAML

    # If the paste has BOTH a URL and command-shaped content → MIXED.
    has_url = bool(_RE_URL_ANY.search(text))
    has_cmd = any(_RE_CMD_HEAD.search(ln) for ln in lines[:20])
    if has_url and has_cmd:
        return InputKind.MIXED

    return InputKind.PLAIN_TEXT


# ── Heuristics ────────────────────────────────────────────────────
def _looks_like_csv(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip()][:8]
    if len(lines) < 2: return False
    counts = [ln.count(",") for ln in lines]
    return counts[0] >= 2 and all(abs(c - counts[0]) <= 1 for c in counts)


def _looks_like_ioc_list(lines) -> bool:
    if len(lines) < 2: return False
    hits = 0
    for ln in lines[:40]:
        s = ln.strip()
        if _RE_HASH.match(s) and len(s) in (32, 40, 64, 128): hits += 1
        elif _RE_IPV4.match(s):                                hits += 1
        elif _RE_ONLY_URL.match(s):                            hits += 1
        elif re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", s, re.I):   hits += 1
    return hits >= max(2, int(0.6 * min(len(lines), 40)))


def _looks_like_yaml(text: str) -> bool:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")][:20]
    if len(lines) < 2: return False
    kv = sum(1 for ln in lines if re.match(r"^[A-Za-z_][A-Za-z0-9_ -]*:", ln))
    return kv >= max(2, int(0.6 * len(lines)))
