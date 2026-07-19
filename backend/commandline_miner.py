"""Command-line miner — extract candidate commandlines from arbitrary text.

Given the plaintext extracted from an uploaded document, pull out substrings
that look like real command-line payloads so each one can be run through the
Batch Analyst / deterministic decode pipeline.

Design
------
Purely deterministic. No LLM, no external calls. Uses a scored regex catalog:

    * `powershell(.exe)? …`                      (with quoted / unquoted args)
    * `pwsh(.exe)? …`
    * `cmd(.exe)? /[cCkK] …`                     (single or double-quoted body)
    * `mshta(.exe)? …`
    * `rundll32 …`,  `regsvr32 …`,  `wmic …`,  `certutil …`,  `bitsadmin …`
    * `msiexec …`,   `hh(.exe)? …`,  `cscript …`,  `wscript …`
    * `bash -c "…"`,  `sh -c "…"`,  `curl … | bash`,  `wget … -O -`
    * `data:*;base64,<b64>`
    * `[Convert]::FromBase64String('…')`,  `[System.Convert]::FromBase64String…`
    * `Invoke-Expression …`,  `IEX(…)`,  `New-Object Net.WebClient`,  `Invoke-WebRequest …`
    * Long stand-alone Base64 blocks (≥ 40 chars) — surfaced so they can be
      decoded independently even if no surrounding wrapper exists
    * Raw URLs (http/https/ftp) that look like C2 endpoints
    * `.ps1 / .bat / .cmd / .vbs / .hta / .wsf / .js / .py / .sh` script bodies
      when the file itself was a script (whole-file fallback)

Every extraction returns a `Candidate` with `origin`, `text`, `kind`,
`confidence` so the UI can group / colour / de-duplicate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List


@dataclass
class Candidate:
    text: str
    kind: str = "commandline"        # commandline | wrapper | script | b64-blob | url
    confidence: float = 0.7
    origin: str = ""                 # copied from ExtractedSegment.origin


# --------------------------------------------------------------------------- #
# Regex catalog — hot-path.  DOTALL allows patterns to span newlines when the
# document extraction glued lines together with `\n` separators.
# --------------------------------------------------------------------------- #
_RX_POWERSHELL = re.compile(
    r"""(?ix)
    \b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)         # binary
    (?:\s+[^;\n\r`]{0,80}?)?                          # optional flags
    (?:\s+["'][^"']+["']                              # quoted payload
       |\s+-?[eE](?:nc(?:oded)?(?:command)?)?         # -EncodedCommand
         \s+[A-Za-z0-9+/=_\-]{16,}                    # b64 body
       |\s+-?[cC](?:ommand)?\s+["'][^"']+["']         # -Command "…"
       |\s+-?[cC](?:ommand)?\s+\{[^}]+\}              # -Command { … }
       |\s+[^\n\r]{4,240}                             # generic tail
    )
    """
)
_RX_CMD = re.compile(
    r"""(?ix)
    \bcmd(?:\.exe)?\s+/[cCkKqQ]                      # cmd /c or /k
    \s+["'][^"']{4,400}["']                          # quoted body
    """
)
_RX_CMD_UNQ = re.compile(
    r"""(?ix)
    \bcmd(?:\.exe)?\s+/[cCkKqQ]\s+[^\n\r]{4,300}
    """
)

_RX_LOLBAS = re.compile(
    r"""(?ix)
    \b(?:mshta|rundll32|regsvr32|regsvcs|regasm|wmic|certutil|bitsadmin
       |msiexec|hh(?:\.exe)?|cscript|wscript|installutil|msbuild
       |odbcconf|schtasks|forfiles|explorer(?:\.exe)?|xcopy)
    (?:\.exe)?\s+[^\n\r]{2,320}
    """
)

_RX_BASH = re.compile(
    r"""(?ix)
    \b(?:bash|sh|dash|zsh)\s+-c\s+["'][^"']{4,400}["']
    """
)
_RX_CURL_PIPE = re.compile(
    r"""(?ix)
    \b(?:curl|wget|fetch)\s+[^|\n\r]{4,240}\s*\|\s*(?:bash|sh|zsh|python|perl|php)\b
    """
)

_RX_FROM_B64 = re.compile(
    r"""
    \[?\s*(?:System\.)?Convert\s*\]?::FromBase64String\(\s*['"][^'"]{8,}['"]\s*\)
    """,
    re.IGNORECASE | re.VERBOSE,
)

_RX_IEX = re.compile(
    r"""(?ix)
    \b(?:Invoke-Expression|IEX)\s*\(?[^\n\r]{4,240}
    """
)
_RX_WEB = re.compile(
    r"""(?ix)
    \b(?:New-Object\s+(?:System\.)?Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|IWR|IRM)
    [^\n\r]{0,200}
    """
)

_RX_DATA_URI = re.compile(
    r"""(?i)\bdata:[a-z0-9.+\-/]+(?:;charset=[^;,]+)?(?:;base64)?,[^"'\s<>]{20,}"""
)

_RX_LONG_B64 = re.compile(
    r"""(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{60,}(?![A-Za-z0-9+/=_-])"""
)

_RX_URL = re.compile(
    r"""(?i)\b(?:https?|ftp)://[^\s"'<>{}|\\^`]{6,240}"""
)

# --------------------------------------------------------------------------- #
# Extraction
# --------------------------------------------------------------------------- #
def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()


def _dedup(cands: Iterable[Candidate]) -> List[Candidate]:
    seen = set()
    out: List[Candidate] = []
    for c in cands:
        key = _norm(c.text.lower())[:400]
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def mine(text: str, *, origin: str = "") -> List[Candidate]:
    """Extract candidate commandlines from a chunk of plaintext.

    Returns a de-duplicated list ordered by confidence descending.
    """
    if not text:
        return []
    cands: List[Candidate] = []

    for m in _RX_POWERSHELL.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.95,
                                origin=origin))
    for m in _RX_CMD.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.92,
                                origin=origin))
    for m in _RX_CMD_UNQ.finditer(text):
        # Skip if already covered by the quoted variant above
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.75,
                                origin=origin))
    for m in _RX_LOLBAS.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.88,
                                origin=origin))
    for m in _RX_BASH.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.9,
                                origin=origin))
    for m in _RX_CURL_PIPE.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.9,
                                origin=origin))
    for m in _RX_FROM_B64.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="wrapper", confidence=0.9,
                                origin=origin))
    for m in _RX_IEX.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.85,
                                origin=origin))
    for m in _RX_WEB.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="commandline", confidence=0.8,
                                origin=origin))
    for m in _RX_DATA_URI.finditer(text):
        cands.append(Candidate(text=_norm(m.group(0)),
                                kind="wrapper", confidence=0.85,
                                origin=origin))
    for m in _RX_LONG_B64.finditer(text):
        blob = m.group(0)
        # Suppress if already inside a candidate — the outer wrapper is more
        # valuable. Cheap check: skip when the blob is a substring of an
        # already-collected wrapper/commandline candidate.
        if any(blob in c.text for c in cands):
            continue
        cands.append(Candidate(text=blob, kind="b64-blob", confidence=0.55,
                                origin=origin))
    for m in _RX_URL.finditer(text):
        url = m.group(0).rstrip(".,;:)]")
        if any(url in c.text for c in cands):
            continue
        cands.append(Candidate(text=url, kind="url", confidence=0.45,
                                origin=origin))

    # Order by confidence descending, stable within kind.
    cands = _dedup(cands)
    cands.sort(key=lambda c: (-c.confidence, c.kind))
    return cands


def mine_segments(segments: Iterable) -> List[Candidate]:
    """Convenience — run `mine()` over every ExtractedSegment produced by
    `file_extractors.extract()` and stamp the segment's origin onto each
    resulting Candidate.
    """
    out: List[Candidate] = []
    for seg in segments:
        text = getattr(seg, "text", "") or ""
        origin = getattr(seg, "origin", "") or ""
        for c in mine(text, origin=origin):
            out.append(c)
    return _dedup(out)
