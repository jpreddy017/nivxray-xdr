"""Command-line adapter — detects Windows / Unix command-line
strings (%COMSPEC%, cmd.exe, powershell.exe, sh -c, bash -c, curl,
wget) and emits them as ``commandline`` artifacts so the UAIE
capabilities that specialise in command-lines (LOLBAS scanner,
PowerShell decoder, encoded-command extractor) pick them up.

This complements plain_text: an input that looks like a single
command line goes through this adapter first so the artifact is
typed as ``commandline`` rather than generic ``text``.
"""
from __future__ import annotations
import re
from typing import Optional
from ..artifact import make_artifact
from ._base import Adapter, AdapterResult, register_adapter


_CMD_MARKERS = (
    r"%COMSPEC%",
    r"\bcmd\.exe\b",
    r"\bpowershell(?:\.exe)?\b",
    r"\bpwsh(?:\.exe)?\b",
    r"\bwscript\.exe\b",
    r"\bcscript\.exe\b",
    r"\bmshta(?:\.exe)?\b",
    r"\brundll32(?:\.exe)?\b",
    r"\bregsvr32(?:\.exe)?\b",
    r"\bcertutil(?:\.exe)?\b",
    r"\bbitsadmin(?:\.exe)?\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bsh\s+-c\b",
    r"\bbash\s+-c\b",
)
_CMD_RE = re.compile("|".join(_CMD_MARKERS), re.IGNORECASE)


class _CommandLineAdapter:
    name = "adapter.commandline"
    priority = 78

    def sniff(self, payload: bytes, *, filename=None, declared_mime=None) -> int:
        # Reject binary payloads outright.  Command-line strings are
        # always printable text with no NUL/PK/MZ headers.
        if payload[:2] in (b"PK", b"MZ") or payload[:4] == b"%PDF":
            return 0
        if b"\x00" in payload[:512]:
            return 0
        try:
            head = payload[:4096].decode("utf-8", errors="ignore")
        except Exception:
            return 0
        if not head.strip():
            return 0
        # Multi-line docs shouldn't get claimed as command lines.
        lines = head.strip().splitlines()
        if len(lines) > 6:
            return 0
        first = lines[0] if lines else ""
        if _CMD_RE.search(first):
            # Strong signal if the WHOLE payload is short (< 32 KB).
            return 92 if len(payload) < 32_768 else 60
        return 0

    def extract(self, payload: bytes, *, filename: Optional[str] = None) -> AdapterResult:
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            text = payload.decode("latin-1", errors="replace")
        art = make_artifact(
            text.encode("utf-8"), "commandline",
            discovered_by=self.name,
            meta={"filename": filename, "length": len(text)})
        return AdapterResult(artifacts=[art],
                                meta={"format": "text/commandline"})


register_adapter(_CommandLineAdapter())
