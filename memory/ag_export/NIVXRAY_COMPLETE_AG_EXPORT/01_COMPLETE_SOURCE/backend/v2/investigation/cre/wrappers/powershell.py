"""PowerShell wrapper — `powershell.exe [switches] -Command "<inner>"`,
`-EncodedCommand <b64>`, `-c "<inner>"`, `-File "<path>"`.

The PowerShell entrypoint is BOTH a wrapper (peels off the launcher
switches to expose the script the interpreter will execute) AND the
terminal analyzer target (the effective payload's dispatch_hint is
POWERSHELL, so the semantic engine picks it up). The CRE cares only
about the wrapper aspect — peel the launcher switches and hand the
script text to the next stage.
"""
from __future__ import annotations

import base64
import re

from ..models import WrapperChainStep

_PS_HEAD_RE = re.compile(
    r"""(?ix)
    ^\s*(?:c:\\[^\s]*\\)?(?:powershell|pwsh)(?:\.exe)?\b
    (?P<tail>.*)$
    """,
    re.DOTALL,
)
_ENCODED_ARG_RE = re.compile(
    r"(?i)-(?:e|ec|enc|encodedcommand)\s+(?P<b64>[A-Za-z0-9+/=]+)")
_COMMAND_ARG_QUOTED_RE = re.compile(
    r"""(?ix)
    -(?:c|command)\s+
    (?P<q>['"])(?P<inner>.*)(?P=q)\s*$
    """,
    re.DOTALL,
)
_COMMAND_ARG_BARE_RE = re.compile(
    r"(?i)-(?:c|command)\s+(?P<inner>\S.*)$", re.DOTALL)
_FILE_ARG_RE = re.compile(
    r"""(?ix)
    -(?:f|file)\s+
    (?:['"])?(?P<path>[^'"\s]+)(?:['"])?
    """
)


class PowerShellWrapper:
    NAME = "powershell"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("powershell") or low.startswith("pwsh") or \
               "\\powershell" in low[:96]

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        head = _PS_HEAD_RE.match(cmdline)
        if not head:
            return None
        tail = head.group("tail") or ""

        # ── -EncodedCommand — the inner script is a UTF-16LE-encoded
        # base64 payload. Decode statically (no execution).
        enc = _ENCODED_ARG_RE.search(tail)
        if enc:
            b64 = enc.group("b64")
            try:
                inner = base64.b64decode(b64).decode("utf-16-le", errors="replace")
            except Exception:  # noqa: BLE001
                return None
            return WrapperChainStep(
                wrapper=self.NAME,
                command="-EncodedCommand",
                inner_command=inner,
                normalized_command=inner.strip(),
                evidence=(
                    "Matched PowerShell `-EncodedCommand` — the Base64 "
                    "argument was decoded as UTF-16LE (the PS standard "
                    "wire format) to yield the inner script. Fully "
                    "deterministic; no execution required."
                ),
                confidence=100,
            )

        # ── -Command "<inner>" (or -c ...)
        cq = _COMMAND_ARG_QUOTED_RE.search(tail)
        if cq:
            inner = cq.group("inner")
            return WrapperChainStep(
                wrapper=self.NAME,
                command="-Command",
                inner_command=inner,
                normalized_command=inner.strip(),
                evidence=(
                    "Matched PowerShell `-Command \"…\"` — the quoted "
                    "script text is what powershell.exe will actually "
                    "execute. Extraction proved by PS argument grammar."
                ),
                confidence=100,
            )
        cb = _COMMAND_ARG_BARE_RE.search(tail)
        if cb:
            inner = cb.group("inner").strip()
            return WrapperChainStep(
                wrapper=self.NAME,
                command="-Command",
                inner_command=inner,
                normalized_command=inner,
                evidence=(
                    "Matched PowerShell `-Command <bare>` — the trailing "
                    "argument after `-Command` / `-c` becomes the script "
                    "the interpreter runs."
                ),
                confidence=90,
            )

        # ── -File <path>  (artefact only — do not fabricate contents)
        f = _FILE_ARG_RE.search(tail)
        if f:
            return WrapperChainStep(
                wrapper=self.NAME,
                command="-File",
                inner_command=f.group("path"),
                normalized_command=f.group("path"),
                evidence=(
                    "Matched PowerShell `-File <path>` — the interpreter "
                    "will run the referenced .ps1 script. The Workspace "
                    "cannot resolve remote / local file contents "
                    "statically; downstream analysis proceeds on the "
                    "file path as an artefact only."
                ),
                confidence=90,
            )
        return None


PARSER = PowerShellWrapper()
