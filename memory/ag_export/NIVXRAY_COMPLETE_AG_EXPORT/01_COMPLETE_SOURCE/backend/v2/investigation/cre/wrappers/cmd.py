"""CMD wrapper — `cmd /c "<inner>"` and `cmd /k "<inner>"`.

Uses the shared escape-aware quoted-string scanner so nested wrapper
chains (`cmd /c "powershell -C \\"…\\""`) survive peeling.
"""
from __future__ import annotations

import re

from ..models import WrapperChainStep
from ._quoting import extract_quoted, normalize_escaped_quotes

_CMD_HEAD_RE = re.compile(
    r"""(?ix)
    ^\s*(?:c:\\[^\s]*\\)?cmd(?:\.exe)?\s+
    (?:/[a-z]\s+)*
    (?P<verb>/c|/k|/r)\s+
    """,
    re.DOTALL,
)


class CmdWrapper:
    NAME = "cmd"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return (low.startswith("cmd ") or low.startswith("cmd.exe ") or
                (low.startswith("c:\\") and "cmd" in low[:64]))

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _CMD_HEAD_RE.match(cmdline)
        if not m:
            return None
        verb = m.group("verb").lower()
        rest = cmdline[m.end():]
        # Quoted form: `cmd /c "..."`
        if rest.startswith('"'):
            got = extract_quoted(rest, 0)
            if got:
                inner, _ = got
                normalized = normalize_escaped_quotes(inner).strip()
                return WrapperChainStep(
                    wrapper=self.NAME,
                    command=verb,
                    inner_command=inner,
                    normalized_command=normalized,
                    evidence=(
                        f"Matched CMD `{verb}` quoted form — wrapper "
                        "executes the inner command in a new cmd "
                        "shell. Escape-aware quote scanner handles "
                        "nested `\\\"…\\\"` sequences."
                    ),
                    confidence=100,
                )
        # Bare form: `cmd /c foo bar baz` (no surrounding quotes)
        inner = rest.strip()
        if not inner:
            return None
        return WrapperChainStep(
            wrapper=self.NAME,
            command=verb,
            inner_command=inner,
            normalized_command=inner,
            evidence=(
                f"Matched CMD `{verb}` bare form (no surrounding quotes "
                "on the inner command). Wrapper executes the trailing "
                "arguments as one command line in a new cmd shell."
            ),
            confidence=90,
        )


PARSER = CmdWrapper()
