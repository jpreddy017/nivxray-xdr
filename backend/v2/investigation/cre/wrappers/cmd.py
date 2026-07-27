"""CMD wrapper — `cmd /c "<inner>"` and `cmd /k "<inner>"`.

Also handles the unquoted form `cmd /c inner…` (cmd's own grammar
accepts a bare inner command after `/c` when no embedded quotes are
present)."""
from __future__ import annotations

import re

from ..models import WrapperChainStep

_CMD_QUOTED_RE = re.compile(
    r"""(?ix)
    ^\s*(?:c:\\[^\s]*\\)?cmd(?:\.exe)?\s+
    (?:/[a-z]\s+)*                               # /d /s /q etc.
    (?P<verb>/c|/k|/r)\s+
    (?P<q>['"])(?P<inner>.*)(?P=q)\s*$
    """,
    re.DOTALL,
)
_CMD_BARE_RE = re.compile(
    r"""(?ix)
    ^\s*(?:c:\\[^\s]*\\)?cmd(?:\.exe)?\s+
    (?:/[a-z]\s+)*
    (?P<verb>/c|/k|/r)\s+
    (?P<inner>\S.*)$
    """,
    re.DOTALL,
)


class CmdWrapper:
    NAME = "cmd"

    def match(self, cmdline: str) -> bool:
        low = cmdline.lstrip().lower()
        return low.startswith("cmd ") or low.startswith("cmd.exe ") or \
               low.startswith("c:\\") and "cmd" in low[:64]

    def extract(self, cmdline: str) -> WrapperChainStep | None:
        m = _CMD_QUOTED_RE.match(cmdline)
        conf = 100
        note = "quoted"
        if not m:
            m = _CMD_BARE_RE.match(cmdline)
            conf = 90
            note = "bare (no surrounding quotes on the inner command)"
        if not m:
            return None
        inner = m.group("inner").strip()
        # Peel doubled escape sequences `\"` → `"` that cmd introduces
        # inside its own quoting (e.g. when nested via wmic).
        normalized = inner.replace('\\"', '"').replace('\\\\', '\\').strip()
        return WrapperChainStep(
            wrapper=self.NAME,
            command=m.group("verb").lower(),
            inner_command=inner,
            normalized_command=normalized,
            evidence=(
                f"Matched CMD `{m.group('verb')}` {note} form — the "
                "wrapper executes the inner command in a new cmd shell. "
                "Extraction proved by CMD's own argument grammar."
            ),
            confidence=conf,
        )


PARSER = CmdWrapper()
