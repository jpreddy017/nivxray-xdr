"""G1/S4 · THE persistent state root, per platform.

Durable acquisition state is not a convenience — the outbox and the Windows
channel bookmarks share one SQLite file (`outbox.db`) precisely so that a
delivery record and the position it justifies live in one fsync domain. That
only holds if the file is where the operator intends it to be.

`/var/lib/nivxray` was the single hard-coded default. On Windows it resolves
to `C:\\var\\lib\\nivxray` on whatever the current drive happens to be:
legal, writable, and nowhere an operator would look, back up, or ACL. So the
default is platform-resolved, and the Windows root is the declared one.

Precedence is unchanged: `XDR_STATE_DIR` always wins. The default exists so
an unset variable lands somewhere defensible, never so it can override an
operator.
"""
from __future__ import annotations

import os
import platform

#: The declared Windows persistence root for NivXForge EDR.
WINDOWS_DEFAULT_STATE_DIR = r"C:\ProgramData\NivXForge\state"
#: The POSIX default, unchanged.
POSIX_DEFAULT_STATE_DIR = "/var/lib/nivxray"


def default_state_dir(system: str | None = None) -> str:
    """The platform default. Windows NEVER falls back to the POSIX path."""
    sysname = system or platform.system()
    return (WINDOWS_DEFAULT_STATE_DIR if sysname == "Windows"
            else POSIX_DEFAULT_STATE_DIR)


def state_dir() -> str:
    """`XDR_STATE_DIR` when set, else the platform default."""
    declared = (os.environ.get("XDR_STATE_DIR") or "").strip()
    return declared or default_state_dir()


def state_path(filename: str) -> str:
    return os.path.join(state_dir(), filename)
