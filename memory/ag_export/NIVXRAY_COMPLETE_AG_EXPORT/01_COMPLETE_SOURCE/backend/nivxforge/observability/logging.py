"""NivXForge logging — isolated namespace, no shared handlers.

Every log line emitted by nivxforge code MUST use `get_logger()` from
this module. This keeps NivXForge logs out of Workspace log streams
so they can be routed / silenced / audited independently.
"""

from __future__ import annotations

import logging


_LOGGER_ROOT = "nivxforge"


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the isolated `nivxforge.*` namespace.

    Args:
        name: A dotted suffix (e.g. `"cio"`, `"engines.base"`). The
              caller does not include the `nivxforge` prefix.
    """
    if not name:
        raise ValueError("logger name must be non-empty")
    return logging.getLogger(f"{_LOGGER_ROOT}.{name}")
