"""Handler Registry — ADR-0001.

Maps family token → list of registered Handlers. The registry is the
only object that knows which handlers exist; downstream orchestration
looks them up here. Registration is explicit — no auto-discovery.
"""

from __future__ import annotations

from typing import Dict, List

from nivxforge.framework.protocol import Handler


_HANDLERS: Dict[str, List[Handler]] = {}


def register_handler(handler: Handler) -> None:
    """Register a handler under its declared family.

    The handler must satisfy the Handler Protocol (runtime-checkable),
    which requires HandlerMetadata carrying an ADR citation and
    evidence_count ≥ 1.
    """
    if not isinstance(handler, Handler):
        raise TypeError(
            f"handler {handler!r} does not satisfy the Handler Protocol"
        )
    fam = handler.family
    if not fam:
        raise ValueError("handler.family must be non-empty")
    _HANDLERS.setdefault(fam, []).append(handler)


def handlers_for(family: str) -> List[Handler]:
    """Return handlers registered for `family`, in registration order."""
    return list(_HANDLERS.get(family, []))


def registered_families() -> List[str]:
    return sorted(_HANDLERS.keys())


def total_handlers() -> int:
    return sum(len(v) for v in _HANDLERS.values())
