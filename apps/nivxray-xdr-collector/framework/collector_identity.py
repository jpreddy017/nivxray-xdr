"""THE collector identity binding for one collector process.

`collector_id` is a permanent identity contract, not a convenience: it is the
value the authoritative NivXRay XDR ingest boundary matches against its
enrolled collector record, and it is one third of the acquisition bookmark
scope `(tenant_id, collector_id, channel)`.

Two rules are enforced here, process-wide:

  * ONE tenant per collector identity. A second connector that declares the
    same `collector_id` under a different tenant is refused — an ingest
    identity is tenant-bound at the boundary, so letting two tenants share
    one would mean one tenant's acquisition position and delivery identity
    stood for another's.
  * The identity must be declared. There is no generated fallback anywhere,
    because a value that changes per process cannot be enrolled server-side
    and cannot resume an acquisition position.
"""
from __future__ import annotations

import threading
from typing import Dict

_LOCK = threading.RLock()
_BINDINGS: Dict[str, str] = {}


class CollectorIdentityConflict(ValueError):
    """A declared collector identity is already bound to another tenant."""


def bind(collector_id: str, tenant_id: str) -> str:
    """Bind `collector_id` to `tenant_id`, or raise on a cross-tenant reuse."""
    cid = (collector_id or "").strip()
    ten = (tenant_id or "").strip()
    if not cid:
        raise ValueError("collector_id must be declared; it is never generated")
    if not ten:
        raise ValueError("tenant_id must be declared for a collector identity")
    if any(ch.isspace() for ch in cid):
        raise ValueError(
            f"collector_id {cid!r} contains whitespace; it must match the id "
            "enrolled in NivXRay XDR exactly")
    with _LOCK:
        held = _BINDINGS.get(cid)
        if held is not None and held != ten:
            raise CollectorIdentityConflict(
                f"collector_id {cid!r} is already bound to tenant {held!r}; "
                f"refusing to also bind it to {ten!r}. One collector identity "
                "belongs to exactly one tenant at the authoritative ingest "
                "boundary and in the acquisition bookmark scope.")
        _BINDINGS[cid] = ten
    return cid


def tenant_of(collector_id: str) -> str | None:
    with _LOCK:
        return _BINDINGS.get((collector_id or "").strip())


def release(collector_id: str) -> None:
    """Drop a binding (connector deleted, or test teardown)."""
    with _LOCK:
        _BINDINGS.pop((collector_id or "").strip(), None)


def bindings() -> Dict[str, str]:
    with _LOCK:
        return dict(_BINDINGS)
