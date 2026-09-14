"""D1 · Provenance timestamps — one shape, four honest statuses.

A timestamp field that exists but was filled from a convenient nearby value
is worse than no field at all: it looks like measurement and is not. So every
stamp carries its own status and its own source, and a consumer can always
tell the difference between:

    AVAILABLE       a real value, captured at the real boundary
    NOT_APPLICABLE  that boundary does not exist on this path
    NOT_OBSERVED    the boundary exists but the source could not see it
    MISSING         it should exist and was not captured — a gap to fix

Nothing in here invents, backfills, or copies a value from another stage.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

AVAILABLE = "AVAILABLE"
NOT_APPLICABLE = "NOT_APPLICABLE"
NOT_OBSERVED = "NOT_OBSERVED"
MISSING = "MISSING"

#: The boundaries the owner requires, in pipeline order.
STAMP_NAMES = (
    "activity_occurred_at",
    "sensor_observed_at",
    "collector_received_at",
    "nivx_received_at",
    "parsed_at",
    "normalized_at",
    "rule_evaluated_at",
    "verdict_at",
)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stamp(value: str | None = None, *, status: str | None = None,
          source: str | None = None, reason: str | None = None
          ) -> dict[str, Any]:
    """One stamp. A value implies AVAILABLE; no value REQUIRES an explicit
    status, so an uncaptured boundary can never masquerade as a measured one."""
    if value:
        return {"value": value, "status": status or AVAILABLE,
                "source": source}
    if not status or status == AVAILABLE:
        raise ValueError("a stamp without a value needs a non-AVAILABLE "
                         "status — refusing to record an empty AVAILABLE")
    return {"value": None, "status": status, "source": source,
            "reason": reason}


def block(**stamps: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Assemble the full set. Anything not supplied is recorded as MISSING
    rather than silently omitted, so a gap is visible instead of invisible."""
    out: dict[str, dict[str, Any]] = {}
    for name in STAMP_NAMES:
        out[name] = stamps.get(name) or stamp(
            status=MISSING,
            reason="no stamp was captured at this boundary")
    return out


def put(canonical: dict[str, Any], name: str, entry: dict[str, Any]) -> None:
    """Record one stamp on a canonical event, creating the block if the
    producer did not seed one."""
    prov = canonical.setdefault("provenance", {})
    tsb = prov.get("timestamps")
    if not isinstance(tsb, dict):
        tsb = block()
        prov["timestamps"] = tsb
    tsb[name] = entry
