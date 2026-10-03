"""G-41 · the ONE comparable temporal value for EDR evidence selection.

WHY THIS EXISTS. `event_time` holds the collector's timestamp VERBATIM, because
`ingest_provenance.validate()` deliberately refuses to re-render a collector's
measurement as ours. That is right for evidence and wrong for comparison:
production holds two valid representations of the same clock —
`"2026-09-27 23:55:38.144"` (Sysmon's zone-less `UtcTime`) and
`"2026-09-27T00:06:30.755Z"` — and MongoDB compares strings byte by byte. At
string position 10 a space is 0x20 and `T` is 0x54, so within one calendar date
EVERY space-format row sorts below EVERY `Z`-format row regardless of the time
of day. Measured in production: an event at 23:55 sorting below an event at
00:06 of the same day, on all three dates where the two representations
coexist, across 43,516 of 43,521 space-format rows.

Ordering alone was never the damage — the trajectory adapter re-sorts in memory
on parsed microseconds and gets the order right. The damage is SELECTION: a
`LIMIT` applied under that string sort fetches the wrong "newest N", and a
resume cursor expressed as a raw stored string excludes same-date rows that
belong on a LATER page, permanently. Evidence that is never fetched cannot be
re-sorted into view.

THE CONTRACT

    observation_us  —  signed int, UTC epoch MICROSECONDS, derived
                       deterministically from the stored event occurrence time.

* The same physical instant yields the same value from any representation.
* `event_time` is never read for ordering again, and never rewritten.
* `ingest_time` is NEVER a source. Backlog replay is real here; placing a
  replayed event at its ingestion instant puts it in the wrong place on an
  analyst's timeline. An absent source time stays absent.
* A value that cannot be parsed FAILS CLOSED: the field is left absent and the
  row is marked unplaceable, so it is excluded from the temporal query path
  instead of being given an invented time. Ingestion still succeeds — evidence
  durability must never depend on this derivation.
* One parser. `edr_trajectory.production_adapter.observation_us` delegates here
  rather than keeping a second implementation that could drift.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Tuple

#: The stored comparable instant. Additive: nothing else is modified.
OBSERVATION_US = "observation_us"

#: The verbatim evidence value. Read-only, for derivation only, never rewritten.
SOURCE_FIELD = "event_time"

#: Declared beside the other `event_time_*` declarations in `additional_fields`.
STATE_KEY = "observation_us_state"
BASIS_KEY = "observation_us_basis"

STATE_DERIVED = "DERIVED_FROM_STORED_OBSERVATION_TIME"
STATE_UNPLACEABLE = "UNPLACEABLE_UNPARSEABLE_OBSERVATION_TIME"
STATE_ABSENT = "UNPLACEABLE_NO_OBSERVATION_TIME"

#: Named so an auditor can see the derivation was arithmetic over the stored
#: value, and not a substituted clock.
BASIS = "ARITHMETIC_OVER_STORED_EVENT_TIME"

CONTRACT_VERSION = "G-41"


def to_epoch_us(value: Any) -> Optional[int]:
    """UTC epoch microseconds, at FULL SOURCE PRECISION. `None` if unreadable.

    Accepts every representation this platform actually stores: a zone-less
    string (treated as UTC, never as local time — the sensors emit UTC), a
    trailing `Z`, an explicit numeric offset, a `datetime`, or a numeric
    millisecond value. `.replace(microsecond=0).timestamp()` keeps the integer
    seconds exact before the microseconds are added back, so sub-millisecond
    precision is never lost to float rounding.
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value) * 1000
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(dt.replace(microsecond=0).timestamp()) * 1_000_000 + dt.microsecond
    s = str(value).strip().replace(" ", "T", 1)
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.replace(microsecond=0).timestamp()) * 1_000_000 + dt.microsecond


def derive(doc: Mapping[str, Any]) -> Tuple[Optional[int], str]:
    """`(observation_us, state)` from the stored observation time alone."""
    raw = doc.get(SOURCE_FIELD)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None, STATE_ABSENT
    us = to_epoch_us(raw)
    return (us, STATE_DERIVED) if us is not None else (None, STATE_UNPLACEABLE)


def stamp(doc: dict) -> dict:
    """Stamp a canonical document in place at the writer boundary.

    Fail-closed: when the stored time cannot be read the field stays ABSENT and
    the state says why. The row is still written; it is simply not addressable
    by the temporal path, which is the same honest `UNPLACEABLE` treatment the
    trajectory adapter already applies.
    """
    us, state = derive(doc)
    extra = doc.setdefault("additional_fields", {})
    if isinstance(extra, dict):
        extra[STATE_KEY] = state
        extra[BASIS_KEY] = BASIS if us is not None else None
    if us is not None:
        doc[OBSERVATION_US] = us
    else:
        doc.pop(OBSERVATION_US, None)
    return doc


def is_stamped(doc: Mapping[str, Any]) -> bool:
    """A document has passed the boundary when it carries a declared state."""
    extra = doc.get("additional_fields")
    return isinstance(extra, Mapping) and STATE_KEY in extra


def assert_stamped(doc: Mapping[str, Any]) -> None:
    """The writer invariant. A future endpoint writer that forgets `stamp()`
    fails here rather than silently producing evidence the temporal path cannot
    select."""
    if not is_stamped(doc):
        raise AssertionError(
            "canonical endpoint evidence must pass temporal_authority.stamp() "
            "before it is written: no observation_us state was declared")
    us = doc.get(OBSERVATION_US)
    state = (doc.get("additional_fields") or {}).get(STATE_KEY)
    if state == STATE_DERIVED and not isinstance(us, int):
        raise AssertionError("state says DERIVED but observation_us is not an int")
    if state != STATE_DERIVED and us is not None:
        raise AssertionError(
            f"state {state!r} must not carry an observation_us value")
