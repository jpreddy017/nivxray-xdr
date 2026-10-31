"""Canonical timestamp instants for the EDR trajectory planes.

The invariant this module exists to enforce:

    compare timestamps as INSTANTS, render timestamps as TIME.
    NEVER compare timestamps lexicographically.

Genuine Windows telemetry states its own instant in two different, equally
authoritative shapes:

    2026-09-22 15:43:31.770          Sysmon `EventData/UtcTime`
    2026-09-22T15:43:31.7788153Z     Windows Event Log `TimeCreated`

They are the same class of UTC instant. Compared as strings they are not
ordered at all — `' '` (0x20) sorts before `'T'` (0x54) — which is how 3333
real Sysmon observations were excluded from every windowed trajectory read
(`TS_LEXICOGRAPHIC_WINDOW_EXCLUSION`).

A value that cannot be parsed returns `None`. It is NEVER given a fabricated
time and never silently treated as inside a requested window; callers state
the parse failure instead.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Optional

#: date, T-or-space, time, optional fraction of any precision (Windows writes
#: 100 ns ticks = 7 digits), optional Z or ±hh[:]mm.
_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?"
    r"(?:[.,](\d{1,9}))?\s*(?:(Z|z)|([+-])(\d{2}):?(\d{2}))?$")


@lru_cache(maxsize=200_000)
def parse_instant(value: Any) -> Optional[datetime]:
    """A stored timestamp → an aware UTC datetime, or None.

    A value with no zone designator is UTC by the source's own contract:
    Sysmon's field is named `UtcTime`, and the Windows connector records
    `TimeCreated SystemTime` in UTC. No local-time guess is ever made.
    """
    if isinstance(value, datetime):
        return (value if value.tzinfo
                else value.replace(tzinfo=timezone.utc)).astimezone(
                    timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    m = _TS_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mi, ss, frac, zulu, sign, oh, om = m.groups()
    micro = 0
    if frac:
        micro = int(frac[:6].ljust(6, "0"))          # truncate, never round up
    try:
        dt = datetime(int(y), int(mo), int(d), int(hh), int(mi),
                      int(ss or 0), micro, tzinfo=timezone.utc)
    except ValueError:
        return None
    if sign:
        off = timedelta(hours=int(oh), minutes=int(om))
        dt = dt - off if sign == "+" else dt + off
    return dt


def instant_ms(value: Any) -> Optional[int]:
    """UTC epoch milliseconds, or None when the value is not a timestamp."""
    dt = parse_instant(value)
    return None if dt is None else int(dt.timestamp() * 1000)


def rfc3339(value: Any) -> Optional[str]:
    """The SAME instant, written RFC 3339 UTC. No precision is invented.

    `2026-09-22 15:43:31.770` → `2026-09-22T15:43:31.770Z`
    Returns None when the value cannot be parsed, so a caller can preserve
    the source string verbatim rather than lose it.
    """
    dt = parse_instant(value)
    if dt is None:
        return None
    frac = ""
    if dt.microsecond:
        frac = (f".{dt.microsecond // 1000:03d}" if dt.microsecond % 1000 == 0
                else f".{dt.microsecond:06d}")
    return f"{dt:%Y-%m-%dT%H:%M:%S}{frac}Z"
