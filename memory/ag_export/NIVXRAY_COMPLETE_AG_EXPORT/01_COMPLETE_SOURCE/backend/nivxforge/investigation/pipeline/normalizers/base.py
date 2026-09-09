"""Common helpers for CEMv1 normalizers."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from nivxforge.investigation.cem import (
    ContainmentState,
    Provenance,
    SeverityLevel,
)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _try_parse_dt(v: Any) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        try:
            # Cisco/Defender use unix seconds or ms.
            if v > 10**12:
                return datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
            return datetime.fromtimestamp(float(v), tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return None
    if isinstance(v, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        ):
            try:
                dt = datetime.strptime(v, fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        # ISO fallback
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def make_provenance(source: str, vendor: Optional[str] = None,
                    timestamp: Optional[datetime] = None,
                    confidence: float = 1.0) -> Provenance:
    return Provenance(
        source=source,
        vendor=vendor,
        timestamp=timestamp or now_utc(),
        confidence=confidence,
    )


def coerce_severity(v: Any) -> SeverityLevel:
    if v is None:
        return SeverityLevel.informational
    if isinstance(v, SeverityLevel):
        return v
    s = str(v).strip().lower()
    if s in ("critical", "sev1", "1", "very_high"):
        return SeverityLevel.critical
    if s in ("high", "sev2", "2"):
        return SeverityLevel.high
    if s in ("medium", "med", "sev3", "3"):
        return SeverityLevel.medium
    if s in ("low", "sev4", "4"):
        return SeverityLevel.low
    return SeverityLevel.informational


def coerce_containment(v: Any) -> ContainmentState:
    if v is None:
        return ContainmentState.none
    if isinstance(v, ContainmentState):
        return v
    s = str(v).strip().lower()
    if s in ("quarantined", "quarantine"):
        return ContainmentState.quarantined
    if s in ("blocked", "block"):
        return ContainmentState.blocked
    if s in ("isolated", "isolate", "contained"):
        return ContainmentState.isolated
    if s in ("remediated", "remediate", "resolved"):
        return ContainmentState.remediated
    if s in ("prevented", "prevent", "denied"):
        return ContainmentState.prevented
    return ContainmentState.none


__all__ = [
    "make_provenance",
    "coerce_severity",
    "coerce_containment",
    "_try_parse_dt",
    "now_utc",
]
