"""Logical-event aggregator (STEP 3 §2.5 · §3.4 · STEP 4 §1.2).

Contract (locked):
- Groups only records that share every canonical grouping key exactly.
- Timestamps compared truncated to 1-second buckets.
- Preserves ``record_refs`` (every collapsed record_id), ``count``,
  ``first_seen``, ``last_seen``, ``variability`` (distinct values).
- Never performs cross-record semantic reunification — that is ICE's job.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Mapping

from canonical.ssot.models import Provenance
from ._prov import aggregate_prov


# Grouping key (STEP 3 §3.4).  Aggregation happens ONLY when every
# listed field either matches exactly or is absent in every record
# in the group.  Missing-in-some-but-present-in-others → NOT aggregated.
GROUPING_KEYS = (
    "canonical.tenant.id",
    "canonical.event.timestamp",       # bucketed to 1s
    "canonical.event.action",
    "canonical.source.ip",
    "canonical.destination.ip",
    "canonical.destination.port",
    "canonical.process.name",
    "canonical.process.command_line",
    "canonical.file.hash.sha256",
)

_TIMESTAMP_KEY = "canonical.event.timestamp"


@dataclass(frozen=True)
class LogicalEvent:
    event_id: str
    tenant_id: str
    input_id: str
    source_file_id: str
    record_refs: List[str]                 # every collapsed record_id
    count: int
    first_seen: str
    last_seen: str
    canonical_fields: Mapping[str, Any]    # shared grouping fields
    variability: Mapping[str, List[Any]]   # canonical_key → distinct values
    provenance: Provenance = field(default_factory=aggregate_prov)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["canonical_fields"] = dict(self.canonical_fields)
        d["variability"] = {k: list(v) for k, v in self.variability.items()}
        return d


def _bucket_timestamp(ts: Any) -> str:
    """Truncate an ISO-ish timestamp to 1-second precision.  Non-string
    or unparseable inputs are used verbatim (stringified)."""
    if not isinstance(ts, str):
        return str(ts)
    # Cheapest correct truncation: keep everything up to (but not
    # including) the fractional-seconds dot, or the timezone suffix,
    # whichever comes first after the seconds field.
    if "T" not in ts or len(ts) < 19:
        return ts
    # "YYYY-MM-DDTHH:MM:SS" is exactly 19 chars.
    seconds_field = ts[:19]
    # preserve timezone marker if present after the fractional dot
    tail = ts[19:]
    tz_suffix = ""
    if tail:
        # look for +/-/Z after any fractional digits
        i = 0
        if tail[0] == ".":
            i = 1
            while i < len(tail) and tail[i].isdigit():
                i += 1
        tz_suffix = tail[i:]
    return seconds_field + tz_suffix


def _grouping_signature(canonical: Mapping[str, Any]) -> str:
    """Deterministic string derived from the grouping fields."""
    parts: List[str] = []
    for k in GROUPING_KEYS:
        if k not in canonical:
            parts.append(f"{k}=∅")
            continue
        v = canonical[k]
        if k == _TIMESTAMP_KEY:
            v = _bucket_timestamp(v)
        parts.append(f"{k}={v}")
    return "|".join(parts)


def _event_id(sig: str, tenant_id: str, source_file_id: str) -> str:
    h = hashlib.sha256(f"{tenant_id}::{source_file_id}::{sig}".encode())
    return h.hexdigest()[:24]


def aggregate(records: Iterable) -> List[LogicalEvent]:
    """Collapse an iterable of NormalizedRecord into LogicalEvents.

    Records missing every grouping field are still emitted — each such
    record becomes its own LogicalEvent with count=1.  This preserves
    the record boundary invariant (STEP 4 §5 invariant #5).
    """
    groups: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []

    for rec in records:
        canonical = dict(rec.canonical_fields or {})
        sig = _grouping_signature(canonical)
        if sig not in groups:
            order.append(sig)
            groups[sig] = {
                "record_refs": [],
                "count": 0,
                "first_seen": None,
                "last_seen": None,
                "canonical_fields": {},
                "variability": {},
                "tenant_id": rec.tenant_id,
                "source_file_id": rec.source_file_id,
                "input_id": rec.input_id,
                "upstream_prov": rec.provenance,   # first record's lineage
            }
        g = groups[sig]
        g["record_refs"].append(rec.record_id)
        g["count"] += 1

        # first / last seen tracking (raw, unbucketed for observability)
        ts = canonical.get(_TIMESTAMP_KEY)
        if ts is not None:
            ts_str = str(ts)
            if g["first_seen"] is None or ts_str < g["first_seen"]:
                g["first_seen"] = ts_str
            if g["last_seen"] is None or ts_str > g["last_seen"]:
                g["last_seen"] = ts_str

        # variability: track distinct values per canonical field
        for k, v in canonical.items():
            if k in GROUPING_KEYS and k != _TIMESTAMP_KEY:
                if k not in g["canonical_fields"]:
                    g["canonical_fields"][k] = v
                continue
            g["variability"].setdefault(k, [])
            if v not in g["variability"][k]:
                g["variability"][k].append(v)

        # pin the bucketed timestamp representative on canonical_fields
        if ts is not None and _TIMESTAMP_KEY not in g["canonical_fields"]:
            g["canonical_fields"][_TIMESTAMP_KEY] = _bucket_timestamp(ts)

    events: List[LogicalEvent] = []
    for sig in order:
        g = groups[sig]
        ev_id = _event_id(sig, g["tenant_id"], g["source_file_id"])
        events.append(LogicalEvent(
            event_id=ev_id,
            tenant_id=g["tenant_id"],
            input_id=g["input_id"],
            source_file_id=g["source_file_id"],
            record_refs=g["record_refs"],
            count=g["count"],
            first_seen=g["first_seen"] or "",
            last_seen=g["last_seen"] or "",
            canonical_fields=g["canonical_fields"],
            variability=g["variability"],
            provenance=aggregate_prov(upstream=g["upstream_prov"],
                                        own_id=ev_id),
        ))
    return events
