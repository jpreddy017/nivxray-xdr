"""D11 · Ingest-path provenance — the collector-delivered boundaries.

Eight boundaries exist and they are NOT interchangeable:

    activity_occurred_at   when the thing itself happened          (DSM owns)
    sensor_observed_at     when the source first saw it
    collector_received_at  when the collector took delivery
    nivx_received_at       when NivX's HTTP boundary accepted it
    parsed_at              when our parser returned        (pipeline owns)
    normalized_at          when normalization finished     (pipeline owns)
    rule_evaluated_at      when detection finished         (pipeline owns)
    verdict_at             when the verdict was authoritative (pipeline owns)

This module owns the three transport boundaries in the middle, plus the
non-timestamp question "who says so": which collector delivered it, which
tenant owns it, and which raw row proves it.

Nothing here rewrites a supplied value, infers an offset, or lets one stage
stand in for another. A boundary that was not observed stays NOT_OBSERVED.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from services import provenance_timestamps as pts

#: Which shape of delivery produced this event. It decides whether a
#: collector boundary exists at all — on a direct sensor path it does not,
#: and NOT_APPLICABLE is the truthful answer rather than NOT_OBSERVED.
COLLECTOR_DELIVERED = "COLLECTOR_DELIVERED"
DIRECT_SENSOR = "DIRECT_SENSOR"

OFFSET_PRESENT = "OFFSET_PRESENT"
OFFSET_ABSENT = "OFFSET_ABSENT"

_NO_OFFSET_NOTE = (
    "the supplied value carries no UTC offset; it is recorded verbatim and "
    "its offset is UNKNOWN — no offset was assumed on its behalf")


def validate(value: Any) -> tuple[str | None, str | None, str | None]:
    """``(verbatim_value, offset_state, error)``.

    The value is returned exactly as supplied when it parses. We deliberately
    do not normalise it to UTC: re-rendering a collector's timestamp would
    make our arithmetic look like their measurement.
    """
    if value is None or not str(value).strip():
        return None, None, None
    raw = str(value).strip()
    probe = (raw[:-1] + "+00:00") if raw.endswith(("Z", "z")) else raw
    try:
        dt = datetime.fromisoformat(probe)
    except ValueError:
        return None, None, (f"supplied value is not a parseable ISO-8601 "
                            f"timestamp: {raw[:80]!r}")
    return raw, (OFFSET_PRESENT if dt.tzinfo is not None
                 else OFFSET_ABSENT), None


def pick(candidates: list[tuple[Any, str]], *, absent_reason: str
         ) -> dict[str, Any]:
    """First parseable candidate wins, in declared precedence order.

    A candidate that was supplied but unusable is not silently skipped past
    into "never observed" — the boundary becomes MISSING and says why, so a
    broken collector looks broken instead of looking quiet.
    """
    errors: list[tuple[str, str]] = []
    for value, source in candidates:
        v, offset, err = validate(value)
        if v:
            return pts.stamp(v, source=source,
                             reason=(None if offset == OFFSET_PRESENT
                                     else _NO_OFFSET_NOTE))
        if err:
            errors.append((source, err))
    if errors:
        # A delivered-but-unreadable value is a gap to fix, and it names the
        # field it arrived in — that is what makes a broken collector
        # findable instead of merely quiet.
        return pts.stamp(status=pts.MISSING, source=errors[0][0],
                         reason="; ".join(f"{s}: {e}" for s, e in errors))
    return pts.stamp(status=pts.NOT_OBSERVED, reason=absent_reason)


def transport_stamps(envelope: dict[str, Any], *, nivx_received_at: str,
                     path_kind: str = COLLECTOR_DELIVERED
                     ) -> dict[str, dict[str, Any]]:
    """The three boundaries the transport can honestly speak for."""
    sensor = pick(
        [(envelope.get("source_timestamp"),
          "collector:envelope.source_timestamp")],
        absent_reason=("the collector envelope carried no source timestamp; "
                       "the source's own observation instant was never "
                       "delivered to us"))

    if path_kind == DIRECT_SENSOR:
        collector = pts.stamp(
            status=pts.NOT_APPLICABLE,
            reason="no collector boundary exists on the direct sensor path")
    else:
        collector = pick(
            [(envelope.get("received_at"), "collector:envelope.received_at"),
             (envelope.get("collection_timestamp"),
              "collector:envelope.collection_timestamp")],
            absent_reason=("the collector envelope carried neither "
                           "received_at nor collection_timestamp; when the "
                           "collector took delivery was never reported"))

    return {
        "sensor_observed_at": sensor,
        "collector_received_at": collector,
        "nivx_received_at": pts.stamp(
            nivx_received_at,
            source="ingest:http receipt POST /api/xdr/ingest/telemetry"),
    }


def _rank(entry: dict[str, Any]) -> int:
    """How much a stamp actually tells us.

    A real measurement outranks everything. A delivered-but-unreadable value
    (MISSING *with* the field it arrived in) outranks "never observed",
    because it is a defect someone must fix. The bare MISSING that `block()`
    seeds says nothing at all and is always replaceable.
    """
    status = entry.get("status")
    if status == pts.AVAILABLE:
        return 3
    if status == pts.MISSING:
        return 2 if entry.get("source") else 0
    return 1


def apply(canonical: dict[str, Any],
          stamps: dict[str, dict[str, Any]]) -> None:
    """Record the stamps, only ever improving a boundary.

    A producer that knows more replaces one that knows less; a producer that
    knows less can never demote what is already recorded.
    """
    existing = ((canonical.get("provenance") or {}).get("timestamps") or {})
    for name, entry in stamps.items():
        current = existing.get(name)
        if current and _rank(entry) <= _rank(current):
            continue
        pts.put(canonical, name, entry)


def identity_block(envelope: dict[str, Any], *, path_kind: str,
                   tenant_id: str, tenant_id_source: str,
                   collector_id: str | None,
                   raw_ref: dict[str, Any] | None) -> dict[str, Any]:
    """Who delivered this, who owns it, and what row proves it.

    Every claim names the field it came from. The collector-supplied source
    label is recorded as a *claim*, not as proven host identity — the
    collector is only as trustworthy as its own credential.
    """
    return {
        "path_kind": path_kind,
        "tenant_id": tenant_id,
        "tenant_id_source": tenant_id_source,
        "collector_id": collector_id or None,
        "collector_id_source": (
            "envelope.collector_id, verified against xdr_collectors.tenant_id"
            if collector_id else "NOT_OBSERVED"),
        "source_label": envelope.get("source") or None,
        "source_label_source": (
            "collector:envelope.source — a collector CLAIM of origin, not "
            "proven host identity"),
        "connector_id": envelope.get("connector_id") or None,
        "data_source_id": envelope.get("data_source_id") or None,
        "collection_method": envelope.get("collection_method") or None,
        "collector_parser_version": envelope.get("parser_version") or None,
        "collector_reported_event_type": envelope.get("event_type") or None,
        "raw_envelope_ref": raw_ref or {
            "state": "NOT_OBSERVED",
            "reason": "no raw row reference was carried into reasoning"},
    }
