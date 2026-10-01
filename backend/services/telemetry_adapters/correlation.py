"""
Cross-Lane Correlation Joiner — Phase 2 operationalisation.

Joins `CanonicalEvent`s across `source_kind` lanes (endpoint,
identity, cloud, network, email) into `CrossLaneCorrelation`
groups.

Owner rules (strictly enforced):

  · Correlation reasons must be explicit — `same_actor`,
    `same_ip`, `same_target`, `chain:identity→cloud`, etc.
    Timestamp proximity ALONE never counts as correlation.
  · Governed evidence only: every group cites the canonical_ids
    that support it.  We NEVER invent an edge without a supporting
    canonical event on both sides.
  · No ATT&CK attribution here.  A correlation says "these events
    are related"; the AttackTechniqueEvidence SSOT still decides
    whether a technique is OBSERVED.
  · Verdict semantics remain untouched.  The joiner emits
    signals; the existing Verdict Engine decides what to do with
    them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .framework import CanonicalEvent, SourceKind


# --------------------------------------------------------------------
@dataclass(frozen=True)
class CrossLaneCorrelation:
    """One correlation group.  Downstream (Verdict / IUE / Cognis)
    receives ONLY this shape — no vendor field ever leaks."""
    key:                str
    reasons:            tuple[str, ...]           # ordered, deterministic
    canonical_ids:      tuple[str, ...]
    lanes:              tuple[str, ...]           # SourceKind values
    actor_id:           str | None
    first_seen:         str | None
    last_seen:          str | None
    confidence:         float                     # 0..1 — deterministic


# --------------------------------------------------------------------
def _actor_key(ev: CanonicalEvent) -> str | None:
    return (ev.actor or {}).get("id") \
              or (ev.actor or {}).get("email")


def _ip(ev: CanonicalEvent) -> str | None:
    return (ev.context or {}).get("ip")


def _parse_time(iso: str | None) -> datetime | None:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None


def _in_window(a: CanonicalEvent, b: CanonicalEvent,
                          window: timedelta) -> bool:
    ta = _parse_time((a.provenance or object()).__dict__.get(
                        "source_event_time") if a.provenance else None)
    tb = _parse_time((b.provenance or object()).__dict__.get(
                        "source_event_time") if b.provenance else None)
    if ta is None or tb is None:
        return True                       # honest fallback: unknown time = don't reject
    return abs(ta - tb) <= window


def correlate(
    events: Iterable[CanonicalEvent],
    *,
    window_minutes: int = 30,
) -> list[CrossLaneCorrelation]:
    """Group events across lanes.  A group is emitted only when it
    contains events from AT LEAST TWO lanes AND at least one of:
      · shared actor (id or email)
      · shared source IP
    plus temporal window compliance.

    Groups never coalesce solely on temporal proximity — that
    would silently promote unrelated events."""
    evs = list(events)
    if not evs:
        return []

    window = timedelta(minutes=window_minutes)

    # Bucket by actor.
    by_actor: dict[str, list[CanonicalEvent]] = {}
    by_ip:    dict[str, list[CanonicalEvent]] = {}
    for e in evs:
        a = _actor_key(e)
        if a:
            by_actor.setdefault(a, []).append(e)
        ip = _ip(e)
        if ip:
            by_ip.setdefault(ip, []).append(e)

    groups: dict[str, dict[str, Any]] = {}

    def _register(key, reason, bucket):
        lanes = {e.source_kind.value for e in bucket}
        if len(lanes) < 2:
            return
        # Only keep events that pass the temporal window against
        # at least one other lane peer.
        selected: list[CanonicalEvent] = []
        for e in bucket:
            peers = [x for x in bucket
                              if x.source_kind is not e.source_kind]
            if any(_in_window(e, p, window) for p in peers):
                selected.append(e)
        if not selected or len({e.source_kind for e in selected}) < 2:
            return
        cids = tuple(e.canonical_id for e in selected)
        lanes_t = tuple(sorted({e.source_kind.value for e in selected}))
        # First / last seen from source_event_time when available.
        times = sorted(
            [t for t in (
                _parse_time(getattr(e.provenance, "source_event_time", None))
                for e in selected) if t is not None])
        first_seen = times[0].isoformat() if times else None
        last_seen  = times[-1].isoformat() if times else None
        actor_id = None
        if reason == "same_actor":
            actor_id = key
        # Deterministic confidence: 0.5 baseline + 0.15 per extra
        # lane covered + 0.05 per extra corroborating event, cap 0.95.
        confidence = min(
            0.95,
            0.5 + 0.15 * (len(lanes_t) - 1) + 0.05 * max(0, len(cids) - 2),
        )
        g = groups.setdefault(f"{reason}:{key}", {
            "key":     f"{reason}:{key}",
            "reasons": [],
            "cids":    set(),
            "lanes":   set(),
            "actor":   actor_id,
            "first":   first_seen,
            "last":    last_seen,
            "conf":    0.0,
        })
        if reason not in g["reasons"]:
            g["reasons"].append(reason)
        g["cids"].update(cids)
        g["lanes"].update(lanes_t)
        g["actor"] = g["actor"] or actor_id
        # Merge times.
        if first_seen and (g["first"] is None or first_seen < g["first"]):
            g["first"] = first_seen
        if last_seen and (g["last"] is None or last_seen > g["last"]):
            g["last"] = last_seen
        g["conf"] = max(g["conf"], confidence)

    for actor, bucket in by_actor.items():
        _register(actor, "same_actor", bucket)
    for ip, bucket in by_ip.items():
        _register(ip, "same_ip", bucket)

    return [
        CrossLaneCorrelation(
            key           = g["key"],
            reasons       = tuple(sorted(g["reasons"])),
            canonical_ids = tuple(sorted(g["cids"])),
            lanes         = tuple(sorted(g["lanes"])),
            actor_id      = g["actor"],
            first_seen    = g["first"],
            last_seen     = g["last"],
            confidence    = round(g["conf"], 3),
        )
        for g in sorted(groups.values(), key=lambda x: x["key"])
    ]
