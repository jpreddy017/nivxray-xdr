"""D12 · The one place `event_time` and `activity_occurred_at` are decided.

Four bases exist, and they are four different evidentiary statements:

    ACTIVITY_TIME
        the source format establishes that this value IS when the activity
        occurred.
    OBSERVATION_TIME
        the source format establishes that this value is when something
        OBSERVED the activity — a log-record write, an ETW emission. Close
        to the activity is not the activity.
    SUPPLIED_TIMESTAMP_UNVERIFIED
        a value was supplied by upstream telemetry, and its authority as
        activity time has not been established.
    INGEST_TIME_SUBSTITUTED
        NivX deliberately used its own clock for `event_time` compatibility
        because nothing from the source was usable.

`event_time` remains a compatibility field. It is not the universal source
of temporal truth, and a consumer that wants causal ordering must read the
evidence-backed boundaries in `provenance.timestamps` instead.

THE INVARIANT THIS MODULE EXISTS TO MAKE UNBREAKABLE

    activity_occurred_at is AVAILABLE only when basis == ACTIVITY_TIME.

A DSM cannot opt out of it, because a DSM cannot produce the two values
separately: one call returns both. Nor can this module guess — every caller
must declare, per candidate field, whether its own wire format PROVES the
field is activity time, and must state why in the cases where it does not.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from services import provenance_timestamps as pts
from services.ingest_provenance import validate

ACTIVITY_TIME = "ACTIVITY_TIME"
OBSERVATION_TIME = "OBSERVATION_TIME"
SUPPLIED_TIMESTAMP_UNVERIFIED = "SUPPLIED_TIMESTAMP_UNVERIFIED"
INGEST_TIME_SUBSTITUTED = "INGEST_TIME_SUBSTITUTED"

#: Only this basis may be accompanied by a measured activity time.
BASES = (ACTIVITY_TIME, OBSERVATION_TIME, SUPPLIED_TIMESTAMP_UNVERIFIED,
         INGEST_TIME_SUBSTITUTED)

ISO_8601 = "ISO_8601"
UNPARSEABLE_FORMAT = "UNPARSEABLE_FORMAT"

#: (value, source) — `source` names the exact wire field, never a guess.
Candidate = tuple[Any, str]

_NO_OFFSET = ("the supplied value carries no UTC offset; it is recorded "
              "verbatim and its offset is UNKNOWN")


def _split(cands: Iterable[Candidate]
           ) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    """Usable candidates and delivered-but-unreadable ones, order preserved."""
    good: list[tuple[str, str, str]] = []
    bad: list[tuple[str, str, str]] = []
    for value, source in cands or ():
        v, offset, err = validate(value)
        if v:
            good.append((v, source, offset))
        elif value is not None and str(value).strip():
            bad.append((str(value).strip(), source, err or "unreadable"))
    return good, bad


def _measured(entry: tuple[str, str, str]) -> dict[str, Any]:
    value, source, offset = entry
    return pts.stamp(value, source=source,
                     reason=(None if offset == "OFFSET_PRESENT"
                             else _NO_OFFSET))


def _unreadable(entry: tuple[str, str, str]) -> dict[str, Any]:
    _, source, err = entry
    return pts.stamp(status=pts.MISSING, source=source, reason=err)


@dataclass(frozen=True)
class Resolution:
    event_time: str
    basis: str
    source: str
    substituted: bool
    format_state: str
    activity: dict[str, Any]
    observation: dict[str, Any]

    def verify(self) -> "Resolution":
        """The invariant, checked on the value object itself, so it holds
        for anything that constructs a Resolution — not only `resolve()`."""
        if self.basis not in BASES:
            raise AssertionError(f"unknown event_time basis: {self.basis!r}")
        if self.basis != ACTIVITY_TIME \
                and self.activity.get("status") == pts.AVAILABLE:
            raise AssertionError(
                f"invariant violated: basis={self.basis} with a measured "
                "activity_occurred_at — only ACTIVITY_TIME may carry one")
        if self.basis == ACTIVITY_TIME:
            if self.activity.get("status") != pts.AVAILABLE:
                raise AssertionError(
                    "invariant violated: basis=ACTIVITY_TIME without a "
                    "measured activity_occurred_at")
            if self.activity.get("value") != self.event_time:
                raise AssertionError(
                    "invariant violated: ACTIVITY_TIME event_time does not "
                    "equal the measured activity_occurred_at")
        if self.substituted is (self.basis == ACTIVITY_TIME):
            raise AssertionError(
                "invariant violated: event_time_substituted must be False "
                "for ACTIVITY_TIME and True for every other basis")
        return self

    def declarations(self) -> dict[str, Any]:
        """The four fields that make the substitution visible to a consumer
        reading `additional_fields` rather than the provenance block."""
        return {"event_time_basis": self.basis,
                "event_time_source": self.source,
                "event_time_substituted": self.substituted,
                "event_time_format_state": self.format_state}

    def stamps(self) -> dict[str, dict[str, Any]]:
        return {"activity_occurred_at": self.activity,
                "sensor_observed_at": self.observation}


def resolve(*,
            activity: Sequence[Candidate] = (),
            observation: Sequence[Candidate] = (),
            supplied: Sequence[Candidate] = (),
            clock: str,
            clock_source: str,
            activity_absent_reason: str,
            observation_absent_reason: str) -> Resolution:
    """Decide `event_time`, its basis, and both source-side boundaries.

    `activity` — fields this DSM's format PROVES are activity occurrence.
    `observation` — fields it proves are an observation instant.
    `supplied` — fields that carry a time whose semantics are not established.

    The two absent-reasons are mandatory: a boundary that goes unfilled has
    to say why, so "we did not look" can never be mistaken for "the source
    did not say".
    """
    a_ok, a_bad = _split(activity)
    o_ok, o_bad = _split(observation)
    s_ok, s_bad = _split(supplied)

    # ── the boundaries, decided by the evidence alone ────────────────
    if a_ok:
        act = _measured(a_ok[0])
    elif a_bad:
        act = _unreadable(a_bad[0])
    else:
        act = pts.stamp(status=pts.NOT_OBSERVED,
                        reason=activity_absent_reason)

    if o_ok:
        obs = _measured(o_ok[0])
    elif o_bad:
        obs = _unreadable(o_bad[0])
    else:
        obs = pts.stamp(status=pts.NOT_OBSERVED,
                        reason=observation_absent_reason)

    # ── then the compatibility field, which follows them ─────────────
    if a_ok:
        value, source, _ = a_ok[0]
        basis, substituted = ACTIVITY_TIME, False
    elif o_ok:
        value, source, _ = o_ok[0]
        basis, substituted = OBSERVATION_TIME, True
    elif s_ok:
        value, source, _ = s_ok[0]
        basis, substituted = SUPPLIED_TIMESTAMP_UNVERIFIED, True
    elif a_bad or o_bad or s_bad:
        # A value WAS supplied and we cannot read it. Kept verbatim for
        # compatibility with whatever already consumes it, and demoted:
        # an unreadable value can order nothing.
        value, source, _ = (a_bad or o_bad or s_bad)[0]
        basis, substituted = SUPPLIED_TIMESTAMP_UNVERIFIED, True
    else:
        value, source = clock, clock_source
        basis, substituted = INGEST_TIME_SUBSTITUTED, True

    parsed, _, _ = validate(value)
    fmt = ISO_8601 if parsed else UNPARSEABLE_FORMAT

    return Resolution(event_time=str(value), basis=basis, source=source,
                      substituted=substituted, format_state=fmt,
                      activity=act, observation=obs).verify()


def apply(canonical: dict[str, Any], res: Resolution) -> None:
    """Seed the eight boundaries with what this DSM knows, and publish the
    declarations. The transport boundaries stay MISSING for the ingest
    handler to fill; the pipeline stamps its own."""
    prov = canonical.setdefault("provenance", {})
    prov["timestamps"] = pts.block(**res.stamps())
    extra = canonical.setdefault("additional_fields", {})
    if isinstance(extra, dict):
        extra.update(res.declarations())
