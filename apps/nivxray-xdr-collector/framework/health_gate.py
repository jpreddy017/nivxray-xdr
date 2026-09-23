"""G1-R3 · Delivery health gate (circuit breaker).

R1 stopped an unattributed 404 from destroying an event on its first attempt.
R2 made each failure self-explaining. Both are per-event corrections, and
neither stops the worker from draining the whole queue into a destination that
is simply not there: during the G1 outage the worker spent ~5h46m attempting
delivery against a backend that was not running.

With R1 alone, a long outage no longer destroys events instantly — it consumes
each event's bounded retry budget instead, and a queue of 125,452 rows would
still walk every one of them to `retries exhausted`. The retry budget exists to
absorb *per-event* problems; spending it on a *destination* problem is the same
category error that caused the original loss.

So health is tracked per destination, not per event:

    CLOSED      deliver normally
    SUSPECT     failures are accumulating but the threshold is not reached —
                delivery continues unchanged; this state exists so an operator
                can see trouble building before anything is paused
    OPEN        the destination is unavailable -> claim NOTHING, attempt
                NOTHING, consume NO retry budget, change NO row
    HALF_OPEN   cooldown elapsed -> allow exactly ONE probe row; success
                closes the gate, failure re-opens it with a longer, bounded
                cooldown

Only *destination-level* evidence moves the gate. An
``AUTHORITATIVE_TERMINAL`` refusal is the application answering correctly about
one event — that is a healthy destination and must never open the gate, or a
stream of bad events would stall delivery of good ones.

Safety properties this preserves by construction:
  * no event loss — while OPEN no row is claimed, so nothing can be stranded
    in DELIVERING;
  * no duplicate acknowledgement — only a real 2xx ever marks DELIVERED;
  * no bookmark corruption — bookmarks follow acknowledgement, and the gate
    never acknowledges;
  * R1/R2 are not bypassed — the probe goes through the ordinary delivery path
    and is classified and recorded exactly like any other attempt.
"""
from __future__ import annotations

import os
from typing import Optional

#: Consecutive destination-level failures before the gate opens.
DEFAULT_FAILURE_THRESHOLD = 5
#: First cooldown, doubled on each consecutive failed probe.
DEFAULT_COOLDOWN_SECONDS = 30.0
#: Bounded: the gate always returns to probing, it never gives up forever.
DEFAULT_MAX_COOLDOWN_SECONDS = 300.0


class GateState:
    CLOSED    = "CLOSED"
    SUSPECT   = "SUSPECT"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


class DeliveryHealthGate:
    """Destination health, decided only from destination-level evidence."""

    def __init__(self, *, failure_threshold: Optional[int] = None,
                 cooldown_seconds: Optional[float] = None,
                 max_cooldown_seconds: Optional[float] = None,
                 clock=None) -> None:
        self.failure_threshold = int(
            failure_threshold
            if failure_threshold is not None
            else _env_float("NIVX_DELIVERY_GATE_THRESHOLD",
                            DEFAULT_FAILURE_THRESHOLD))
        self.base_cooldown = (
            cooldown_seconds
            if cooldown_seconds is not None
            else _env_float("NIVX_DELIVERY_GATE_COOLDOWN_SECONDS",
                            DEFAULT_COOLDOWN_SECONDS))
        self.max_cooldown = (
            max_cooldown_seconds
            if max_cooldown_seconds is not None
            else _env_float("NIVX_DELIVERY_GATE_MAX_COOLDOWN_SECONDS",
                            DEFAULT_MAX_COOLDOWN_SECONDS))
        if self.max_cooldown < self.base_cooldown:
            self.max_cooldown = self.base_cooldown

        import time as _time
        self._now = clock or _time.monotonic
        self.state = GateState.CLOSED
        self.consecutive_failures = 0
        self.current_cooldown = self.base_cooldown
        self.opened_at: Optional[float] = None
        self.opened_count = 0
        self.probes = 0
        self.skipped_ticks = 0
        self.last_reason: Optional[str] = None
        self.last_transition_at: Optional[str] = None

    # ── decision ─────────────────────────────────────────────────────
    def allow_delivery(self) -> bool:
        """True when a drain may claim rows. Promotes OPEN -> HALF_OPEN once
        the cooldown has elapsed, so the gate always re-probes."""
        if self.state in (GateState.CLOSED, GateState.SUSPECT):
            return True
        if self.state == GateState.HALF_OPEN:
            return True
        if self.opened_at is not None and \
                (self._now() - self.opened_at) >= self.current_cooldown:
            self._transition(GateState.HALF_OPEN,
                             "cooldown elapsed; probing the destination")
            return True
        self.skipped_ticks += 1
        return False

    def probe_limit(self) -> Optional[int]:
        """Rows this drain may claim: exactly one while probing."""
        return 1 if self.state == GateState.HALF_OPEN else None

    # ── evidence ─────────────────────────────────────────────────────
    def record_success(self) -> None:
        self.consecutive_failures = 0
        self.current_cooldown = self.base_cooldown
        if self.state != GateState.CLOSED:
            self._transition(GateState.CLOSED,
                             "destination acknowledged a delivery")
        self.opened_at = None

    def record_destination_failure(self, reason: str) -> None:
        """A failure that says something about the DESTINATION, not an event."""
        if self.state == GateState.HALF_OPEN:
            # The probe failed: re-open with a longer, still bounded cooldown.
            self.current_cooldown = min(self.current_cooldown * 2,
                                        self.max_cooldown)
            self._open(reason)
            return
        self.consecutive_failures += 1
        if self.state in (GateState.CLOSED, GateState.SUSPECT) and \
                self.consecutive_failures >= self.failure_threshold:
            self._open(reason)
        elif self.state == GateState.CLOSED:
            self._transition(
                GateState.SUSPECT,
                f"{reason} ({self.consecutive_failures}/"
                f"{self.failure_threshold} before pausing)")
        else:
            self.last_reason = reason

    def record_event_refusal(self, reason: str) -> None:
        """An authoritative per-event refusal. The destination is healthy, so
        this resets the failure run rather than moving the gate."""
        self.consecutive_failures = 0
        self.last_reason = reason
        if self.state != GateState.CLOSED:
            self._transition(GateState.CLOSED,
                             "destination answered authoritatively")
        self.opened_at = None

    def note_probe(self) -> None:
        self.probes += 1

    # ── internals ────────────────────────────────────────────────────
    def _open(self, reason: str) -> None:
        self.opened_at = self._now()
        self.opened_count += 1
        self._transition(GateState.OPEN, reason)

    def _transition(self, state: str, reason: str) -> None:
        import datetime as _dt
        self.state = state
        self.last_reason = reason
        self.last_transition_at = _dt.datetime.now(_dt.timezone.utc).isoformat()

    def seconds_until_probe(self) -> Optional[float]:
        if self.state != GateState.OPEN or self.opened_at is None:
            return None
        return max(0.0, self.current_cooldown - (self._now() - self.opened_at))

    def status(self) -> dict:
        return {
            "state":                 self.state,
            "consecutive_failures":  self.consecutive_failures,
            "failure_threshold":     self.failure_threshold,
            "cooldown_seconds":      self.current_cooldown,
            "max_cooldown_seconds":  self.max_cooldown,
            "seconds_until_probe":   self.seconds_until_probe(),
            "opened_count":          self.opened_count,
            "probes":                self.probes,
            "skipped_ticks":         self.skipped_ticks,
            "last_reason":           self.last_reason,
            "last_transition_at":    self.last_transition_at,
        }
