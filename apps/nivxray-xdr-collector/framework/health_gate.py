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

G1-R3.1 · the gate is DURABLE
-----------------------------
An in-memory gate forgets the outage every time the service restarts. A
collector service that restarts (or crash-loops) would then rediscover a
known-dead destination from CLOSED each time and spend another full threshold
of real event attempts proving what it already knew — the same retry-budget
burn R3 exists to prevent, reintroduced through the process lifecycle.

The minimum authoritative state therefore lives in the SAME durable store as
the outbox rows (table ``delivery_health_gate``), because "what is queued" and
"is the destination reachable" belong to one operational domain and must not be
able to diverge:

  * OPEN survives restart, and so does its cooldown DEADLINE — which is
    wall-clock, because a monotonic clock is meaningless across processes;
  * the consecutive-failure run survives, so a crash-loop cannot reset a
    building outage back to zero;
  * a restart while OPEN generates NO delivery traffic — the gate is restored
    OPEN with the REMAINING cooldown;
  * a restart while HALF_OPEN resumes as OPEN, probe-eligible immediately, so
    exactly one bounded probe is permitted rather than a burst;
  * persisted state that cannot be read or does not validate fails SAFE and
    VISIBLE: the gate starts OPEN with the base cooldown and reports
    ``state_load_error``, so the fault is never silent and never turns into
    unthrottled traffic;
  * nothing secret is persisted — reasons are bounded and credential-scrubbed;
  * no row status, attempt count, bookmark or acknowledgement is involved.

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
import re
from typing import Any, Dict, Optional

#: Consecutive destination-level failures before the gate opens.
DEFAULT_FAILURE_THRESHOLD = 5
#: First cooldown, doubled on each consecutive failed probe.
DEFAULT_COOLDOWN_SECONDS = 30.0
#: Bounded: the gate always returns to probing, it never gives up forever.
DEFAULT_MAX_COOLDOWN_SECONDS = 300.0

#: R3.1 · persisted-state contract version. A row written by a different
#: version is not guessed at — it fails safe like any other unreadable state.
GATE_STATE_VERSION = 1
#: One collector delivers to one authoritative ingest; the key exists so the
#: contract does not have to change when that stops being true.
DEFAULT_DESTINATION_KEY = "nivx-ingest"

#: Bound on a persisted reason, and the patterns scrubbed out of it. The
#: reason comes from a delivery failure, which is operator text — it must
#: never become a place a credential can come to rest.
_REASON_MAX = 300
_SECRET_PATTERNS = (
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-\._~\+/=]+"),
    re.compile(r"(?i)\b(token|api[-_]?key|secret|password|authorization)\b"
               r"\s*[:=]\s*\S+"),
)


class GateState:
    CLOSED    = "CLOSED"
    SUSPECT   = "SUSPECT"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    ALL = (CLOSED, SUSPECT, OPEN, HALF_OPEN)


class GateStateUnreadable(Exception):
    """Persisted gate state exists and cannot be trusted."""


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def scrub_reason(reason: Any) -> Optional[str]:
    """Bounded, credential-free text safe to write to disk."""
    if reason is None:
        return None
    text = str(reason)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text[:_REASON_MAX]


def _require_int(snapshot: Dict[str, Any], key: str) -> int:
    value = snapshot.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GateStateUnreadable(f"{key} is not a number: {value!r}")
    ivalue = int(value)
    if ivalue < 0:
        raise GateStateUnreadable(f"{key} is negative: {value!r}")
    return ivalue


def validate_snapshot(snapshot: Any) -> Dict[str, Any]:
    """The persisted row, or ``GateStateUnreadable``. No field is defaulted:
    a partially readable outage is not a readable one."""
    if not isinstance(snapshot, dict):
        raise GateStateUnreadable(
            f"persisted state is not a record: {type(snapshot).__name__}")
    version = snapshot.get("state_version")
    if version != GATE_STATE_VERSION:
        raise GateStateUnreadable(
            f"persisted state_version {version!r} is not "
            f"{GATE_STATE_VERSION}")
    state = snapshot.get("state")
    if state not in GateState.ALL:
        raise GateStateUnreadable(f"unknown gate state: {state!r}")
    cooldown = snapshot.get("cooldown_seconds")
    if isinstance(cooldown, bool) or not isinstance(cooldown, (int, float)) \
            or cooldown <= 0:
        raise GateStateUnreadable(f"cooldown_seconds is invalid: {cooldown!r}")
    deadline = snapshot.get("cooldown_until_epoch")
    if state == GateState.OPEN:
        if isinstance(deadline, bool) or not isinstance(deadline,
                                                        (int, float)):
            raise GateStateUnreadable(
                "state is OPEN without a cooldown deadline: "
                f"{deadline!r}")
    return {
        "state":                state,
        "consecutive_failures": _require_int(snapshot,
                                             "consecutive_failures"),
        "cooldown_seconds":     float(cooldown),
        "cooldown_until_epoch": (float(deadline)
                                 if isinstance(deadline, (int, float))
                                 and not isinstance(deadline, bool)
                                 else None),
        "opened_count":         _require_int(snapshot, "opened_count"),
        "probes":               _require_int(snapshot, "probes"),
        "last_reason":          (None if snapshot.get("last_reason") is None
                                 else str(snapshot["last_reason"])),
        "last_transition_at":   (None
                                 if snapshot.get("last_transition_at") is None
                                 else str(snapshot["last_transition_at"])),
    }


class DeliveryHealthGate:
    """Destination health, decided only from destination-level evidence."""

    def __init__(self, *, failure_threshold: Optional[int] = None,
                 cooldown_seconds: Optional[float] = None,
                 max_cooldown_seconds: Optional[float] = None,
                 clock=None,
                 store: Any = None,
                 destination_key: str = DEFAULT_DESTINATION_KEY,
                 wall_clock=None) -> None:
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
        #: R3.1 · a cooldown deadline that must outlive the process cannot be
        #: monotonic. Wall clock is used for the persisted deadline ONLY.
        self._wall = wall_clock or _time.time
        self._store = store
        self._key = destination_key

        self.state = GateState.CLOSED
        self.consecutive_failures = 0
        self.current_cooldown = self.base_cooldown
        self.opened_at: Optional[float] = None
        self.opened_count = 0
        self.probes = 0
        self.skipped_ticks = 0
        self.last_reason: Optional[str] = None
        self.last_transition_at: Optional[str] = None
        #: R3.1 · restart provenance, so an operator never has to infer
        #: whether this gate remembered the outage or rediscovered it.
        self.restored_from: Optional[str] = None
        self.state_load_error: Optional[str] = None

        if self._store is not None:
            self._restore()

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
        self._persist()

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
            self._persist()

    def record_event_refusal(self, reason: str) -> None:
        """An authoritative per-event refusal. The destination is healthy, so
        this resets the failure run rather than moving the gate."""
        self.consecutive_failures = 0
        self.last_reason = reason
        if self.state != GateState.CLOSED:
            self._transition(GateState.CLOSED,
                             "destination answered authoritatively")
        self.opened_at = None
        self._persist()

    def note_probe(self) -> None:
        self.probes += 1
        self._persist()

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
        self._persist()

    def seconds_until_probe(self) -> Optional[float]:
        if self.state != GateState.OPEN or self.opened_at is None:
            return None
        return max(0.0, self.current_cooldown - (self._now() - self.opened_at))

    # ── R3.1 · durability ────────────────────────────────────────────
    def snapshot(self) -> Dict[str, Any]:
        """The minimum authoritative state needed for safe restart."""
        if self.state == GateState.OPEN:
            deadline = self._wall() + (self.seconds_until_probe() or 0.0)
        elif self.state == GateState.HALF_OPEN:
            # A restart mid-probe resumes OPEN and probe-eligible: exactly one
            # bounded probe, never a burst.
            deadline = self._wall()
        else:
            deadline = None
        return {
            "state_version":        GATE_STATE_VERSION,
            "state":                self.state,
            "consecutive_failures": int(self.consecutive_failures),
            "cooldown_seconds":     float(self.current_cooldown),
            "cooldown_until_epoch": deadline,
            "opened_count":         int(self.opened_count),
            "probes":               int(self.probes),
            "last_reason":          scrub_reason(self.last_reason),
            "last_transition_at":   self.last_transition_at,
        }

    def _persist(self) -> None:
        if self._store is None:
            return
        try:
            self._store.save_health_gate(self._key, self.snapshot())
        except Exception as exc:                                # noqa: BLE001
            # Losing durability must be visible, but it must not stop
            # delivery decisions that are otherwise correct in memory.
            self.state_load_error = (
                f"health-gate state could not be persisted: "
                f"{type(exc).__name__}: {str(exc)[:160]}")

    def _restore(self) -> None:
        try:
            raw = self._store.load_health_gate(self._key)
        except Exception as exc:                                # noqa: BLE001
            self._fail_safe(f"{type(exc).__name__}: {str(exc)[:160]}")
            return
        if raw is None:
            # First boot for this destination. CLOSED is the truthful default:
            # nothing is known about the destination yet.
            return
        try:
            snap = validate_snapshot(raw)
        except GateStateUnreadable as exc:
            self._fail_safe(str(exc))
            return

        self.restored_from = snap["state"]
        self.consecutive_failures = snap["consecutive_failures"]
        self.current_cooldown = min(max(snap["cooldown_seconds"],
                                        self.base_cooldown),
                                    self.max_cooldown)
        self.opened_count = snap["opened_count"]
        self.probes = snap["probes"]
        self.last_reason = snap["last_reason"]
        self.last_transition_at = snap["last_transition_at"]

        if snap["state"] in (GateState.CLOSED, GateState.SUSPECT):
            # A crash-loop must not reset a building outage to zero, so the
            # failure run is kept exactly as it was.
            self.state = snap["state"]
            self.opened_at = None
            return

        remaining = 0.0
        if snap["state"] == GateState.OPEN:
            deadline = snap["cooldown_until_epoch"] or 0.0
            remaining = deadline - self._wall()
            # A clock moved backwards cannot extend a pause beyond its own
            # bound, and a deadline already passed cannot go negative.
            remaining = min(max(remaining, 0.0), self.current_cooldown)
        self.state = GateState.OPEN
        self.opened_at = self._now() - (self.current_cooldown - remaining)

    def _fail_safe(self, detail: str) -> None:
        """Unreadable persisted state pauses delivery, visibly and bounded."""
        self.state_load_error = detail
        self.consecutive_failures = 0
        self.current_cooldown = self.base_cooldown
        self.opened_at = self._now()
        self.opened_count += 1
        self._transition(
            GateState.OPEN,
            "persisted delivery-health state was unreadable, so the gate "
            f"failed safe and paused delivery: {detail}")

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
            "durable":               self._store is not None,
            "destination_key":       self._key,
            "restored_from":         self.restored_from,
            "state_load_error":      self.state_load_error,
        }
