"""NivXForge sensor · DELIVERY COUNTERS (capability, default OFF).

The server can only measure what it RECEIVED. Everything before that —
what the endpoint observed, what the sensor read, what it attempted, what
it actually put on the wire — is only knowable at the endpoint. Without
these counters the delivery boundary is unmeasurable, and an engine
reading that telemetry cannot prove its own completeness.

Rules:

* **Metadata only.** A counter is a number. No path, no command line, no
  payload, no hostname, no credential, no event identity of any kind
  ever enters this module.
* **Monotonic within an epoch.** Counters only ever increase. A sensor
  restart starts a NEW `counter_epoch`; the server records the epoch
  change and keeps the previous snapshot instead of pretending the
  counters went backwards.
* **Default OFF.** Nothing is collected and nothing is reported unless
  `NIVX_SENSOR_DELIVERY_COUNTERS=1`. When disabled, `snapshot()` returns
  None and the heartbeat carries no counter fields at all.
* **Not an evidence authority.** These numbers explain DELIVERY. They
  are never evidence that an activity happened.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

CAPABILITY_FLAG = "NIVX_SENSOR_DELIVERY_COUNTERS"
STATE_FILENAME = "delivery_counters.json"

#: Exactly the boundaries the server accepts. Anything else is refused
#: there, so the two sides cannot drift.
BOUNDARIES = ("endpoint_observed", "endpoint_read", "sensor_attempted",
              "sensor_sent", "sensor_failed",
              "sensor_suppressed_by_policy", "sensor_queue_depth")


def enabled() -> bool:
    return os.environ.get(CAPABILITY_FLAG, "0").strip() in ("1", "true",
                                                            "TRUE", "yes")


class DeliveryCounters:
    """Per-process monotonic counters, persisted for local inspection."""

    def __init__(self, state_dir: str | os.PathLike | None = None,
                 epoch: str | None = None):
        self.state_dir = Path(state_dir) if state_dir else None
        self.epoch = epoch or f"epoch-{int(time.time() * 1000)}"
        self._counts = {name: 0 for name in BOUNDARIES}

    @property
    def enabled(self) -> bool:
        return enabled()

    def bump(self, boundary: str, count: int = 1) -> None:
        if boundary not in BOUNDARIES:
            raise ValueError(f"not a declared delivery boundary: {boundary}")
        if not self.enabled or count <= 0:
            return
        self._counts[boundary] += int(count)

    def observe_gauge(self, boundary: str, value: int) -> None:
        """A GAUGE (queue depth) never decreases the stored value: it is
        kept as the high-water mark so the record stays monotonic."""
        if boundary not in BOUNDARIES:
            raise ValueError(f"not a declared delivery boundary: {boundary}")
        if not self.enabled:
            return
        self._counts[boundary] = max(self._counts[boundary], int(value or 0))

    def snapshot(self) -> dict | None:
        """The counters to report, or None when the capability is off."""
        if not self.enabled:
            return None
        return dict(self._counts)

    def persist(self) -> None:
        if not self.enabled or not self.state_dir:
            return
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            (self.state_dir / STATE_FILENAME).write_text(json.dumps(
                {"counter_epoch": self.epoch, "counters": self._counts,
                 "capability": CAPABILITY_FLAG,
                 "note": "metadata only; never event content"},
                separators=(",", ":")))
        except OSError:
            # A counter file that cannot be written must never stop
            # telemetry delivery.
            pass

    def heartbeat_fields(self) -> dict:
        """Additive heartbeat fields, or {} when the capability is off."""
        snap = self.snapshot()
        if snap is None:
            return {}
        return {"counter_epoch": self.epoch, "delivery_counters": snap}
