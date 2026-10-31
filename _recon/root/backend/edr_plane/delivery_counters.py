"""DELIVERY FIDELITY COUNTERS — where telemetry is, boundary by boundary.

The boundaries, in order:

```
endpoint_observed → sensor_attempted → sensor_sent
                  → received → parsed | parse_failed | refused
                  → accepted | deduplicated → canonicalized
```

Rules this module exists to hold:

* **Counters are METADATA ONLY.** No path, no command line, no payload,
  no credential, no hostname — a counter answers "how many", never
  "which one". Evidence lives in `edr_raw_events` and
  `xdr_canonical_evidence`; these counters are NOT an evidence authority
  and nothing may be attributed from them.
* **Monotonic.** Server-side counters are `$inc` only and are never
  reset, so a decrease is impossible by construction. Sensor-reported
  counters restart with the sensor process; each sensor declares a
  `counter_epoch` and a new epoch is recorded as an epoch CHANGE with
  the previous snapshot retained, never as a decrease and never merged.
* **A parse failure is an OUTCOME, not a gap.** Every received event
  increments exactly one terminal outcome, so "received minus accounted"
  is always zero and an unexplained disappearance is impossible.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional

COLLECTION = "edr_delivery_counters"

#: Boundaries the SERVER can observe itself.
RECEIVED = "received"
PARSED = "parsed"
PARSE_FAILED = "parse_failed"
REFUSED = "refused"
ACCEPTED = "accepted"
DEDUPLICATED = "deduplicated"
CANONICALIZED = "canonicalized"
SERVER_BOUNDARIES = (RECEIVED, PARSED, PARSE_FAILED, REFUSED, ACCEPTED,
                     DEDUPLICATED, CANONICALIZED)
#: Detail of `deduplicated` — a byte-identical re-delivery is not the same
#: fact as a re-observation of an activity already held as evidence.
DEDUP_CLASSES = ("deduplicated_payload", "deduplicated_activity")
COUNTED = SERVER_BOUNDARIES + DEDUP_CLASSES

#: Boundaries only the ENDPOINT can observe. Reported by the sensor,
#: stored as a sensor CLAIM, never promoted to a server measurement.
SENSOR_BOUNDARIES = ("endpoint_observed", "endpoint_read",
                     "sensor_attempted", "sensor_sent", "sensor_failed",
                     "sensor_suppressed_by_policy", "sensor_queue_depth")
MAX_COUNTER = 2 ** 53

RESTART_SEMANTICS = (
    "server counters are persistent and monotonic: they are never reset, "
    "so a lower value than a previous read is impossible. sensor counters "
    "are per counter_epoch: a sensor restart or state reset declares a NEW "
    "epoch, and the previous epoch's final snapshot is retained in "
    "sensor_epoch_history instead of being added to or subtracted from the "
    "new one")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def channel_of(payload: Any) -> str:
    """The delivery CHANNEL an event arrived on, from its envelope only.

    Metadata, deliberately coarse: a Windows channel name or a sensor
    activity class. Nothing from the event body is read.
    """
    if isinstance(payload, str):
        import json
        try:
            payload = json.loads(payload)
        except (ValueError, TypeError):
            return "UNPARSEABLE_ENVELOPE"
    if not isinstance(payload, dict):
        return "UNKNOWN"
    winlog = payload.get("winlog")
    if isinstance(winlog, dict) and winlog.get("channel"):
        return str(winlog["channel"])[:120]
    activity = payload.get("activity")
    if activity:
        return f"SENSOR_{str(activity)[:60]}"
    return "UNKNOWN"


async def ensure_indexes(db: Any) -> None:
    await db[COLLECTION].create_index(
        [("tenant_id", 1), ("endpoint_id", 1), ("channel", 1)],
        unique=True, name="uniq_tenant_endpoint_channel")


async def record(db: Any, *, tenant_id: str, endpoint_id: str,
                 channel: str, outcomes: Iterable[str] | Dict[str, int],
                 reason_code: Optional[str] = None) -> Dict[str, Any]:
    """Increment one or more delivery boundaries. `$inc` only."""
    if isinstance(outcomes, dict):
        deltas = {k: int(v) for k, v in outcomes.items() if int(v) > 0}
    else:
        deltas = {k: 1 for k in outcomes}
    unknown = sorted(k for k in deltas if k not in COUNTED)
    if unknown:
        raise ValueError(f"not a declared delivery boundary: {unknown}")
    if not deltas:
        return {"recorded": False, "reason": "no boundary named"}
    inc = {f"counters.{k}": v for k, v in deltas.items()}
    if reason_code:
        code = str(reason_code)[:80].replace(".", "_").replace("$", "_")
        if PARSE_FAILED in deltas:
            inc[f"parse_failure_reasons.{code}"] = deltas[PARSE_FAILED]
        if REFUSED in deltas:
            inc[f"refusal_reasons.{code}"] = deltas[REFUSED]
    await db[COLLECTION].update_one(
        {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
         "channel": channel or "UNKNOWN"},
        {"$inc": inc,
         "$set": {"last_recorded_at": _now()},
         "$setOnInsert": {"counter_epoch": _now(),
                          "authority": "SERVER_OBSERVED",
                          "evidence_authority": False,
                          "restart_semantics": RESTART_SEMANTICS}},
        upsert=True)
    return {"recorded": True, "boundaries": deltas}


def validate_sensor_counters(counters: Any) -> Dict[str, int]:
    """Accept ONLY declared, non-negative integer boundaries."""
    if not isinstance(counters, dict):
        raise ValueError("delivery_counters must be an object")
    clean: Dict[str, int] = {}
    for key, value in counters.items():
        if key not in SENSOR_BOUNDARIES:
            raise ValueError(f"not a declared sensor boundary: {key!r}")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"{key} must be an integer")
        if value < 0 or value > MAX_COUNTER:
            raise ValueError(f"{key} is out of range")
        clean[key] = value
    return clean


async def record_sensor_reported(db: Any, *, tenant_id: str,
                                 endpoint_id: str, counter_epoch: str,
                                 counters: Dict[str, int],
                                 sensor_version: Optional[str] = None
                                 ) -> Dict[str, Any]:
    """Store the sensor's OWN counters as a claim, epoch-aware.

    Stored under the reserved channel `__sensor__` so it can never be
    confused with a server measurement of a real delivery channel.
    """
    clean = validate_sensor_counters(counters)
    key = {"tenant_id": tenant_id, "endpoint_id": endpoint_id,
           "channel": "__sensor__"}
    doc = await db[COLLECTION].find_one(
        key, {"_id": 0, "sensor_counter_epoch": 1, "sensor_counters": 1})
    epoch = str(counter_epoch or "")[:64] or "UNDECLARED"
    prior_epoch = (doc or {}).get("sensor_counter_epoch")
    update: Dict[str, Any] = {
        "$set": {"sensor_counters": clean, "sensor_counter_epoch": epoch,
                 "sensor_version": sensor_version,
                 "sensor_reported_at": _now(),
                 "authority": "SENSOR_CLAIMED",
                 "evidence_authority": False,
                 "restart_semantics": RESTART_SEMANTICS},
        "$setOnInsert": {"counter_epoch": _now()},
    }
    epoch_changed = bool(prior_epoch) and prior_epoch != epoch
    if epoch_changed:
        update["$push"] = {"sensor_epoch_history": {
            "counter_epoch": prior_epoch,
            "final_snapshot": (doc or {}).get("sensor_counters") or {},
            "closed_at": _now()}}
        update["$inc"] = {"sensor_counter_epoch_changes": 1}
    await db[COLLECTION].update_one(key, update, upsert=True)
    return {"recorded": True, "counter_epoch": epoch,
            "epoch_changed": epoch_changed,
            "boundaries": sorted(clean)}


async def read(db: Any, *, tenant_id: str,
               endpoint_id: Optional[str] = None) -> Dict[str, Any]:
    """Read-only delivery fidelity for one tenant (optionally one
    endpoint). Reports what is measurable AND what is not."""
    query: Dict[str, Any] = {"tenant_id": tenant_id}
    if endpoint_id:
        query["endpoint_id"] = endpoint_id
    rows = await db[COLLECTION].find(query, {"_id": 0}).to_list(length=2000)
    totals = {k: 0 for k in COUNTED}
    channels = []
    sensor_claims = []
    parse_reasons: Dict[str, int] = {}
    refusal_reasons: Dict[str, int] = {}
    for row in rows:
        if row.get("channel") == "__sensor__":
            sensor_claims.append({
                "endpoint_id": row.get("endpoint_id"),
                "counter_epoch": row.get("sensor_counter_epoch"),
                "counters": row.get("sensor_counters") or {},
                "reported_at": row.get("sensor_reported_at"),
                "sensor_version": row.get("sensor_version"),
                "epoch_changes": row.get("sensor_counter_epoch_changes", 0),
            })
            continue
        counters = row.get("counters") or {}
        for key in COUNTED:
            totals[key] += int(counters.get(key) or 0)
        for name, bucket in (("parse_failure_reasons", parse_reasons),
                             ("refusal_reasons", refusal_reasons)):
            for code, count in (row.get(name) or {}).items():
                bucket[code] = bucket.get(code, 0) + int(count)
        channels.append({"endpoint_id": row.get("endpoint_id"),
                         "channel": row.get("channel"),
                         "counters": {k: int(counters.get(k) or 0)
                                      for k in COUNTED},
                         "last_recorded_at": row.get("last_recorded_at")})
    # TWO accounting layers, because an event has TWO outcomes: was it
    # stored, and was it canonicalised. Mixing them would make an
    # accepted-and-then-failed event look like a discrepancy.
    stored = totals[ACCEPTED] + totals["deduplicated_payload"]
    canonical_outcomes = (totals[CANONICALIZED]
                          + totals["deduplicated_activity"]
                          + totals[PARSE_FAILED] + totals[REFUSED])
    return {
        "collection": COLLECTION,
        "authority": "OPERATIONAL_COUNTER_NOT_EVIDENCE",
        "monotonic": True,
        "restart_semantics": RESTART_SEMANTICS,
        "server_observed": totals,
        "unaccounted_received": totals[RECEIVED] - stored,
        "unaccounted_accepted": totals[ACCEPTED] - canonical_outcomes,
        "parse_failure_reasons": parse_reasons,
        "refusal_reasons": refusal_reasons,
        "channels": channels,
        "sensor_claimed": sensor_claims,
        "boundary_measurability": {
            "endpoint_observed": ("SENSOR_CLAIMED" if sensor_claims
                                  else "NOT_MEASURABLE_SENSOR_COUNTERS_"
                                       "NOT_REPORTED"),
            "sensor_sent": ("SENSOR_CLAIMED" if sensor_claims
                            else "NOT_MEASURABLE_SENSOR_COUNTERS_NOT_"
                                 "REPORTED"),
            "received": "SERVER_MEASURED",
            "parsed": "SERVER_MEASURED",
            "parse_failed": "SERVER_MEASURED",
            "refused": "SERVER_MEASURED",
            "accepted": "SERVER_MEASURED",
            "deduplicated": "SERVER_MEASURED",
            "canonicalized": "SERVER_MEASURED",
        },
        "note": ("`unaccounted_received` must be 0: every received event "
                 "is either ACCEPTED as a new raw event or counted as a "
                 "byte-identical re-delivery. `unaccounted_accepted` must "
                 "be 0 once each accepted event has reached a "
                 "canonicalisation outcome; a non-zero value means events "
                 "were in flight when the service last restarted, which is "
                 "a delivery fact and not evidence loss. Deduplication and "
                 "delivery latency are NOT loss. A sensor-claimed boundary "
                 "is the endpoint's own statement and is never presented "
                 "as a server measurement"),
    }
