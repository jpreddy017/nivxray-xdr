"""The durable FORWARD-STREAM state for Behavior shadow evaluation.

Two operations and nothing else: INITIALIZE a frontier, and READ/ADVANCE it.
No rule is evaluated, no detection is written, no engine is constructed.

The rule this module exists to enforce: **an absent checkpoint is a refusal,
never "start from the beginning"**. `run_replay` treats a missing checkpoint as
"page from the start", which against an endpoint holding tens of thousands of
historical observations would quietly violate the new-evidence-only decision.
Here, reading an uninitialized stream raises.

Ordering authority is `(stored observation time, EvidenceRef.stable_key())` —
the same key `EvidenceRecord.sort_key()` exposes. Ingest time is never read.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence, Tuple

MODE_FRONTIER = "INITIALIZED_AT_CURRENT_FRONTIER"
MODE_NO_EVIDENCE = "INITIALIZED_AT_CURRENT_FRONTIER_NO_EVIDENCE"

REFUSED_NOT_INITIALIZED = "SHADOW_NO_FRONTIER_INITIALIZED"
REFUSED_BACKWARDS = "SHADOW_BACKWARD_ADVANCE_REFUSED"
REFUSED_MALFORMED_KEY = "SHADOW_MALFORMED_SORT_KEY_REFUSED"
REFUSED_TENANT = "SHADOW_TENANT_MISMATCH_REFUSED"
REFUSED_ENDPOINT = "SHADOW_ENDPOINT_MISMATCH_REFUSED"
REFUSED_RULESET = "SHADOW_RULESET_STREAM_MISMATCH_REFUSED"
REFUSED_UNRESOLVED_ITEM = "SHADOW_ADVANCE_PAST_UNRESOLVED_ITEM_REFUSED"
REFUSED_UNBOUNDED = "SHADOW_UNBOUNDED_INITIALIZATION_REFUSED"


class ShadowFrontierRefused(RuntimeError):
    """A refusal with a named reason. Never a silent fallback."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class StaleCheckpoint(ShadowFrontierRefused):
    """Optimistic-concurrency conflict: someone else advanced this stream."""

    def __init__(self) -> None:
        super().__init__("SHADOW_CHECKPOINT_STALE_REVISION")


def stream_id(ruleset_content_hash: str) -> str:
    """A ruleset's forward stream. A content change starts its OWN stream, so
    one ruleset can never inherit another's watermark."""
    h = str(ruleset_content_hash or "").strip()
    if not h:
        raise ShadowFrontierRefused(REFUSED_RULESET)
    return f"shadow:{h}"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sort_key(value: Any) -> Tuple[datetime, str]:
    """A sort key is a (tz-aware observation time, non-empty stable key) pair."""
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        raise ShadowFrontierRefused(REFUSED_MALFORMED_KEY)
    when, key = value
    if not isinstance(when, datetime) or when.tzinfo is None:
        raise ShadowFrontierRefused(REFUSED_MALFORMED_KEY)
    if not isinstance(key, str) or not key.strip():
        raise ShadowFrontierRefused(REFUSED_MALFORMED_KEY)
    return when.astimezone(timezone.utc), key.strip()


def _stored(cp: Dict[str, Any]) -> Optional[Tuple[datetime, str]]:
    """The stream's current position, or None for a no-evidence frontier."""
    t, k = cp.get("after_time"), cp.get("after_key")
    if not t or not k:
        return None
    return datetime.fromisoformat(str(t).replace("Z", "+00:00")), str(k)


async def initialize(provider: Any, store: Any, *, tenant_id: str,
                     endpoint_id: str, ruleset_id: str, ruleset_version: Any,
                     ruleset_content_hash: str, window_start: datetime,
                     window_end: datetime, initialized_by: str,
                     now: Optional[datetime] = None,
                     scan_limit: int = 1000) -> Dict[str, Any]:
    """Establish the frontier. Evaluates ZERO rules and writes ZERO detections.

    The newest eligible evidence is identified through the Step-25 §d-backed
    provider only — this module issues no query of its own.
    """
    if window_start is None or window_end is None or window_end < window_start:
        raise ShadowFrontierRefused(REFUSED_UNBOUNDED)
    rid = stream_id(ruleset_content_hash)
    at = _iso(now or datetime.now(timezone.utc))

    records: Sequence[Any] = await provider.window(
        tenant_id=tenant_id, endpoint_id=endpoint_id, start=window_start,
        end=window_end, kinds=(), limit=max(1, int(scan_limit)))

    cp: Dict[str, Any] = {
        "tenant_id": tenant_id, "endpoint_id": endpoint_id, "replay_id": rid,
        "ruleset_id": ruleset_id, "ruleset_version": ruleset_version,
        "ruleset_content_hash": ruleset_content_hash,
        "initialized_at": at, "initialized_by": initialized_by,
        "evaluated_total": 0, "revision": 1,
        # A forward stream is never finished.
        "done": False,
    }
    if records:
        newest = max(records, key=lambda r: r.sort_key())
        when, key = _sort_key(newest.sort_key())
        cp.update({"mode": MODE_FRONTIER, "frontier_time": _iso(when),
                   "frontier_key": key, "after_time": _iso(when),
                   "after_key": key})
    else:
        # The initialization INSTANT is not an observed evidence time, so it is
        # never written into a frontier field. Eligibility for the first
        # subsequently observed evidence is the runner's decision, not a
        # fabricated timestamp.
        cp.update({"mode": MODE_NO_EVIDENCE, "frontier_time": None,
                   "frontier_key": None, "after_time": None,
                   "after_key": None})

    await store.save(tenant_id, rid, endpoint_id, cp)
    return cp


async def read(store: Any, *, tenant_id: str, endpoint_id: str,
               ruleset_content_hash: str) -> Dict[str, Any]:
    """The stream's state, or a refusal. Never a beginning-of-history default."""
    rid = stream_id(ruleset_content_hash)
    cp = await store.load(tenant_id, rid, endpoint_id)
    if not cp or not cp.get("mode"):
        raise ShadowFrontierRefused(REFUSED_NOT_INITIALIZED)
    _assert_stream(cp, tenant_id, endpoint_id, ruleset_content_hash)
    return dict(cp)


def _assert_stream(cp: Dict[str, Any], tenant_id: str, endpoint_id: str,
                   ruleset_content_hash: str) -> None:
    if cp.get("tenant_id") != tenant_id:
        raise ShadowFrontierRefused(REFUSED_TENANT)
    if cp.get("endpoint_id") != endpoint_id:
        raise ShadowFrontierRefused(REFUSED_ENDPOINT)
    if cp.get("ruleset_content_hash") != ruleset_content_hash:
        raise ShadowFrontierRefused(REFUSED_RULESET)


async def advance(store: Any, *, tenant_id: str, endpoint_id: str,
                  ruleset_content_hash: str,
                  processed_sort_key: Tuple[datetime, str],
                  expected_revision: Optional[int] = None,
                  evaluated_delta: int = 1,
                  item_resolved: bool = True) -> Dict[str, Any]:
    """Move the watermark to an explicitly processed evidence sort key.

    This module does NOT decide what "processed" means — the future runner owns
    that and calls this only after its own persistence has succeeded. An item
    the runner could not resolve (budget exceeded, evaluation failed) must be
    passed with `item_resolved=False` and is refused, so the stream can never
    step over evidence whose outcome is unknown.
    """
    if not item_resolved:
        raise ShadowFrontierRefused(REFUSED_UNRESOLVED_ITEM)
    cp = await read(store, tenant_id=tenant_id, endpoint_id=endpoint_id,
                    ruleset_content_hash=ruleset_content_hash)
    if expected_revision is not None and \
            int(cp.get("revision") or 0) != int(expected_revision):
        raise StaleCheckpoint()

    when, key = _sort_key(processed_sort_key)
    current = _stored(cp)
    if current is not None:
        if (when, key) < current:
            raise ShadowFrontierRefused(REFUSED_BACKWARDS)
        if (when, key) == current:
            return cp        # idempotent: same key, no revision, no counting

    cp.update({"after_time": _iso(when), "after_key": key,
               "evaluated_total": int(cp.get("evaluated_total") or 0)
               + max(0, int(evaluated_delta)),
               "revision": int(cp.get("revision") or 0) + 1,
               "done": False})
    await store.save(tenant_id, stream_id(ruleset_content_hash), endpoint_id,
                     cp)
    return cp
