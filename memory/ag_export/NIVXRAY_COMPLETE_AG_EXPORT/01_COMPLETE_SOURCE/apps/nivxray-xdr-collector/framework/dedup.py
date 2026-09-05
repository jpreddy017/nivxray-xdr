"""
Bounded per-connector dedup cache.

Every canonical envelope carries a `source_event_id` (nullable for
sources that don't emit one).  When set, we drop duplicates within a
sliding window to survive vendor retries / webhook re-deliveries /
syslog UDP redelivery.

Cache is in-process and bounded — Phase B.5 replaces it with a durable
per-tenant Redis / SQLite backing.
"""
from __future__ import annotations

from collections import OrderedDict
from threading  import RLock
from typing     import Optional


class DedupCache:
    def __init__(self, capacity: int = 10_000) -> None:
        self._capacity = capacity
        self._lock     = RLock()
        self._buckets: dict[str, OrderedDict[str, None]] = {}

    def seen(self, connector_id: str, event_id: Optional[str]) -> bool:
        """Return True if `event_id` was already recorded for this
        connector and remember it going forward.  Null ids never
        deduplicate — the caller is responsible for treating them as
        unique deliveries."""
        if not event_id:
            return False
        with self._lock:
            bucket = self._buckets.setdefault(connector_id, OrderedDict())
            if event_id in bucket:
                # Move-to-end so re-seen ids stay hot in the LRU.
                bucket.move_to_end(event_id)
                return True
            bucket[event_id] = None
            if len(bucket) > self._capacity:
                bucket.popitem(last=False)
            return False

    def size(self, connector_id: str) -> int:
        with self._lock:
            return len(self._buckets.get(connector_id, {}))

    def clear(self, connector_id: Optional[str] = None) -> None:
        with self._lock:
            if connector_id is None:
                self._buckets.clear()
            else:
                self._buckets.pop(connector_id, None)
