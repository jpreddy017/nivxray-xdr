"""Persistent Deduplication Service for NivXRay Streaming Telemetry.

Backed by authoritative collection `security_event_dedup` (with file-system atomic lock fallback).
Memory LRU ring buffer is maintained strictly as an ephemeral performance optimization.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, Tuple

from ..persistence.repository import InterProcessCaseLock


class PersistentDeduplicationService:
    """Authoritative persistent deduplication store scoped by tenant and event fingerprint."""

    COLLECTION_NAME = "security_event_dedup"

    def __init__(
        self,
        ttl_seconds: int = 86400,
        lru_capacity: int = 10000,
        fallback_storage_dir: Optional[str] = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self._lru_capacity = lru_capacity
        self._lru_cache: collections.OrderedDict[Tuple[str, str], float] = collections.OrderedDict()

        self._fallback_dir = fallback_storage_dir or os.path.join(
            os.path.dirname(__file__), "..", "..", ".persisted_security_state"
        )
        os.makedirs(os.path.join(self._fallback_dir, "dedup_locks"), exist_ok=True)

        self._use_mongo = False
        self._dedup_col = None

        try:
            from deps import sync_collection
            self._dedup_col = sync_collection(self.COLLECTION_NAME)
            self._dedup_col.find_one()
            self._use_mongo = True
            self._ensure_indexes()
        except Exception:
            self._use_mongo = False

    def _ensure_indexes(self) -> None:
        if not self._use_mongo or self._dedup_col is None:
            return
        try:
            self._dedup_col.create_index(
                [("tenant_id", 1), ("event_fingerprint", 1)],
                unique=True,
                name="idx_sec_dedup_uniq",
            )
            self._dedup_col.create_index(
                [("ttl_expires_at", 1)],
                expireAfterSeconds=0,
                name="idx_sec_dedup_ttl",
            )
        except Exception:
            pass

    def _get_dedup_file(self, tenant_id: str) -> str:
        s_tenant = tenant_id.replace(":", "_").replace("/", "_").replace("\\", "_")
        return os.path.join(self._fallback_dir, f"dedup_{s_tenant}.json")

    def _get_lock(self, tenant_id: str) -> InterProcessCaseLock:
        s_tenant = tenant_id.replace(":", "_").replace("/", "_").replace("\\", "_")
        lock_path = os.path.join(self._fallback_dir, "dedup_locks", f"lock_{s_tenant}")
        return InterProcessCaseLock(lock_path)

    def _read_records(self, filepath: str) -> Dict[str, Dict[str, Any]]:
        if not os.path.exists(filepath):
            return {}
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_records(self, filepath: str, records: Dict[str, Dict[str, Any]]) -> None:
        temp_path = filepath + f".tmp_{os.getpid()}_{time.time()}"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        try:
            os.replace(temp_path, filepath)
        except OSError:
            pass

    def is_duplicate_or_record(
        self,
        tenant_id: str,
        fingerprint: str,
        source_id: str = "",
    ) -> bool:
        """Check if (tenant_id, fingerprint) is duplicate.

        If NOT duplicate, atomically records it and returns False.
        If ALREADY SEEN, returns True.
        """
        cache_key = (tenant_id, fingerprint)
        now_ts = time.time()

        # Fast path: check memory LRU cache
        if cache_key in self._lru_cache:
            # Refresh LRU position
            self._lru_cache.move_to_end(cache_key)
            return True

        now_dt = datetime.now(timezone.utc)
        expires_dt = now_dt + timedelta(seconds=self.ttl_seconds)

        if self._use_mongo and self._dedup_col is not None:
            doc = {
                "tenant_id": tenant_id,
                "event_fingerprint": fingerprint,
                "source_id": source_id,
                "first_seen_at": now_dt.isoformat(),
                "ttl_expires_at": expires_dt,
            }
            try:
                # Atomic insertion with unique index
                self._dedup_col.insert_one(doc)
                self._record_in_lru(cache_key, now_ts)
                return False  # Newly recorded, not duplicate
            except Exception as ex:
                if "duplicate key" in str(ex).lower():
                    self._record_in_lru(cache_key, now_ts)
                    return True  # Duplicate
                raise ex
        else:
            # Durable Multi-process file fallback
            lock = self._get_lock(tenant_id)
            with lock:
                filepath = self._get_dedup_file(tenant_id)
                records = self._read_records(filepath)

                # Clean expired records
                expired_keys = [
                    k for k, v in records.items()
                    if v.get("expires_at_epoch", 0) < now_ts
                ]
                for k in expired_keys:
                    del records[k]

                if fingerprint in records:
                    self._record_in_lru(cache_key, now_ts)
                    return True

                records[fingerprint] = {
                    "tenant_id": tenant_id,
                    "event_fingerprint": fingerprint,
                    "source_id": source_id,
                    "first_seen_at": now_dt.isoformat(),
                    "expires_at_epoch": now_ts + self.ttl_seconds,
                }
                self._write_records(filepath, records)
                self._record_in_lru(cache_key, now_ts)
                return False

    def _record_in_lru(self, key: Tuple[str, str], ts: float) -> None:
        self._lru_cache[key] = ts
        if len(self._lru_cache) > self._lru_capacity:
            self._lru_cache.popitem(last=False)

    def clear_memory_cache(self) -> None:
        """Clear local in-memory LRU cache to simulate process restart / replica cache-miss."""
        self._lru_cache.clear()
