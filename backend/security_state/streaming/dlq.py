"""Authoritative Dead-Letter Queue (DLQ) Service for NivXRay Streaming Telemetry."""
from __future__ import annotations

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..persistence.repository import InterProcessCaseLock
from .models import DLQFailureClass, DLQRecord


class DeadLetterQueueService:
    """Authoritative DLQ store for rejected, corrupt, or unroutable streaming evidence."""

    COLLECTION_NAME = "security_state_dlq"

    def __init__(self, fallback_storage_dir: Optional[str] = None) -> None:
        self._fallback_dir = fallback_storage_dir or os.path.join(
            os.path.dirname(__file__), "..", "..", ".persisted_security_state"
        )
        os.makedirs(os.path.join(self._fallback_dir, "dlq_locks"), exist_ok=True)

        self._use_mongo = False
        self._dlq_col = None

        try:
            from deps import sync_collection
            self._dlq_col = sync_collection(self.COLLECTION_NAME)
            self._dlq_col.find_one()
            self._use_mongo = True
            self._ensure_indexes()
        except Exception:
            self._use_mongo = False

    def _ensure_indexes(self) -> None:
        if not self._use_mongo or self._dlq_col is None:
            return
        try:
            self._dlq_col.create_index(
                [("tenant_id", 1), ("dlq_id", 1)],
                unique=True,
                name="idx_sec_dlq_uniq",
            )
            self._dlq_col.create_index(
                [("tenant_id", 1), ("failure_class", 1)],
                name="idx_sec_dlq_class",
            )
        except Exception:
            pass

    def _get_dlq_file(self, tenant_id: str) -> str:
        s_tenant = tenant_id.replace(":", "_").replace("/", "_").replace("\\", "_")
        return os.path.join(self._fallback_dir, f"dlq_{s_tenant}.json")

    def _get_lock(self, tenant_id: str) -> InterProcessCaseLock:
        s_tenant = tenant_id.replace(":", "_").replace("/", "_").replace("\\", "_")
        lock_path = os.path.join(self._fallback_dir, "dlq_locks", f"lock_{s_tenant}")
        return InterProcessCaseLock(lock_path)

    def _read_records(self, filepath: str) -> List[Dict[str, Any]]:
        if not os.path.exists(filepath):
            return []
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _write_records(self, filepath: str, records: List[Dict[str, Any]]) -> None:
        temp_path = filepath + f".tmp_{os.getpid()}_{time.time()}"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        try:
            os.replace(temp_path, filepath)
        except OSError:
            pass

    def record_dead_letter(
        self,
        source_id: str,
        event_id: str,
        tenant_id: str,
        failure_class: DLQFailureClass,
        reason: str,
        provenance: Dict[str, Any],
        raw_envelope: Dict[str, Any],
        schema_version: str = "1.0.0",
    ) -> DLQRecord:
        """Atomically persist a dead-letter record."""
        dlq_id = f"dlq-{uuid.uuid4().hex[:12]}"
        now_ts = datetime.now(timezone.utc).isoformat()

        record = DLQRecord(
            dlq_id=dlq_id,
            source_id=source_id,
            event_id=event_id,
            tenant_id=tenant_id,
            failure_class=failure_class.value,
            reason=reason,
            timestamp=now_ts,
            schema_version=schema_version,
            provenance=provenance,
            raw_envelope=raw_envelope,
            replayed=False,
            replayed_at=None,
        )

        if self._use_mongo and self._dlq_col is not None:
            self._dlq_col.insert_one(record.to_dict())
        else:
            lock = self._get_lock(tenant_id)
            with lock:
                filepath = self._get_dlq_file(tenant_id)
                recs = self._read_records(filepath)
                recs.append(record.to_dict())
                self._write_records(filepath, recs)

        return record

    def get_dlq_records(
        self,
        tenant_id: str,
        replayed: Optional[bool] = None,
    ) -> List[DLQRecord]:
        """Fetch DLQ records for tenant."""
        if self._use_mongo and self._dlq_col is not None:
            query: Dict[str, Any] = {"tenant_id": tenant_id}
            if replayed is not None:
                query["replayed"] = replayed
            cursor = self._dlq_col.find(query).sort("timestamp", -1)
            return [DLQRecord.from_dict(d) for d in cursor]
        else:
            filepath = self._get_dlq_file(tenant_id)
            recs = self._read_records(filepath)
            if replayed is not None:
                recs = [d for d in recs if d.get("replayed", False) == replayed]
            return [DLQRecord.from_dict(d) for d in sorted(recs, key=lambda x: x.get("timestamp", ""), reverse=True)]

    def mark_replayed(self, tenant_id: str, dlq_id: str) -> bool:
        """Mark a DLQ record as successfully remediated and replayed."""
        now_ts = datetime.now(timezone.utc).isoformat()
        if self._use_mongo and self._dlq_col is not None:
            res = self._dlq_col.update_one(
                {"tenant_id": tenant_id, "dlq_id": dlq_id},
                {"$set": {"replayed": True, "replayed_at": now_ts}},
            )
            return res.modified_count > 0
        else:
            lock = self._get_lock(tenant_id)
            with lock:
                filepath = self._get_dlq_file(tenant_id)
                recs = self._read_records(filepath)
                found = False
                for r in recs:
                    if r.get("dlq_id") == dlq_id:
                        r["replayed"] = True
                        r["replayed_at"] = now_ts
                        found = True
                        break
                if found:
                    self._write_records(filepath, recs)
                return found
