"""Immutable SSOT store (D6-r).

Two backends:
- InMemorySSOTStore: default; dict-backed; deterministic; test-friendly.
- SSOTStore (Mongo-backed): writes to a NEW collection alongside the
  legacy `investigation_ssot`, additive-only.

Phase 2 constraint: the legacy `investigation_ssot` collection is not
read from and not written to. `workspace_cases.ssot` is not touched.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .authoritative import AuthoritativeSSOT
from .ssot_ref import SSOTRef, make_ssot_ref, parse_fingerprint, validate_ref


CANONICAL_SSOT_COLLECTION = "canonical_ssot_store"  # NEW — see spec §5


# ─────────────────────────────────────────────────────────────────────────
#   In-memory store — the default backend for Phase 2 tests
# ─────────────────────────────────────────────────────────────────────────
class InMemorySSOTStore:
    """Content-addressed, append-only, in-memory store."""

    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, Any]] = {}

    def put(self, ssot: AuthoritativeSSOT) -> SSOTRef:
        fp = ssot.fingerprint()
        ref = make_ssot_ref(fp)
        # Content-addressed: identical content → identical ref → no-op write.
        blob = ssot.to_dict()
        blob.setdefault("_stored_at", datetime.now(timezone.utc).isoformat())
        # Never overwrite a stored blob (immutable-store invariant).
        if fp not in self._data:
            self._data[fp] = blob
        return ref

    def get(self, ref: SSOTRef) -> Optional[AuthoritativeSSOT]:
        if not validate_ref(ref):
            raise ValueError(f"invalid ssot_ref: {ref!r}")
        fp = parse_fingerprint(ref)
        blob = self._data.get(fp)
        if blob is None:
            return None
        clean = dict(blob)
        clean.pop("_stored_at", None)
        return AuthoritativeSSOT.from_dict(clean)

    def exists(self, ref: SSOTRef) -> bool:
        return validate_ref(ref) and parse_fingerprint(ref) in self._data

    def count(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        """Test-only helper. Never used in production."""
        self._data.clear()


# ─────────────────────────────────────────────────────────────────────────
#   Mongo-backed store — lazy binding, sync (pymongo) for service-layer use
# ─────────────────────────────────────────────────────────────────────────
class SSOTStore:
    """Mongo-backed content-addressed store — writes ONLY to the new
    `canonical_ssot_store` collection. Never touches `investigation_ssot`.

    Phase 2 note: this class exists so future phases can persist without
    a code shape change. Phase 2 tests exercise `InMemorySSOTStore` for
    determinism; a smoke test proves this class connects when MONGO_URL
    is set.
    """

    def __init__(self, mongo_url: Optional[str] = None,
                 db_name: Optional[str] = None,
                 collection: str = CANONICAL_SSOT_COLLECTION) -> None:
        from pymongo import MongoClient
        self._url = mongo_url or os.environ.get("MONGO_URL")
        self._db_name = db_name or os.environ.get("DB_NAME")
        if not self._url or not self._db_name:
            raise ValueError("MONGO_URL and DB_NAME must be set")
        self._client = MongoClient(self._url)
        self._col = self._client[self._db_name][collection]

    def put(self, ssot: AuthoritativeSSOT) -> SSOTRef:
        fp = ssot.fingerprint()
        ref = make_ssot_ref(fp)
        # Idempotent write keyed on fingerprint. Existing blobs untouched.
        self._col.update_one(
            {"_fp": fp},
            {"$setOnInsert": {
                "_fp": fp,
                "_ref": ref,
                "_stored_at": datetime.now(timezone.utc).isoformat(),
                "doc": ssot.to_dict(),
            }},
            upsert=True,
        )
        return ref

    def get(self, ref: SSOTRef) -> Optional[AuthoritativeSSOT]:
        if not validate_ref(ref):
            raise ValueError(f"invalid ssot_ref: {ref!r}")
        fp = parse_fingerprint(ref)
        row = self._col.find_one({"_fp": fp})
        if row is None:
            return None
        return AuthoritativeSSOT.from_dict(row["doc"])

    def exists(self, ref: SSOTRef) -> bool:
        if not validate_ref(ref):
            return False
        fp = parse_fingerprint(ref)
        return self._col.count_documents({"_fp": fp}, limit=1) > 0
