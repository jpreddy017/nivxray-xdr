"""NivXRay · File Store (P1 · ADR-0008 §5.2 · owner-locked 2026-08-11).

Design contract (all four corrections locked by owner):

1. **Streaming ingest**  — never read the full upload into RAM. We chain
   ``UploadFile.read(chunk)`` → ``hashlib.sha256().update`` → ``GridIn.write``
   so a 200 MB file uses ~1 MB of resident memory at any time.
2. **Race-safe dedup**   — the identity model exposes an ``identity_key``
   which today is the SHA-256 hex string, tomorrow (multi-tenant) becomes
   ``f"{tenant_id}:{sha256}"``. A unique index on ``identity_key`` in
   ``file_index`` collection provides atomic dedup: two concurrent
   uploads of the same content collapse into one GridFS object.
3. **Controlled retention** — a nightly application job walks
   ``file_index`` for entries older than ``NIVX_FILES_TTL_DAYS`` that are
   not pinned; deletes the GridFS object (metadata + chunks atomically);
   removes the index row. Naïve TTL on ``documents.files`` would leave
   orphaned chunks — deliberately avoided.
4. **Tenant-ready identity** — every ``file_index`` row carries a
   ``tenant_id`` column (defaults to ``"default"`` today). The unique
   index is ``(tenant_id, sha256)`` so the migration to multi-tenant
   requires zero schema change.

Public surface:

    class FileStore:
        async def ensure_indexes(): ...
        async def put(upload_file, *, uploaded_by, tenant_id="default") -> FileRecord
        async def open_read(file_id) -> GridOut     # streaming read
        async def metadata(file_id) -> FileRecord
        async def delete(file_id) -> bool           # controlled delete
        async def pin(file_id, case_id) -> None
        async def unpin(file_id, case_id) -> None
        async def sweep_expired(now=None) -> dict   # retention job

No filesystem paths are exposed to clients. Every operation is
auth-gated by the caller (``routers/files.py``).
"""
from __future__ import annotations
import asyncio
import hashlib
import mimetypes
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from typing import Optional

from bson import ObjectId
from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from pymongo import ASCENDING


# ─── Config ──────────────────────────────────────────────────────────
MAX_UPLOAD_BYTES = int(os.environ.get("NIVX_FILES_MAX_UPLOAD_BYTES",
                                      str(200 * 1024 * 1024)))
TTL_DAYS         = int(os.environ.get("NIVX_FILES_TTL_DAYS", "30"))
STREAM_CHUNK     = int(os.environ.get("NIVX_FILES_STREAM_CHUNK",
                                      str(1024 * 1024)))  # 1 MB


class FileStoreError(Exception):
    """Structured error surface. ``reason`` is a stable snake_case token."""
    def __init__(self, reason: str, detail: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}

    def to_dict(self) -> dict:
        return {"error": "file_store", "reason": self.reason, **self.detail}


@dataclass
class FileRecord:
    file_id:       str
    sha256:        str
    size:          int
    mime:          str
    filename:      str
    uploaded_by:   str
    uploaded_at:   str   # ISO-8601 UTC
    tenant_id:     str
    pinned_cases:  list[str]
    analysis_status: str  # "pending" | "processing" | "done" | "unsupported" | "failed"

    def public(self) -> dict:
        """Analyst-safe metadata (no internal paths)."""
        d = asdict(self)
        return d


# ─── Store ───────────────────────────────────────────────────────────
class FileStore:
    """GridFS-backed, streaming, race-safe file store."""

    def __init__(self, db):
        self.db     = db
        self.bucket = AsyncIOMotorGridFSBucket(db, bucket_name="nivx_files")
        self.index  = db.file_index

    # ── Indexes ──────────────────────────────────────────────────────
    async def ensure_indexes(self) -> None:
        # Race-safe dedup — atomic uniqueness across (tenant, sha256).
        await self.index.create_index(
            [("tenant_id", ASCENDING), ("sha256", ASCENDING)],
            unique=True, name="uniq_tenant_sha256",
        )
        # Retention sweep query
        await self.index.create_index(
            [("uploaded_at", ASCENDING)], name="uploaded_at_asc",
        )
        # file_id lookup
        await self.index.create_index(
            [("file_id", ASCENDING)], unique=True, name="uniq_file_id",
        )

    # ── Ingest ───────────────────────────────────────────────────────
    async def put(
        self,
        upload_file,
        *,
        uploaded_by: str,
        tenant_id: str = "default",
    ) -> FileRecord:
        """Streaming ingest with SHA-256 + race-safe dedup.

        Chunks are read from the FastAPI ``UploadFile``, hashed, and
        piped into a GridFS ``open_upload_stream``. If the resulting
        SHA-256 matches an existing tenant/sha256 pair, the freshly
        written GridFS object is DROPPED and the pre-existing file_id
        is returned. This is race-safe because the unique index on
        ``(tenant_id, sha256)`` will raise ``DuplicateKeyError`` on
        concurrent inserts.
        """
        filename = upload_file.filename or "unknown"
        mime = (
            upload_file.content_type
            or mimetypes.guess_type(filename)[0]
            or "application/octet-stream"
        )

        # Streaming write to GridFS
        stream = self.bucket.open_upload_stream(
            filename,
            metadata={"uploaded_by": uploaded_by, "tenant_id": tenant_id,
                      "mime": mime},
        )
        h = hashlib.sha256()
        size = 0
        try:
            while True:
                chunk = await upload_file.read(STREAM_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    # Abort the stream + delete partial GridFS object
                    await stream.abort()
                    raise FileStoreError(
                        "upload_too_large",
                        {"size": size, "max": MAX_UPLOAD_BYTES},
                    )
                h.update(chunk)
                await stream.write(chunk)
            await stream.close()
        except FileStoreError:
            raise
        except Exception as e:                                     # noqa: BLE001
            try:
                await stream.abort()
            except Exception:                                      # noqa: BLE001
                pass
            raise FileStoreError("upload_failed", {"parser": type(e).__name__})

        sha = h.hexdigest()
        gridfs_id = stream._id
        now = datetime.now(timezone.utc)

        # Race-safe dedup: try to insert index row; on DuplicateKeyError
        # the concurrent winner already wrote the row.
        file_id = _mk_file_id()
        row = {
            "file_id":         file_id,
            "sha256":          sha,
            "size":            size,
            "mime":            mime,
            "filename":        filename[:512],
            "uploaded_by":     uploaded_by,
            "uploaded_at":     now.isoformat(),
            "tenant_id":       tenant_id,
            "gridfs_id":       gridfs_id,
            "pinned_cases":    [],
            "analysis_status": "pending",
        }
        try:
            await self.index.insert_one(row)
        except Exception as e:                                     # noqa: BLE001
            # DuplicateKeyError — a concurrent (or earlier) upload of
            # the same content already claimed the identity. Drop OUR
            # GridFS object and return the existing record.
            try:
                await self.bucket.delete(gridfs_id)
            except Exception:                                      # noqa: BLE001
                pass
            existing = await self.index.find_one(
                {"tenant_id": tenant_id, "sha256": sha}
            )
            if not existing:
                # Truly unexpected — surface it.
                raise FileStoreError("dedup_index_race",
                                     {"parser": type(e).__name__})
            return _to_record(existing)

        return _to_record(row)

    # ── Read / metadata ──────────────────────────────────────────────
    async def open_read(self, file_id: str, *, tenant_id: str = "default"):
        row = await self.index.find_one({"file_id": file_id, "tenant_id": tenant_id})
        if not row:
            raise FileStoreError("not_found", {"file_id": file_id})
        return await self.bucket.open_download_stream(row["gridfs_id"])

    async def metadata(self, file_id: str, *, tenant_id: str = "default") -> FileRecord:
        row = await self.index.find_one({"file_id": file_id, "tenant_id": tenant_id})
        if not row:
            raise FileStoreError("not_found", {"file_id": file_id})
        return _to_record(row)

    # ── Retention (controlled delete) ────────────────────────────────
    async def delete(self, file_id: str, *, tenant_id: str = "default") -> bool:
        row = await self.index.find_one({"file_id": file_id, "tenant_id": tenant_id})
        if not row:
            return False
        try:
            await self.bucket.delete(row["gridfs_id"])
        except Exception:                                          # noqa: BLE001
            # Idempotent — GridFS object may already be gone from a
            # previous partial sweep. We still drop the index row.
            pass
        await self.index.delete_one({"_id": row["_id"]})
        return True

    async def pin(self, file_id: str, case_id: str, *,
                  tenant_id: str = "default") -> None:
        await self.index.update_one(
            {"file_id": file_id, "tenant_id": tenant_id},
            {"$addToSet": {"pinned_cases": case_id}},
        )

    async def unpin(self, file_id: str, case_id: str, *,
                    tenant_id: str = "default") -> None:
        await self.index.update_one(
            {"file_id": file_id, "tenant_id": tenant_id},
            {"$pull": {"pinned_cases": case_id}},
        )

    async def sweep_expired(self, now: Optional[datetime] = None) -> dict:
        """Application-controlled retention job.

        Deletes ``(GridFS object + index row)`` for entries older than
        TTL that carry an empty ``pinned_cases`` list. Idempotent by
        construction — safe to run concurrently at most once (no lock
        needed at current single-worker scale; add advisory lock when
        we go multi-worker in P5).
        """
        now = now or datetime.now(timezone.utc)
        cutoff_iso = (now - timedelta(days=TTL_DAYS)).isoformat()
        deleted, errors = 0, 0
        cursor = self.index.find({
            "uploaded_at": {"$lt": cutoff_iso},
            "pinned_cases": {"$in": [None, []]},
        })
        async for row in cursor:
            try:
                await self.bucket.delete(row["gridfs_id"])
            except Exception:                                      # noqa: BLE001
                errors += 1
                # Still remove the index row; a missing GridFS object
                # is a benign inconsistency we can safely converge.
            await self.index.delete_one({"_id": row["_id"]})
            deleted += 1
        return {"deleted": deleted, "errors": errors,
                "cutoff": cutoff_iso, "now": now.isoformat()}


# ─── helpers ─────────────────────────────────────────────────────────
def _mk_file_id() -> str:
    """Opaque file_id — no filesystem path, no ObjectId leakage."""
    import uuid
    return f"nvxf_{uuid.uuid4().hex}"


def _to_record(row: dict) -> FileRecord:
    return FileRecord(
        file_id         = row["file_id"],
        sha256          = row["sha256"],
        size            = row["size"],
        mime            = row["mime"],
        filename        = row["filename"],
        uploaded_by     = row.get("uploaded_by", ""),
        uploaded_at     = row["uploaded_at"],
        tenant_id       = row.get("tenant_id", "default"),
        pinned_cases    = list(row.get("pinned_cases") or []),
        analysis_status = row.get("analysis_status", "pending"),
    )
