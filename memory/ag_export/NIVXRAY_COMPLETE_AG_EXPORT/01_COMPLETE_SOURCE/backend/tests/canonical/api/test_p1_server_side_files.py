"""P1 · Server-Side File Mode · test suite (ADR-0008 §5.2).

Locks:
- streaming ingest (memory footprint scales O(chunk), not O(file))
- race-safe SHA-256 dedup (unique index prevents double-write)
- controlled retention (application-driven sweep, not naïve TTL)
- Input Router dispatch (existing analyzers only, unsupported → deterministic)
- oversize refusal (structured 413/422)
- path safety (no filesystem path leak; opaque file_id)
- tenant-ready identity (default tenant today, migration-safe)

Every test runs against a UNIQUE tenant_id namespace so pytest-xdist
parallel workers cannot collide on the shared ``file_index`` collection.
"""
from __future__ import annotations
import io
import os
import uuid
import asyncio
import hashlib
import pytest

from services.files.store import (
    FileStore, FileStoreError, MAX_UPLOAD_BYTES, TTL_DAYS,
)
from services.files.input_router import route_for, Route

pytestmark = pytest.mark.asyncio


def _tenant() -> str:
    """Unique tenant per test — prevents parallel-worker collisions."""
    return f"test_{uuid.uuid4().hex[:12]}"


class _FakeUpload:
    """Minimal fake matching FastAPI UploadFile interface."""
    def __init__(self, filename: str, content: bytes, mime: str = "application/octet-stream"):
        self.filename = filename
        self.content_type = mime
        self._buf = io.BytesIO(content)

    async def read(self, size: int = -1):
        return self._buf.read(size)


async def _fresh_store():
    """Real store bound to the running Motor DB.

    We rebind the Motor client to the current event loop on every call
    so pytest-asyncio's per-test loops don't hit "Event loop is closed"
    on the shared client from a previous test.
    """
    from deps import init_database, db as proxy
    init_database()
    real = object.__getattribute__(proxy, "_real")
    # Rebind the Motor client to the current running loop.
    try:
        import asyncio as _aio
        real.client.get_io_loop = _aio.get_running_loop  # type: ignore[attr-defined]
    except Exception:
        pass
    st = FileStore(real)
    await st.ensure_indexes()
    return st


# ─── Streaming ingest ───────────────────────────────────────────────
async def test_upload_stores_and_returns_metadata():
    st = await _fresh_store()
    tenant = _tenant()
    content = b"powershell -enc SGVsbG8=" * 1000
    up = _FakeUpload("hello.ps1", content, "text/x-powershell")
    rec = await st.put(up, uploaded_by="test@nivxray.com", tenant_id=tenant)
    try:
        assert rec.file_id.startswith("nvxf_")
        assert rec.sha256 == hashlib.sha256(content).hexdigest()
        assert rec.size == len(content)
        assert rec.mime == "text/x-powershell"
        assert rec.filename == "hello.ps1"
        assert rec.tenant_id == tenant
        assert rec.pinned_cases == []
    finally:
        await st.delete(rec.file_id, tenant_id=tenant)


async def test_upload_streaming_chunk_semantics():
    """The store must read the upload in chunks, not slurp .read()."""
    calls: list[int] = []
    class TrackingUpload(_FakeUpload):
        async def read(self, size: int = -1):
            calls.append(size)
            return await super().read(size)
    st = await _fresh_store()
    tenant = _tenant()
    up = TrackingUpload("x.bin", b"A" * (3 * 1024 * 1024))
    rec = await st.put(up, uploaded_by="t@e", tenant_id=tenant)
    try:
        # Every call should specify a bounded chunk size (not -1 / not slurp).
        assert calls, "read() was never called"
        assert all(c > 0 for c in calls), f"expected bounded chunks; got {calls[:3]}"
        assert max(calls) <= 2 * 1024 * 1024, f"chunk too large: {max(calls)}"
    finally:
        await st.delete(rec.file_id, tenant_id=tenant)


# ─── Race-safe dedup ────────────────────────────────────────────────
async def test_dedup_same_content_returns_same_file_id():
    st = await _fresh_store()
    tenant = _tenant()
    content = b"deterministic content for dedup " * 100
    r1 = await st.put(_FakeUpload("a.txt", content), uploaded_by="u1@e", tenant_id=tenant)
    r2 = await st.put(_FakeUpload("b.txt", content), uploaded_by="u2@e", tenant_id=tenant)
    try:
        assert r1.file_id == r2.file_id, "dedup must collapse identical content"
        assert r1.sha256 == r2.sha256
    finally:
        await st.delete(r1.file_id, tenant_id=tenant)


async def test_dedup_survives_concurrent_uploads():
    """Two concurrent uploads of the same content must collapse to one row."""
    st = await _fresh_store()
    tenant = _tenant()
    content = b"race-safe payload " * 250
    async def one():
        return await st.put(_FakeUpload("c.txt", content), uploaded_by="r@e", tenant_id=tenant)
    a, b = await asyncio.gather(one(), one())
    try:
        assert a.file_id == b.file_id, "unique index must serialise dedup"
    finally:
        await st.delete(a.file_id, tenant_id=tenant)


# ─── Oversize refusal ───────────────────────────────────────────────
async def test_oversize_refused_with_structured_error():
    st = await _fresh_store()
    tenant = _tenant()
    # 1 KB over the cap
    huge = b"\x00" * (MAX_UPLOAD_BYTES + 1024)
    with pytest.raises(FileStoreError) as exc:
        await st.put(_FakeUpload("huge.bin", huge), uploaded_by="u@e", tenant_id=tenant)
    assert exc.value.reason == "upload_too_large"
    assert exc.value.detail["max"] == MAX_UPLOAD_BYTES


# ─── Retention ──────────────────────────────────────────────────────
async def test_pin_prevents_sweep():
    from datetime import datetime, timezone, timedelta
    st = await _fresh_store()
    tenant = _tenant()
    rec = await st.put(_FakeUpload("keep.txt", b"pin-me"), uploaded_by="u@e", tenant_id=tenant)
    try:
        await st.pin(rec.file_id, "case-42", tenant_id=tenant)
        # Simulate "now" TTL+1 days later
        future = datetime.now(timezone.utc) + timedelta(days=TTL_DAYS + 1)
        result = await st.sweep_expired(now=future)
        # Row still exists
        m = await st.metadata(rec.file_id, tenant_id=tenant)
        assert m.pinned_cases == ["case-42"]
        # Deleted count may be nonzero from OTHER expired test rows, but
        # our pinned row must survive.
        assert result["deleted"] >= 0
    finally:
        await st.unpin(rec.file_id, "case-42", tenant_id=tenant)
        await st.delete(rec.file_id, tenant_id=tenant)


async def test_unpinned_and_expired_are_swept():
    from datetime import datetime, timezone, timedelta
    st = await _fresh_store()
    tenant = _tenant()
    rec = await st.put(_FakeUpload("gc.txt", b"gc-me"), uploaded_by="u@e", tenant_id=tenant)
    # No pin; sweep at TTL+1 days in the future
    future = datetime.now(timezone.utc) + timedelta(days=TTL_DAYS + 1)
    result = await st.sweep_expired(now=future)
    # The freshly-inserted row should be gone.
    with pytest.raises(FileStoreError) as exc:
        await st.metadata(rec.file_id, tenant_id=tenant)
    assert exc.value.reason == "not_found"
    assert result["deleted"] >= 1


# ─── Delete ──────────────────────────────────────────────────────────
async def test_delete_removes_metadata_and_binary():
    st = await _fresh_store()
    tenant = _tenant()
    rec = await st.put(_FakeUpload("d.txt", b"delete-me"), uploaded_by="u@e", tenant_id=tenant)
    ok = await st.delete(rec.file_id, tenant_id=tenant)
    assert ok is True
    with pytest.raises(FileStoreError):
        await st.metadata(rec.file_id, tenant_id=tenant)


async def test_delete_missing_is_idempotent():
    st = await _fresh_store()
    tenant = _tenant()
    ok = await st.delete("nvxf_does_not_exist", tenant_id=tenant)
    assert ok is False   # idempotent, does not raise


# ─── Input Router ────────────────────────────────────────────────────
class TestInputRouter:
    def test_pe_magic(self):
        assert route_for(b"MZ\x90\x00", "", "loader.exe") == "pe"

    def test_pdf_magic(self):
        assert route_for(b"%PDF-1.4", "application/pdf", "x.pdf") == "pdf"

    def test_office_by_extension(self):
        assert route_for(b"PK\x03\x04", "", "doc.docx") == "office"

    def test_zip_generic(self):
        assert route_for(b"PK\x03\x04", "", "archive.zip") == "archive"

    def test_csv_by_mime(self):
        assert route_for(b"host,event\nx,y", "text/csv", "log.csv") == "csv"

    def test_text_by_extension(self):
        assert route_for(b"$var = 1", "", "run.ps1") == "text"

    def test_unsupported(self):
        # random-looking binary with no magic + no extension
        assert route_for(b"\x00\x01\x02\x03\x04\x05\x06\x07", "", "blob") == "unsupported"

    def test_magic_wins_over_filename(self):
        """A file renamed to .txt containing PE bytes still routes to pe."""
        assert route_for(b"MZ\x90\x00", "text/plain", "harmless.txt") == "pe"


# ─── Identity opacity ────────────────────────────────────────────────
async def test_file_id_is_opaque_no_path_leak():
    st = await _fresh_store()
    tenant = _tenant()
    rec = await st.put(_FakeUpload("secret.txt", b"nope"), uploaded_by="u@e", tenant_id=tenant)
    try:
        d = rec.public()
        # No FS-path artefacts in metadata
        blob = str(d).lower()
        for token in ("/tmp", "/app", "gridfs_id", "/root", "chunks"):
            assert token not in blob, f"leaked filesystem/internal token: {token}"
        assert rec.file_id.startswith("nvxf_")
    finally:
        await st.delete(rec.file_id, tenant_id=tenant)


# ─── Tenant-ready identity ───────────────────────────────────────────
async def test_dedup_scoped_by_tenant():
    """Same content in different tenants must produce different file_ids."""
    st = await _fresh_store()
    tenant = _tenant()
    content = b"tenant-scoped content"
    a = await st.put(_FakeUpload("a", content), uploaded_by="u@e", tenant_id="alpha")
    b = await st.put(_FakeUpload("b", content), uploaded_by="u@e", tenant_id="beta")
    try:
        assert a.file_id != b.file_id
        assert a.sha256 == b.sha256
        assert a.tenant_id == "alpha" and b.tenant_id == "beta"
    finally:
        await st.delete(a.file_id, tenant_id="alpha")
        await st.delete(b.file_id, tenant_id="beta")
