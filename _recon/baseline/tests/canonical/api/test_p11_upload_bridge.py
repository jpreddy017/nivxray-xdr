"""P1.1 · Close-the-bridge · `/api/upload` FileStore integration.

Locks the additive contract change for the legacy Workspace upload:

* Response contract preserved (`filename`, `size`, `hashes`, `file_type`,
  `text`, `hex_dump`, `strings`, `content`, `archive_refused`).
* Additive fields present (`file_id`, `route`, `dedup`).
* Authoritative SHA-256 = ``hashes.sha256`` = ``FileStore.sha256``.
* Dedup: uploading the same bytes twice returns the same ``file_id``
  and ``dedup=True`` on the second call.
* Server-side upload cap (413 on oversize).
* P0 archive_guard behaviour unchanged (archive_refused surface).
* No filesystem path leakage anywhere in the response.
* Input-Router route decided by content magic (not filename alone).
"""
from __future__ import annotations
import hashlib
import io
import os
import uuid
import pytest
from fastapi.testclient import TestClient

from server import app

# Legacy contract keys — every one of these must remain in the response.
LEGACY_KEYS = {
    "filename", "size", "hashes", "file_type",
    "text", "hex_dump", "strings", "content", "archive_refused",
}
ADDITIVE_KEYS = {"file_id", "route", "dedup"}


@pytest.fixture(scope="session")
def client():
    """Session-scoped TestClient — the FastAPI shutdown handler closes
    the shared Motor client, so tearing down at module scope would
    invalidate the client for any subsequent module in the same xdist
    worker (see `test_p1_server_side_files.py::_fresh_store`).
    """
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def token(client):
    email = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
    pw = os.environ.get("ADMIN_PASSWORD", "ci-only-not-a-real-secret")
    r = client.post("/api/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _upload(client, token, name: str, content: bytes,
            mime: str = "text/plain"):
    return client.post(
        "/api/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (name, io.BytesIO(content), mime)},
    )


# ─── Contract preservation ──────────────────────────────────────────
def test_response_contract_preserved_prose(client, token):
    marker = uuid.uuid4().hex.encode()
    content = b"hello P1.1 " + marker + b"\npowershell -enc AAAA\n"
    r = _upload(client, token, "hello.txt", content)
    assert r.status_code == 200, r.text
    body = r.json()
    missing = LEGACY_KEYS - set(body.keys())
    assert not missing, f"legacy contract violated · missing: {missing}"
    added = ADDITIVE_KEYS - set(body.keys())
    assert not added, f"additive fields missing: {added}"
    unexpected = set(body.keys()) - (LEGACY_KEYS | ADDITIVE_KEYS)
    assert not unexpected, f"unexpected keys leaked: {unexpected}"


def test_sha256_authoritative_from_filestore(client, token):
    content = b"sha authority " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "s.txt", content)
    assert r.status_code == 200
    body = r.json()
    expected = hashlib.sha256(content).hexdigest()
    assert body["hashes"]["sha256"] == expected
    assert body["hashes"]["md5"] == hashlib.md5(content).hexdigest()
    assert body["hashes"]["sha1"] == hashlib.sha1(content).hexdigest()


def test_file_id_opaque_no_path_leak(client, token):
    content = b"opaque " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "op.txt", content)
    assert r.status_code == 200
    fid = r.json()["file_id"]
    assert isinstance(fid, str) and fid.startswith("nvxf_")
    for tok in ("/", "\\", "..", "tmp", "var", "app"):
        assert tok not in fid, f"path token '{tok}' leaked in file_id"


def test_route_from_content_magic_not_filename(client, token):
    """Content-magic beats filename — a PDF renamed to .txt still routes to pdf."""
    content = b"%PDF-1.4\n%fake pdf body " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "actually_pdf.txt", content, mime="text/plain")
    assert r.status_code == 200
    assert r.json()["route"] == "pdf"


def test_route_text_for_plain_prose(client, token):
    content = b"plain prose text " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "p.txt", content)
    assert r.status_code == 200
    assert r.json()["route"] == "text"


# ─── Dedup ──────────────────────────────────────────────────────────
def test_dedup_returns_same_file_id_and_flag(client, token):
    content = b"dedup content " + uuid.uuid4().hex.encode()
    a = _upload(client, token, "a.txt", content)
    b = _upload(client, token, "b.txt", content)
    assert a.status_code == 200 and b.status_code == 200
    assert a.json()["file_id"] == b.json()["file_id"], "dedup must reuse id"
    assert a.json()["dedup"] is False
    assert b.json()["dedup"] is True


# ─── P0 archive guard preserved ─────────────────────────────────────
def test_archive_refused_present_none_on_normal_upload(client, token):
    r = _upload(client, token, "x.txt", b"normal " + uuid.uuid4().hex.encode())
    assert r.status_code == 200
    body = r.json()
    assert "archive_refused" in body
    assert body["archive_refused"] is None


# ─── Content-cap not blown out by 200 MB storage cap ────────────────
def test_content_field_remains_capped(client, token):
    payload = ("A" * 100_000).encode()  # 100 KB payload
    r = _upload(client, token, "big.txt", payload)
    assert r.status_code == 200
    content = r.json()["content"]
    assert content is not None
    assert len(content) <= 64_500, f"content cap violated: {len(content)}"


# ─── Oversize protection surfaces via 413 ───────────────────────────
def test_oversize_upload_rejected(client, token):
    from services.files import store as _store_mod
    original = _store_mod.MAX_UPLOAD_BYTES
    _store_mod.MAX_UPLOAD_BYTES = 4096
    try:
        r = _upload(client, token, "over.bin", b"O" * 8192,
                    mime="application/octet-stream")
        assert r.status_code == 413, r.text
        detail = r.json().get("detail")
        assert isinstance(detail, dict)
        assert detail.get("reason") == "upload_too_large"
    finally:
        _store_mod.MAX_UPLOAD_BYTES = original


# ─── File_id resolvable via /api/files/{id}/metadata ────────────────
def test_file_id_resolvable_via_metadata_endpoint(client, token):
    content = b"resolve " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "r.txt", content)
    assert r.status_code == 200
    fid = r.json()["file_id"]
    m = client.get(f"/api/files/{fid}/metadata",
                   headers={"Authorization": f"Bearer {token}"})
    assert m.status_code == 200
    assert m.json()["file_id"] == fid
    assert m.json()["sha256"] == hashlib.sha256(content).hexdigest()


# ─── size correctness ───────────────────────────────────────────────
def test_size_matches_content_length(client, token):
    content = b"exact bytes " + uuid.uuid4().hex.encode()
    r = _upload(client, token, "sz.txt", content)
    assert r.status_code == 200
    assert r.json()["size"] == len(content)
