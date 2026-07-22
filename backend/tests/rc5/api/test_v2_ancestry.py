"""tests/rc5/api/test_v2_ancestry.py · R1.2 Process Ancestry tests."""
from __future__ import annotations
import os
import pytest


@pytest.fixture(scope="module", autouse=True)
def _env_flags():
    os.environ.setdefault("NIVX_FLAG_TRAJECTORY_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_CASE_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_ADAPTERS", "shadow")


@pytest.mark.asyncio
async def test_ancestry_root_by_binary_name(_env_flags=None):
    """Endpoint accepts a bare binary name (`cmd.exe`) and resolves to bin:cmd.exe."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.routers.ancestry import process_ancestry

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]

    # Bypass require_admin — call the underlying function
    async def _call(iid):
        # patch _db module-level reference for this test invocation
        import v2.routers.ancestry as m
        real = m._db
        m._db = db
        try:
            return await process_ancestry(
                case_id="case_dfir_bumblebee_akira_2026",
                process_iid=iid,
                _={"email": "admin@nivxray.com"},  # bypass admin dep
            )
        finally:
            m._db = real

    r = await _call("cmd.exe")
    assert r["ok"] is True
    assert r["root"] == "bin:cmd.exe"
    assert r["root_label"] == "cmd.exe"
    assert r["stats"]["total_events"] >= 1
    assert any(n["role"] == "root" for n in r["nodes"])
    assert "cmd.exe" in {n["label"] for n in r["nodes"] if n["role"] == "root"}


@pytest.mark.asyncio
async def test_ancestry_missing_process_returns_404():
    from motor.motor_asyncio import AsyncIOMotorClient
    from fastapi import HTTPException
    from v2.routers.ancestry import process_ancestry
    import v2.routers.ancestry as m

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    real = m._db
    m._db = db
    try:
        with pytest.raises(HTTPException) as exc:
            await process_ancestry(
                case_id="case_dfir_bumblebee_akira_2026",
                process_iid="__nonexistent__.exe",
                _={"email": "admin@nivxray.com"},
            )
        assert exc.value.status_code == 404
    finally:
        m._db = real


@pytest.mark.asyncio
async def test_ancestry_events_returned_per_node():
    """Each node returned must have its events retrievable via r['events'][key]."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.routers.ancestry import process_ancestry
    import v2.routers.ancestry as m

    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    real = m._db
    m._db = db
    try:
        r = await process_ancestry(
            case_id="case_dfir_bumblebee_akira_2026",
            process_iid="cmd.exe",
            _={"email": "admin@nivxray.com"},
        )
    finally:
        m._db = real

    for node in r["nodes"]:
        assert node["key"] in r["events"], f"missing events for node {node['key']}"
        assert len(r["events"][node["key"]]) == node["event_count"]
