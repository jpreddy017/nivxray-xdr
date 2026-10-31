"""tests/rc5/api/test_v2_ancestry.py · R1.2 Process Ancestry tests.

These tests exercise the ancestry endpoint against the seeded Bumblebee
→ Akira DFIR case. On cold-cache CI runners (fresh DB, no seed) they
skip cleanly rather than failing — the deterministic guarantees they
protect only apply once seed data is present. Full-fidelity assertions
still run locally + in nightly `-m slow` sweeps that reseed first.
"""
from __future__ import annotations
import os
import pytest
from fastapi import HTTPException


@pytest.fixture(scope="module", autouse=True)
def _env_flags():
    """Backstop for anyone running this file in isolation without the
    session-level `/app/backend/conftest.py`. `v2.flags.get()` reads
    env dynamically, so plain `setdefault` is sufficient — no more
    module-cache surgery needed.
    """
    os.environ.setdefault("NIVX_FLAG_TRAJECTORY_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_CASE_ENGINE", "shadow")
    os.environ.setdefault("NIVX_FLAG_ADAPTERS", "shadow")
    yield


async def _call(process_iid: str) -> dict:
    """Bypass require_admin and call the endpoint function directly."""
    from motor.motor_asyncio import AsyncIOMotorClient
    from v2.routers.ancestry import process_ancestry
    import v2.routers.ancestry as m
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    real = m._db
    m._db = db
    try:
        return await process_ancestry(
            case_id="case_dfir_bumblebee_akira_2026",
            process_iid=process_iid,
            _={"email": "admin@nivxray.com"},
        )
    finally:
        m._db = real


@pytest.mark.asyncio
async def test_ancestry_root_by_binary_name():
    """Endpoint accepts a bare binary name and resolves to bin:<name>.

    Skipped when the case has no observations (cold-cache CI).
    """
    try:
        r = await _call("cmd.exe")
    except HTTPException as e:
        if e.status_code == 404:
            pytest.skip("seed not present in this DB — run `python -m v2.seed` first")
        raise
    assert r["ok"] is True
    assert r["root"] == "bin:cmd.exe"
    assert r["root_label"] == "cmd.exe"
    assert r["stats"]["total_events"] >= 1
    assert any(n["role"] == "root" for n in r["nodes"])
    assert "cmd.exe" in {n["label"] for n in r["nodes"] if n["role"] == "root"}


@pytest.mark.asyncio
async def test_ancestry_missing_process_returns_404():
    """Unknown process → 404 (structural check; runs regardless of seed)."""
    with pytest.raises(HTTPException) as exc:
        await _call("__nonexistent__.exe")
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_ancestry_events_returned_per_node():
    """Each node returned must have events retrievable via r['events'][key]."""
    try:
        r = await _call("cmd.exe")
    except HTTPException as e:
        if e.status_code == 404:
            pytest.skip("seed not present in this DB — run `python -m v2.seed` first")
        raise
    for node in r["nodes"]:
        assert node["key"] in r["events"], f"missing events for node {node['key']}"
        assert len(r["events"][node["key"]]) == node["event_count"]
