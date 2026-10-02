import os

import pytest

from edr_trajectory import kushu_import as kx
from edr_trajectory import platform_seed as pls

pytestmark = pytest.mark.skipif(not os.environ.get("MONGO_URL"), reason="needs a local MongoDB (preview DB only)")
REF = 1_790_900_000_000


@pytest.fixture
async def dbs():
    from motor.motor_asyncio import AsyncIOMotorClient
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c["e3_pytest_platform"], c["e3_pytest_platform_stage"]
    await c.drop_database("e3_pytest_platform")
    await c.drop_database("e3_pytest_platform_stage")


async def test_linux_goes_through_e1_linux_path(dbs):
    db, stage = dbs
    out = await pls.seed_linux(db, stage, REF)
    assert out["observation_docs"] == out["projected_rows"] == out["stored_total"] > 100
    m = await kx.meta_for(db, pls.LNX["device"])
    assert m["source"] == "SYNTHETIC_E1_LINUX_PATH"
    page = await kx.trajectory(db, m, limit=4000)
    types = {e["event_type"] for e in page["events"]}
    assert {"process_create", "network_connect"} <= types
    assert any(e.get("image") == "/tmp/.cache/kworkerd" for e in page["events"])


async def test_mac_is_labelled_fixture_only(dbs):
    db, _ = dbs
    await pls.seed_mac(db, REF)
    m = await kx.meta_for(db, pls.MAC["device"])
    assert m["source"] == "FIXTURE_ONLY_NO_E1_MACOS_PARSER" and "no E1 macOS parser" in m["label"]
    page = await kx.trajectory(db, m, limit=100)
    assert any(e.get("file", "").endswith(".pack.gz_") for e in page["events"])
    assert any(e.get("e3_detection") for e in page["events"])
