"""tests/rc5/api/test_v2_ingest.py · R2.5 Ingest Adapter tests.

Structural tests only — no seed dependency. Each adapter is called via
requests directly through the ASGI app (skip on cold-cache DBs is not
needed because these tests INGEST data as part of the flow).
"""
from __future__ import annotations
import json
import os
import pytest


@pytest.fixture(scope="module", autouse=True)
def _env_flags():
    """Enable v2 flags AND force-refresh the FLAGS snapshot (see
    test_v2_ancestry._env_flags for rationale)."""
    os.environ["NIVX_FLAG_TRAJECTORY_ENGINE"] = "shadow"
    os.environ["NIVX_FLAG_CASE_ENGINE"] = "shadow"
    os.environ["NIVX_FLAG_ADAPTERS"] = "shadow"
    import v2.flags as _f
    for _n in _f.FLAG_NAMES:
        _f.FLAGS[_n] = _f._read(_n)
    yield


async def _call(endpoint: str, payload, content_type: str = "application/json"):
    """Invoke an ingest endpoint bypassing require_admin."""
    from motor.motor_asyncio import AsyncIOMotorClient
    import v2.routers.ingest as m
    client = AsyncIOMotorClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    real = m._db
    m._db = db
    try:
        if endpoint == "json":
            return await m.ingest_json(payload=payload, case_id="ingest-test-json",
                                       _={"email": "admin@nivxray.com"})
        if endpoint == "syslog":
            return await m.ingest_syslog(payload=payload, case_id="ingest-test-syslog",
                                         _={"email": "admin@nivxray.com"})
        if endpoint == "csv":
            return await m.ingest_csv(payload=payload, case_id="ingest-test-csv",
                                      _={"email": "admin@nivxray.com"})
        if endpoint == "webhook":
            return await m.ingest_webhook(payload=payload, case_id="ingest-test-webhook",
                                          _={"email": "admin@nivxray.com"})
        if endpoint == "ndjson":
            return await m.ingest_ndjson(payload=payload, case_id="ingest-test-ndjson",
                                         _={"email": "admin@nivxray.com"})
        raise ValueError(f"unknown endpoint {endpoint}")
    finally:
        m._db = real


@pytest.mark.asyncio
async def test_ingest_json_single_record():
    r = await _call("json", {"command": "powershell -enc BASE64HERE"})
    assert r["ok"] and r["adapter"] == "json"
    assert r["ingested_records"] == 1
    assert r["observations_created"] >= 1


@pytest.mark.asyncio
async def test_ingest_json_list_of_events():
    r = await _call("json", {"events": [
        {"command": "cmd /c whoami"},
        {"cmdline":  "net user backup_admin /add"},
        {"text":     "wbadmin start backup"},
    ]})
    assert r["ingested_records"] == 3
    assert r["observations_created"] >= 3


@pytest.mark.asyncio
async def test_ingest_ndjson():
    payload = "\n".join([
        json.dumps({"cmdline": "cmd /c systeminfo"}),
        json.dumps({"cmdline": "cmd /c whoami /all"}),
        "",  # blank line ignored
        json.dumps({"cmdline": "nltest /dclist:"}),
    ])
    r = await _call("ndjson", payload)
    assert r["ingested_records"] == 3


@pytest.mark.asyncio
async def test_ingest_syslog():
    payload = "\n".join([
        "<134>1 2026-02-22T13:04:54Z host proc 1 - - cmd /c whoami",
        "<134>1 2026-02-22T13:04:55Z host proc 1 - - powershell -enc AAAA",
        "<134>Feb 22 13:04:56 host proc: cmd /c systeminfo",
    ])
    r = await _call("syslog", payload)
    assert r["ingested_records"] == 3


@pytest.mark.asyncio
async def test_ingest_csv():
    payload = "command,case_id\n\"cmd /c whoami\",csv-case-42\n\"powershell -enc XYZ\",csv-case-42\n"
    r = await _call("csv", payload)
    assert r["ingested_records"] == 2
    assert r["case_id"] == "csv-case-42"  # override applied


@pytest.mark.asyncio
async def test_ingest_webhook_wrapper():
    r = await _call("webhook", {"events": [{"command": "cmd /c whoami"}]})
    assert r["adapter"] == "webhook"
    assert r["ingested_records"] == 1
