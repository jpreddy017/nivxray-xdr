"""
Round 20 · OSINT Enrichment Cache
─────────────────────────────────

Validates:
  * Read-through: fresh entry → cache_hit; stale entry → refresh.
  * Never fabricates: upstream failure → last-known with is_stale=True,
    OR honest 'unknown' when nothing was cached.
  * TTL per provider is honoured.
  * `summary()` returns honest counts per provider.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_osint_cache import (
    read, write, fetch, summary, ttl_for, COLLECTION,
    DEFAULT_TTL_S,
)


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


@pytest.fixture()
def indicator():
    return "test-indicator-" + uuid.uuid4().hex[:10]


# ── TTL config ─────────────────────────────────────────────────

def test_ttl_config_covers_locked_providers():
    for p in ("talos", "dshield", "abuseipdb", "virustotal",
                    "urlhaus", "urlscan", "threatfox", "malwarebazaar"):
        assert ttl_for(p) > 0
    # Unknown provider gets the default TTL.
    assert ttl_for("brand-new-provider") == DEFAULT_TTL_S


# ── Write/read + freshness ─────────────────────────────────────

def test_write_and_read_fresh_entry(loop, db, indicator):
    _run(loop, write(db, indicator, "talos", "clean",
                                detail={"note": "ok"}, score=5))
    r = _run(loop, read(db, indicator, "talos"))
    assert r is not None
    assert r["verdict"] == "clean"
    assert r["is_stale"] is False
    assert r["age_s"] >= 0


def test_read_missing_returns_none(loop, db):
    r = _run(loop, read(db, "never-written", "talos"))
    assert r is None


# ── Fetch: cache hit / refresh ─────────────────────────────────

def test_fetch_cache_hit_when_fresh(loop, db, indicator):
    _run(loop, write(db, indicator, "talos", "clean"))
    calls = []
    async def fake(ind, prov):
        calls.append((ind, prov))
        return {"verdict": "malicious"}   # would flip if called

    r = _run(loop, fetch(db, indicator, "talos", fake))
    assert r["source"] == "cache_hit"
    assert r["verdict"] == "clean"        # fetcher NOT called
    assert calls == []


def test_fetch_refresh_when_missing(loop, db, indicator):
    async def fake(ind, prov):
        return {"verdict": "suspicious", "score": 42,
                    "detail": {"note": "test"}}
    r = _run(loop, fetch(db, indicator, "talos", fake))
    assert r["source"] == "cache_refresh"
    assert r["verdict"] == "suspicious"
    assert r["is_stale"] is False


def test_fetch_refresh_when_stale(loop, db, indicator):
    """Force-stale by writing with fetched_at in the past."""
    stale_at = (datetime.now(timezone.utc)
                     - timedelta(seconds=ttl_for("talos") + 60)).isoformat()
    _run(loop, db[COLLECTION].update_one(
        {"id": f"talos::{indicator}"},
        {"$set": {"id":         f"talos::{indicator}",
                      "indicator": indicator,
                      "provider":  "talos",
                      "verdict":   "clean",
                      "fetched_at": stale_at,
                      "observed_at": stale_at,
                      "ttl_s":     ttl_for("talos")}},
        upsert=True))
    async def fake(ind, prov):
        return {"verdict": "malicious"}
    r = _run(loop, fetch(db, indicator, "talos", fake))
    assert r["source"] == "cache_refresh"
    assert r["verdict"] == "malicious"


# ── Honest failure ─────────────────────────────────────────────

def test_fetch_upstream_failure_falls_back_to_stale_never_fabricates(
        loop, db, indicator):
    """When upstream fails, cache returns the LAST KNOWN value with
    is_stale=True — never a fabricated success."""
    stale_at = (datetime.now(timezone.utc)
                     - timedelta(seconds=ttl_for("talos") + 60)).isoformat()
    _run(loop, db[COLLECTION].update_one(
        {"id": f"talos::{indicator}"},
        {"$set": {"id":         f"talos::{indicator}",
                      "indicator": indicator,
                      "provider":  "talos",
                      "verdict":   "clean",
                      "fetched_at": stale_at,
                      "observed_at": stale_at,
                      "ttl_s":     ttl_for("talos")}},
        upsert=True))
    async def broken(ind, prov):
        raise RuntimeError("upstream 503")
    r = _run(loop, fetch(db, indicator, "talos", broken))
    assert r["source"] == "cache_stale_after_upstream_failure"
    assert r["verdict"] == "clean"
    assert r["is_stale"] is True
    assert "upstream 503" in r["upstream_error"]


def test_fetch_no_cache_no_upstream_returns_honest_unknown(loop, db):
    async def broken(ind, prov):
        raise RuntimeError("upstream 503")
    r = _run(loop, fetch(db,
        "brand-new-" + uuid.uuid4().hex[:8], "talos", broken))
    assert r["source"] == "upstream_failure_no_cache"
    assert r["verdict"] == "unknown"
    assert r["is_stale"] is True


# ── Summary shape ──────────────────────────────────────────────

def test_summary_returns_provider_breakdown(loop, db):
    ind = "sum-" + uuid.uuid4().hex[:6]
    _run(loop, write(db, ind, "virustotal", "malicious"))
    s = _run(loop, summary(db))
    assert s["collection"] == COLLECTION
    assert s["total_entries"] > 0
    assert s["default_ttl_s"] == DEFAULT_TTL_S
    # Every configured provider has a TTL entry.
    for p in ("talos", "dshield", "virustotal", "urlhaus"):
        assert p in s["provider_ttl_s"]
