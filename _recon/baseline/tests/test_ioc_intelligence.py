"""
IOC Intelligence Engine · behavioural tests (2026-03-02)
─────────────────────────────────────────────────────────
Locks the deterministic contract:

  · Every card carries `consensus.verdict` (never crashes on empty
    provider responses).
  · Providers that fail auth degrade to `pending`, never damage the
    consensus verdict.
  · Cache hits are returned with `from_cache=True`.
"""
from __future__ import annotations
import asyncio

import pytest

from services.ioc_intelligence import enrich_ioc, enrich_iocs
from services.ioc_intelligence.cache import clear as cache_clear


@pytest.fixture(autouse=True)
def _clear_cache():
    cache_clear()
    yield
    cache_clear()


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro) \
        if not asyncio.get_event_loop().is_running() \
        else asyncio.run(coro)


def test_enrich_ioc_never_crashes_on_unknown_hash():
    card = asyncio.run(
        enrich_ioc("hash",
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    use_cache=False)
    )
    assert card.kind == "hash"
    assert card.consensus["verdict"] in ("unknown", "clean", "suspicious", "malicious")
    assert isinstance(card.consensus["confidence_percent"], int)
    assert isinstance(card.sources, list)
    # Sources include at least one provider result
    assert len(card.sources) >= 1


def test_enrich_ioc_pending_when_keys_missing():
    """With no keys configured, keyed providers must return `pending`
    — never a false `clean` verdict."""
    card = asyncio.run(
        enrich_ioc("ip", "8.8.8.8", use_cache=False)
    )
    # AbuseIPDB requires a key; must appear as pending in the sources
    ai = [s for s in card.sources if s["provider"] == "abuseipdb"]
    assert ai, "abuseipdb provider must be consulted for an IP IOC"
    assert ai[0]["source"] in ("pending", "error")


def test_cache_hits_return_from_cache_true():
    v = "http://malicious.test/payload.exe"
    first = asyncio.run(enrich_ioc("url", v, use_cache=True))
    assert first.from_cache is False
    second = asyncio.run(enrich_ioc("url", v, use_cache=True))
    assert second.from_cache is True
    # Consensus verdict must be identical across the cache round-trip.
    assert first.consensus["verdict"] == second.consensus["verdict"]


def test_enrich_batch_runs_multiple():
    results = asyncio.run(enrich_iocs([
        {"kind": "hash",   "value": "abc" * 20},
        {"kind": "url",    "value": "http://malicious.test/a"},
        {"kind": "domain", "value": "evil.example.com"},
        {"kind": "ip",     "value": "1.2.3.4"},
    ], use_cache=False))
    assert len(results) == 4
    for r in results:
        assert r.consensus["verdict"] in ("unknown", "clean", "suspicious", "malicious")
        assert r.value
