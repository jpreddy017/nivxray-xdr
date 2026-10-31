"""Regression tests for the TI-HITS matching fix (Feb 2026).

Two behaviours must hold:

1. `lookup_ti_hits` returns URL → hostname fallback matches when the DB
   stores only the base domain but the payload only surfaces a full URL.
2. Extraction key names in the IOC dict match the keys `lookup_ti_hits`
   reads — regression against the earlier bug where the code queried
   the wrong Mongo key.
"""
from __future__ import annotations
import asyncio
from types import SimpleNamespace

import pytest


class _FakeCursor:
    def __init__(self, docs):
        self._docs = list(docs)

    def __aiter__(self):
        self._i = -1
        return self

    async def __anext__(self):
        self._i += 1
        if self._i >= len(self._docs):
            raise StopAsyncIteration
        return self._docs[self._i]


class _FakeIocs:
    def __init__(self, docs):
        self._docs = list(docs)
        self.calls = []

    def find(self, query, projection=None):
        self.calls.append(query)
        # Emulate the tiny subset of pymongo predicates our code uses:
        # {"value": {"$in": [...]}}  and
        # {"kind": "domain", "value": {"$in": [...]}}
        vals = query.get("value", {}).get("$in", [])
        kind = query.get("kind")
        matches = [
            d for d in self._docs
            if d.get("value") in vals and (kind is None or d.get("kind") == kind)
        ]
        return _FakeCursor(matches)


@pytest.mark.asyncio
async def test_url_hostname_fallback(monkeypatch):
    import analysis_core

    fake_iocs = _FakeIocs([
        {"kind": "domain", "value": "attacker.example",
         "source": "otx", "severity": "high"},
    ])
    monkeypatch.setattr(analysis_core, "db",
                        SimpleNamespace(iocs=fake_iocs))

    iocs = {
        # The URL string does NOT match anything in the DB, but the
        # hostname `attacker.example` DOES match.
        "urls": ["https://attacker.example/very/long/path?q=1"],
        # No domain surfaced by the extractor — this is the whole point
        # of the fallback.
        "domains": [],
    }
    hits = await analysis_core.lookup_ti_hits(iocs)
    assert len(hits) == 1
    assert hits[0]["kind"] == "domain"
    assert hits[0]["value"] == "attacker.example"
    assert (hits[0].get("extra") or {}).get("matched_via") == "url-hostname"


@pytest.mark.asyncio
async def test_exact_value_still_hits(monkeypatch):
    import analysis_core
    fake_iocs = _FakeIocs([
        {"kind": "ip", "value": "1.2.3.4", "source": "abuseipdb", "severity": "critical"},
        {"kind": "sha256",
         "value": "a" * 64, "source": "malwarebazaar", "severity": "high"},
    ])
    monkeypatch.setattr(analysis_core, "db",
                        SimpleNamespace(iocs=fake_iocs))
    iocs = {"urls": [], "ips": ["1.2.3.4"], "domains": [],
            "md5": [], "sha1": [], "sha256": ["a" * 64]}
    hits = await analysis_core.lookup_ti_hits(iocs)
    kinds = sorted(h["kind"] for h in hits)
    assert kinds == ["ip", "sha256"]


@pytest.mark.asyncio
async def test_empty_iocs_returns_empty(monkeypatch):
    import analysis_core
    monkeypatch.setattr(analysis_core, "db",
                        SimpleNamespace(iocs=_FakeIocs([])))
    hits = await analysis_core.lookup_ti_hits({})
    assert hits == []


@pytest.mark.asyncio
async def test_no_double_hit_when_url_and_domain_both_in_iocs(monkeypatch):
    """When both the domain AND a URL sharing its hostname are extracted,
    the fallback must not add a duplicate entry."""
    import analysis_core
    fake_iocs = _FakeIocs([
        {"kind": "domain", "value": "attacker.example",
         "source": "otx", "severity": "high"},
    ])
    monkeypatch.setattr(analysis_core, "db",
                        SimpleNamespace(iocs=fake_iocs))
    iocs = {"urls": ["https://attacker.example/x"],
            "domains": ["attacker.example"]}
    hits = await analysis_core.lookup_ti_hits(iocs)
    assert len(hits) == 1
