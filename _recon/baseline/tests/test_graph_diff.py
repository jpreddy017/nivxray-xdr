"""UAIE · Legacy-Adapter + Graph-Diff CI Gate.

Phase 3 unblock proof — both engines can now emit the canonical SSOT
shape and the deterministic graph-diff engine can compare them.

Run:  cd /app/backend && python -m pytest tests/test_graph_diff.py -v
"""
from __future__ import annotations

import os
import sys
import uuid

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.legacy_ssot_adapter import legacy_to_canonical, diff
from services.uaie.orchestrator          import Orchestrator
from services.uaie                       import plugins as _plugins_pkg
from services.uaie.ssot_projector        import project as _uaie_project


def _sample_uaie_ssot() -> dict:
    payload = (
        b"\xFC\xE8\x89\x00\x00\x00\x60wininet.dll\x00ws2_32.dll\x00"
        b"WSAStartup\x00socket\x00connect\x00InternetOpenA\x00"
        b"http://c2.example/beacon.php\x00149.28.81.19\x00" + b"P" * 256
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    return _uaie_project(orch.run(payload, root_type="shellcode_bytes"),
                         root_input="paste", root_output="paste")


def _sample_legacy_result(overrides: dict | None = None) -> dict:
    base = {
        "verdict_card": {"verdict": "Malicious", "confidence": 88, "family": "Cobalt Strike"},
        "analysis":     {"iocs": {"urls": ["http://c2.example/beacon.php"],
                                   "ips":  ["149.28.81.19"]},
                          "mitre": ["T1071.001", "T1105"]},
        "chain":        [{"op": "shellcode.analyzer"}],
        "decode_trace": [{"op": "shellcode_bytes"}],
        "reached_shellcode": True,
    }
    if overrides:
        base.update(overrides)
    return base


# ═════════════════════════════════════════════════════════════════════════
def test_legacy_to_canonical_shape():
    ssot = legacy_to_canonical(_sample_legacy_result())
    for k in ("verdict_card", "analysis", "mitre", "chain", "decode_trace",
              "source_engine", "reached_shellcode"):
        assert k in ssot
    assert ssot["source_engine"] == "legacy"


def test_legacy_to_canonical_handles_empty():
    ssot = legacy_to_canonical({})
    assert ssot["source_engine"] == "legacy"
    assert ssot["mitre"] == []
    assert ssot["chain"] == []


def test_diff_identical_ssots_report_full_match():
    legacy = legacy_to_canonical(_sample_legacy_result())
    d = diff(legacy, legacy)
    assert d["overall_match"] is True
    assert d["verdict_diff"]["match"] is True
    assert d["confidence_delta"] == 0
    assert d["mitre_delta"]["missing"] == []
    assert d["mitre_delta"]["extra"] == []
    assert d["ioc_delta"]["missing"] == []
    assert d["ioc_delta"]["extra"] == []


def test_diff_flags_missing_and_extra_iocs():
    legacy = legacy_to_canonical(_sample_legacy_result())
    uaie   = legacy_to_canonical(_sample_legacy_result({
        "analysis": {"iocs": {"urls": ["http://c2.example/beacon.php",
                                        "http://EXTRA.example/x"]},
                     "mitre": ["T1071.001"]},
    }))
    d = diff(legacy, uaie)
    assert d["overall_match"] is False
    extra_urls = {row["value"] for row in d["ioc_delta"]["extra"] if row["kind"] == "urls"}
    assert "http://EXTRA.example/x" in extra_urls
    # UAIE is missing the ips['149.28.81.19'] we had on legacy
    missing_ips = {row["value"] for row in d["ioc_delta"]["missing"] if row["kind"] == "ips"}
    assert "149.28.81.19" in missing_ips


def test_diff_verdict_mismatch():
    legacy = legacy_to_canonical(_sample_legacy_result())
    uaie   = legacy_to_canonical(_sample_legacy_result({
        "verdict_card": {"verdict": "Suspicious", "confidence": 50},
    }))
    d = diff(legacy, uaie)
    assert d["verdict_diff"]["match"] is False
    assert d["confidence_delta"] > 0


def test_diff_reports_decode_trace_overlap():
    legacy = legacy_to_canonical({
        "decode_trace": [{"op": "base64.bare"}, {"op": "gzip.inflate"}],
    })
    uaie = legacy_to_canonical({
        "decode_trace": [{"op": "base64.bare"}, {"op": "shellcode.analyzer"}],
    })
    d = diff(legacy, uaie)
    assert d["decode_trace_delta"]["common"] == ["base64.bare"]
    assert "gzip.inflate" in d["decode_trace_delta"]["legacy_ops"]
    assert "shellcode.analyzer" in d["decode_trace_delta"]["uaie_ops"]


def test_uaie_ssot_and_legacy_ssot_have_same_diffable_shape():
    """The critical Phase 3 pre-condition: both engines emit an SSOT
    that ``diff()`` can consume without raising."""
    uaie  = _sample_uaie_ssot()
    lg    = legacy_to_canonical(_sample_legacy_result())
    d = diff(lg, uaie)   # must run without exception
    assert "verdict_diff" in d
    assert "overall_match" in d


def test_diff_is_pure_function():
    legacy = legacy_to_canonical(_sample_legacy_result())
    uaie   = _sample_uaie_ssot()
    d1 = diff(legacy, uaie)
    d2 = diff(legacy, uaie)
    assert d1 == d2, "diff must be deterministic"
