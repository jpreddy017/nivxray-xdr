"""T1-C · Prod-mode ``build_session`` envelope golden.

Freezes the shape of ``services.session.adapter.build_session()``
for a known deterministic SSOT payload.  Volatile fields (session_id,
created_at, narrative timestamps) are scrubbed by the harness.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


def _fixture_ssot():
    """Deterministic minimal SSOT payload sufficient to exercise every
    branch of ``build_session`` (understanding, acquired doc, incident,
    inputs promotion, summary narrative)."""
    return {
        "input": {"raw": "https://test.example.gov/advisory/t1c"},
        "understanding": {
            "input_type": "threat_report_url",
            "label": "Threat Report URL",
            "confidence": 0.9,
        },
        "document_profile": {
            "vendor": "Test Vendor",
            "title": "Test Advisory",
        },
        "acquired_document": {
            "ok": True,
            "url": "https://test.example.gov/advisory/t1c",
            "final_url": "https://test.example.gov/advisory/t1c",
            "sitename": "example.gov",
            "title": "Test Advisory",
            "fetched_bytes": 42_000,
            "duration_ms": 800,
            "engine": "trafilatura",
            "source_kind": "Static article",
            "fallback_chain": ["trafilatura"],
        },
        "report_extraction": {
            "commands": [
                {"normalized_command": "powershell -enc AAAA",
                 "mitre": ["T1059.001"], "tactic": "execution"},
            ],
            "mitre_techniques": [
                {"id": "T1059.001", "name": "PowerShell",
                 "tactic": "execution"},
            ],
            "threat_actors": [{"name": "TestActor"}],
            "malware_families": [{"name": "TestFamily"}],
            "behaviors": [{"name": "downloader"}],
            "body_artifacts": [{"type": "ip", "value": "198.51.100.20"}],
            "iocs": {"ips": ["198.51.100.20"]},
        },
        "incident": {
            "id": "incident:root",
            "title": "Test Advisory",
            "objective": "Encoded PowerShell",
            "severity": "medium",
            "confidence": 60,
            "readiness": {"overall_percent": 70},
        },
    }


def test_t1_c_prod_session_envelope_golden():
    from services.session.adapter import build_session
    ssot = _fixture_ssot()
    envelope = build_session(
        input_text="https://test.example.gov/advisory/t1c",
        ssot=ssot,
        session_id="ses-t1c-deterministic",
    )

    # Keep only the frozen contract keys – narrative may vary in
    # non-contract details across future improvements.
    frozen = {k: envelope.get(k) for k in (
        "schema", "original_input", "document_profile",
        "acquired_document", "investigation_inputs",
        "incident", "readiness", "summary",
    )}
    compare_or_capture("t1_c_prod_session_envelope", frozen)
