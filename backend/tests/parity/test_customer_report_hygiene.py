"""Customer / Investigation Report hygiene tests.

Every Customer / Investigation / Threat-Hunt report MUST NOT mention
the internal decoder pipeline. This test enforces the contract by
composing reports from representative CIOs and searching for forbidden
terms.

Failure of ANY of these tests must block deployment.
"""
from __future__ import annotations

import re

import pytest

from nivxforge.investigation.customer_report import (
    FORBIDDEN_TERMS,
    CUSTOMER_LIKE_PERSONAS,
    compose_customer_report,
)


def _sample_cio_powershell_ioc() -> dict:
    """Canonical CIO that mirrors the live-verified PowerShell -enc payload."""
    return {
        "verdict": {
            "label": "Malicious",
            "confidence_pct": 100,
            "reason": "Test rationale",
            "escalation_rule": "esc-lolbin-network",
        },
        "truth": {
            "findings": [
                {"id": "F-001", "title": "PowerShell downloader observed",
                 "severity": "high", "detail": "Encoded PS command invokes WebClient.DownloadString."},
                {"id": "F-002", "title": "LOLBIN chain via powershell.exe",
                 "severity": "high", "detail": "Signed binary launches remote payload."},
            ],
            "recommendations": [
                {"id": "R-CONTAIN", "action": "contain", "priority": "p0",
                 "detail": "Isolate the endpoint from the network."},
                {"id": "R-HUNT", "action": "hunt", "priority": "p1",
                 "detail": "Sweep for related invocations across the fleet."},
            ],
        },
        "evidence_graph": {
            "nodes": [
                {"id": "L-1", "kind": "lolbin", "label": "powershell",
                 "attrs": {"binary": "powershell.exe", "techniques": ["T1059.001"]}},
                {"id": "T-1", "kind": "mitre_technique",
                 "label": "PowerShell",
                 "attrs": {"technique_id": "T1059.001", "tactic": "Execution"}},
                {"id": "T-2", "kind": "mitre_technique",
                 "label": "Ingress Tool Transfer",
                 "attrs": {"technique_id": "T1105", "tactic": "Command and Control"}},
            ],
            "edges": [],
        },
        "metadata": {
            "iocs": {"urls": ["https://malicious.com/p.ps1"], "domains": ["malicious.com"]},
            "osint": {"live": {"domains": [{"URLScan": {"total": 868, "malicious": 0}}]}},
        },
        "entities": {"hosts": ["AZG51-CHECKIN-1"], "users": ["dtwarren"]},
    }


@pytest.mark.parametrize("persona", CUSTOMER_LIKE_PERSONAS)
def test_report_contains_no_forbidden_terms(persona):
    """Customer / threat-hunt / forensic reports must never leak
    decoder-pipeline vocabulary into customer-facing surfaces."""
    cio = _sample_cio_powershell_ioc()
    report = compose_customer_report(cio, persona=persona)
    md = report.to_markdown()
    for term in FORBIDDEN_TERMS:
        assert not re.search(rf"\b{re.escape(term)}\b", md, flags=re.IGNORECASE), (
            f"[{persona}] Report contained forbidden decoder-telemetry term: {term!r}"
        )


def test_report_has_all_16_sections_in_order():
    cio = _sample_cio_powershell_ioc()
    report = compose_customer_report(cio, persona="customer")
    numbers = [s.number for s in report.sections]
    assert numbers == list(range(1, 17)), f"expected 1..16, got {numbers}"


def test_report_includes_required_fields_when_present():
    """Every field present in the CIO MUST appear in the report."""
    cio = _sample_cio_powershell_ioc()
    report = compose_customer_report(cio, persona="customer")
    md = report.to_markdown()
    # Host
    assert "AZG51-CHECKIN-1" in md
    # User
    assert "dtwarren" in md
    # Verdict
    assert "Malicious" in md
    # MITRE
    assert "T1059.001" in md and "T1105" in md
    # IOC
    assert "malicious.com" in md
    # Recommendation
    assert "contain" in md.lower()


def test_report_never_mentions_decoder_layers():
    """Explicit belt-and-suspenders check for the phrases the user flagged
    as customer-inappropriate."""
    cio = _sample_cio_powershell_ioc()
    report = compose_customer_report(cio, persona="customer")
    md = report.to_markdown().lower()
    for forbidden in ["layer 0", "layer 1", "layer 2", "url-decode",
                      "crypto-detect", "recovered payload", "operation history"]:
        assert forbidden not in md, f"customer report leaked {forbidden!r}"


def test_decoder_persona_can_still_talk_about_layers():
    """The 'decoder' persona is intentionally exempt from the forbidden-
    terms lint, since it exists precisely to describe pipeline mechanics."""
    cio = _sample_cio_powershell_ioc()
    # Compose without hygiene lint fires — this should not raise.
    report = compose_customer_report(cio, persona="decoder")
    assert report.persona == "decoder"
