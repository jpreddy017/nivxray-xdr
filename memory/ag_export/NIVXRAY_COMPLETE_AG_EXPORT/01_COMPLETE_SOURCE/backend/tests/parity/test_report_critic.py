"""Report Critic tests — GAP 1 · 5 · 6 · 8."""
from __future__ import annotations

import pytest

from nivxforge.investigation.customer_report import compose_customer_report
from nivxforge.investigation.report_critic import critique, PERSONA_CONTRACTS


def _cio_full():
    """CIO with every canonical field populated."""
    return {
        "verdict": {"label": "Malicious", "confidence_pct": 100,
                    "reason": "test", "escalation_rule": "esc-lolbin"},
        "truth": {
            "findings": [
                {"id": "F1", "title": "PowerShell downloader observed",
                 "severity": "high", "detail": "Encoded command with network intent."},
            ],
            "recommendations": [
                {"id": "R1", "action": "contain", "priority": "p0",
                 "detail": "Isolate endpoint."},
            ],
        },
        "evidence_graph": {
            "nodes": [
                {"id": "L", "kind": "lolbin", "label": "powershell",
                 "attrs": {"binary": "powershell.exe", "techniques": ["T1059.001"]}},
                {"id": "T", "kind": "mitre_technique", "label": "PowerShell",
                 "attrs": {"technique_id": "T1059.001", "tactic": "Execution"}},
            ],
            "edges": [],
        },
        "metadata": {
            "iocs": {"urls": ["https://malicious.example/p.ps1"],
                     "sha256": ["a" * 64]},
            "osint": {"live": {"domains": [{"URLScan": {"total": 42}}]}},
            "timeline": [{"timestamp": "2026-02-02T09:00:00Z", "label": "First execution"}],
        },
        "entities": {"hosts": ["AZG51-CHECKIN-1"], "users": ["dtwarren"]},
    }


def _cio_minimal():
    """CIO with only verdict + one MITRE. Every other section should
    be classified as empty by the critic."""
    return {
        "verdict": {"label": "Suspicious", "confidence_pct": 55, "reason": "test"},
        "truth": {"findings": [], "recommendations": []},
        "evidence_graph": {
            "nodes": [
                {"id": "T", "kind": "mitre_technique", "label": "PowerShell",
                 "attrs": {"technique_id": "T1059.001", "tactic": "Execution"}},
            ],
            "edges": [],
        },
        "metadata": {},
        "entities": {},
    }


def test_critic_passes_a_complete_report():
    """A CIO with every canonical field populated must produce a
    report that passes every critic gate."""
    cio = _cio_full()
    report = compose_customer_report(cio, persona="customer")
    result = critique(report, cio)
    assert result.passed, f"critic issues: {[i.__dict__ for i in result.issues]}"
    assert result.score >= 85, f"score too low: {result.score}"


def test_critic_flags_missing_field_when_cio_carries_it():
    """If we hand-craft a report that leaves out a CIO field, the
    critic must flag it as `missing-cio-field-in-report`."""
    cio = _cio_full()
    report = compose_customer_report(cio, persona="customer")
    # Strip the host from every section to fake a bug.
    for s in report.sections:
        s.body = s.body.replace("AZG51-CHECKIN-1", "[REDACTED]")
    result = critique(report, cio)
    codes = [i.code for i in result.issues]
    assert "missing-cio-field-in-report" in codes


def test_critic_marks_empty_sections_for_drop():
    """A minimal CIO should trigger `drop-empty-section` for the
    sections that don't have data."""
    cio = _cio_minimal()
    report = compose_customer_report(cio, persona="customer")
    result = critique(report, cio)
    drop_titles = set(result.dropped_sections)
    for expected_drop in ("Affected Hosts", "Users", "File Hashes", "IOCs",
                          "Threat Intelligence", "Timeline"):
        assert expected_drop in drop_titles, f"expected {expected_drop} dropped, got {drop_titles}"


def test_threat_hunt_persona_must_contain_mitre_and_timeline():
    cio = _cio_full()
    report = compose_customer_report(cio, persona="threat_hunt")
    result = critique(report, cio)
    codes = [i.code for i in result.issues]
    # The full CIO has both — should pass.
    assert "persona-missing-required" not in codes, [i.__dict__ for i in result.issues]


def test_customer_persona_blocks_decoder_telemetry_terms():
    """P0.3 · The customer persona blocks *decoder-internal telemetry*
    (Layer 0, ps-encodedcommand, etc.) but NOT legitimate evidence
    identifiers like `IEX` or `Base64` — those are analyst-relevant
    and MUST appear in the customer report so the customer can see
    the concrete indicators tied to the verdict.
    """
    cio = _cio_full()
    report = compose_customer_report(cio, persona="customer")
    # Simulate a regression by injecting a genuine forbidden term
    # (decoder pipeline telemetry) into a section body.
    report.sections[0].body += " (recovered at Layer 0 via ps-encodedcommand)"
    result = critique(report, cio)
    codes = [i.code for i in result.issues]
    assert "persona-forbidden-term" in codes, f"expected persona-forbidden-term in {codes}"
    assert not result.passed


def test_customer_persona_allows_legitimate_evidence_identifiers():
    """P0.3 · `IEX`, `Base64` (in MITRE names), PowerShell cmdlets and
    similar identifiers are LEGITIMATE evidence the customer should
    see — the critic must NOT flag them."""
    cio = _cio_full()
    report = compose_customer_report(cio, persona="customer")
    report.sections[0].body += (
        " Attacker used IEX to invoke a payload matching MITRE "
        "T1027.010 Command Obfuscation: Base64/Encoded Command."
    )
    result = critique(report, cio)
    codes = [i.code for i in result.issues]
    assert "persona-forbidden-term" not in codes, (
        f"IEX and Base64 must NOT trigger forbidden-term: {codes}"
    )


def test_critic_result_serialises_to_dict():
    cio = _cio_full()
    report = compose_customer_report(cio, persona="customer")
    result = critique(report, cio)
    d = result.to_dict()
    for k in ("passed", "score", "persona", "issues", "coverage",
              "dropped_sections", "kept_sections"):
        assert k in d
