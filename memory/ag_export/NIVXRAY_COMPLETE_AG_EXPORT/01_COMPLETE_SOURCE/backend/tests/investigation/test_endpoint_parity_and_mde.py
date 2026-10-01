"""Integration tests · endpoint parity + Microsoft Defender pipeline.

Locks in two operator-facing invariants:

  1. **BUG-P4-02 · Investigation pipeline divergence** — `/decode/smart`
     and `/v2/auto-investigate` MUST produce identical analyst
     narrative + Executive Summary for the same input.

  2. **Microsoft Defender for Endpoint** telemetry flows through the
     Phase 1 pipeline correctly, producing an analyst-style narrative
     that names the device, initiating process, threat family, and
     ATT&CK techniques.
"""
from __future__ import annotations

import json

import pytest

from nivxforge.cim.fact_substrate import from_analysis_result
from nivxforge.investigation.builder import build_cio
from nivxforge.investigation.pipeline.orchestrator import run_phase1
from nivxforge.investigation.pipeline.vendor_detection import Vendor
from nivxforge.investigation.summary_composer import compose_summary


MDE_SAMPLE = json.dumps({
    "AlertId": "da637-abc",
    "AlertTitle": "Suspicious command line launched cmd.exe",
    "AlertSeverity": "High",
    "Category": "Execution",
    "ThreatFamilyName": "Trojan:Win32/Emotet",
    "DeviceName": "FIN-LAPTOP-07",
    "DeviceId": "abc123def456",
    "AccountName": "jsmith",
    "AccountDomain": "CORP",
    "FileName": "invoice.doc.exe",
    "FolderPath": "C:\\Users\\jsmith\\Downloads",
    "SHA256": "f" * 64,
    "InitiatingProcessCommandLine": "\"cmd.exe\" /c powershell -nop -w hidden -c IEX",
    "InitiatingProcessFileName": "cmd.exe",
    "InitiatingProcessFolderPath": "C:\\Windows\\System32",
    "InitiatingProcessSHA256": "a" * 64,
    "RemoteUrl": "http://payload.example.net/stage1",
    "RemoteIP": "203.0.113.42",
    "MitreTechniques": ["T1204.002", "T1059.001"],
    "MitreTactics": ["Execution", "Initial Access"],
    "Timestamp": "2026-08-01T14:22:00Z",
    "RemediationStatus": "Blocked",
})


# ── Microsoft Defender · Phase 1 pipeline sanity ─────────────────────

def test_mde_vendor_detected():
    state = run_phase1(MDE_SAMPLE)
    assert state.vendor.vendor == Vendor.DEFENDER
    assert state.vendor.confidence >= 0.85
    assert state.cem.vendor_route == "microsoft_defender"


def test_mde_graph_carries_device_process_and_url():
    state = run_phase1(MDE_SAMPLE)
    kinds = {n.kind for n in state.graph.nodes}
    assert {"host", "user", "process", "command",
             "file", "hash", "url", "ip",
             "detection"}.issubset(kinds), sorted(kinds)


def test_mde_incident_narrative_names_defender_and_device():
    state = run_phase1(MDE_SAMPLE)
    from nivxforge.investigation.pipeline.narrative_engine import (
        compose_incident_narrative,
    )
    narr = compose_incident_narrative(state)
    body = narr.to_markdown()
    # Vendor must be named
    assert "Microsoft Defender" in body
    # Device identified
    assert "FIN-LAPTOP-07" in body
    # Threat family attribution present via Detection.threat_family
    assert "Trojan:Win32/Emotet" in body
    # ATT&CK techniques surfaced from raw.mitre_techniques
    assert "T1204.002" in body or "T1059.001" in body


# ── BUG-P4-02 · endpoint-parity regression ──────────────────────────

def _summary_for(endpoint: str, raw: str):
    """Mimic the router flow exactly: build a CIO from the analysis
    result, stash raw_input on metadata, invalidate phase1 caches,
    then recompose the summary. This is what BOTH routers now do —
    the test proves they converge on identical narratives."""
    fake_result = {"output": raw, "iocs": {}, "engine": "test"}
    cio_fs = from_analysis_result(
        fake_result, input_text=raw, source_endpoint=endpoint,
    )
    cio = build_cio(cio_fs)
    cio.metadata["raw_input"] = raw
    cio.metadata.pop("phase1_state", None)
    cio.metadata.pop("phase1_narrative", None)
    cio.summary = compose_summary(cio)
    return cio.summary


def test_decode_smart_and_auto_investigate_produce_identical_narrative():
    """BUG-P4-02 regression: `/decode/smart` and `/v2/auto-investigate`
    must produce identical `analyst_narrative` and identical
    `report_sections.what_happened` for the same input."""
    sample = MDE_SAMPLE
    s1 = _summary_for("/api/decode/smart", sample)
    s2 = _summary_for("/api/v2/auto-investigate", sample)

    assert s1.analyst_narrative == s2.analyst_narrative, (
        "analyst_narrative diverges between endpoints:\n"
        f"decode/smart:\n{s1.analyst_narrative[:400]}\n\n"
        f"auto-investigate:\n{s2.analyst_narrative[:400]}"
    )
    assert s1.report_sections.what_happened == s2.report_sections.what_happened
