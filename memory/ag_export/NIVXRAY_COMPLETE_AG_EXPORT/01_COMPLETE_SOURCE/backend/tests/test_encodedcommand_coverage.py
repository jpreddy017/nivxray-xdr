"""Regression tests — MITRE / LOLBAS / YARA must fire on `-EncodedCommand`
(the long-form flag) as well as the short forms `-e`, `-ec`, `-enc`, `-encoded`.

Bug context: The original regexes only matched `-e(nc)?\\s` — requiring a
whitespace right after the flag. `powershell.exe -EncodedCommand XXX` has
no whitespace after `-Enc` (only after `-EncodedCommand`), so all matchers
missed the classic MSF one-liner.
"""
from __future__ import annotations
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from operations import mitre_map, yara_lite_scan, risk_score, extract_iocs
from lolbas import scan_lolbas


_PS_PAYLOAD_BENIGN = (
    "powershell.exe -EncodedCommand "
    "RwBlAHQALQBQAHIAbwBjAGUAcwBzACAAfAAgAFMAZQBsAGUAYwB0AC0ATwBiAGoAZQBjAHQAIABQ"
    "AHIAbwBjAGUAcwBzAE4AYQBtAGUALAAgAEkAZAAgAC0ARgBpAHIAcwB0ACAANQA="
)
# ↑ decodes to `Get-Process | Select-Object ProcessName, Id -First 5`


def test_mitre_matches_long_form_encoded_command():
    hits = mitre_map(_PS_PAYLOAD_BENIGN)
    ids = [h["id"] for h in hits]
    # T1059.001 (PowerShell) + T1027.010 (Encoded/Obfuscated Command) MUST fire
    assert "T1059.001" in ids, f"PowerShell MITRE tag missing: {ids}"
    assert "T1027.010" in ids, f"Command Obfuscation MITRE tag missing: {ids}"


def test_mitre_matches_short_form_encoded_command():
    """Regression: short forms `-e`, `-ec`, `-enc` must still fire."""
    for flag in ("-e ", "-ec ", "-enc ", "-encoded "):
        ids = [h["id"] for h in mitre_map(f"powershell.exe {flag}RwBl")]
        assert "T1059.001" in ids, f"regression on short flag {flag!r}: {ids}"


def test_mitre_matches_get_process_discovery():
    """The decoded body `Get-Process | Select-Object ...` maps to T1057."""
    ids = [h["id"] for h in mitre_map("Get-Process | Select-Object ProcessName, Id -First 5")]
    assert "T1057" in ids, f"Process Discovery MITRE tag missing: {ids}"


def test_lolbas_matches_long_form_encoded_command():
    hits = scan_lolbas(_PS_PAYLOAD_BENIGN)
    bins = [h.get("binary", "") for h in hits]
    assert "powershell.exe" in bins, f"powershell.exe LOLBIN missing: {bins}"


def test_yara_matches_long_form_encoded_command():
    hits = yara_lite_scan(_PS_PAYLOAD_BENIGN)
    rules = [h["rule"] for h in hits]
    assert "PS_EncodedCommand" in rules, f"YARA rule missing: {rules}"


def test_full_analysis_produces_populated_panels():
    """The full user-reported flow: MITRE + LOLBAS + YARA all populate,
    and risk score is well above 15 (i.e. NOT 'Benign')."""
    text = _PS_PAYLOAD_BENIGN + "\nGet-Process | Select-Object ProcessName, Id -First 5"
    mitre = mitre_map(text)
    yara = yara_lite_scan(text)
    lolbas = scan_lolbas(text)
    iocs = extract_iocs(text)
    risk = risk_score(mitre, yara, iocs)

    assert len(mitre) >= 2, f"expected ≥2 MITRE hits, got {len(mitre)}: {mitre}"
    assert len(lolbas) >= 1, f"expected ≥1 LOLBAS hit, got {lolbas}"
    assert len(yara) >= 1, f"expected ≥1 YARA hit, got {yara}"
    assert risk["score"] > 30, f"expected non-benign score, got {risk}"
