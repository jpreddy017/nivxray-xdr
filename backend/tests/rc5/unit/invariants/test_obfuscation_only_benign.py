"""RC5 · Phase 9.5d hotfix · Obfuscation-only-Benign invariant.

Generic invariant test:
  "Obfuscation is evidence, not guilt. Multi-layer decoding that
   produces a benign plaintext must NEVER elevate verdict above Benign,
   regardless of chain length or which encodings were used."

Exercises the pure helper `rc22_adapter._apply_obfuscation_only_cap`
so no dependency on the outer orchestrator, no LLM keys, no network.
"""
from __future__ import annotations

import pytest

from rc22_adapter import _apply_obfuscation_only_cap


class _MockTech:
    def __init__(self, tid): self.technique_id = tid


class _MockLolbas:
    def __init__(self, name="regsvr32"): self.binary = name


class _MockTradecraft:
    def __init__(self, flag="amsi_bypass"): self.flag = flag


@pytest.mark.parametrize("chain_hint", ["1 layer", "2 layers", "5 layers",
                                          "10 layers", "20 layers"])
def test_obfuscation_only_caps_at_benign_regardless_of_chain_length(chain_hint):
    """Chain length alone must not elevate the verdict. If the legacy
    engine reported Suspicious/80 with T1027 as the sole signal, the
    cap must always produce Benign/0 regardless of how many decode
    layers were involved (chain_hint is informational only — the
    helper doesn't take chain length as input, which is exactly the
    point: chain length must never influence the verdict).
    """
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="suspicious",
        risk_score=80,
        mitre_list=[{"technique_id": "T1027"}],
        lolbas_list=[],
        tradecraft_list=[],
    )
    assert v.lower() == "benign", f"[{chain_hint}] expected Benign, got {v}"
    assert r == 0
    assert reason and "invariant" in reason.lower()
    assert "T1027" in reason or "obfuscation" in reason.lower()


def test_no_cap_when_lolbas_present():
    """LOLBAS hit is real evidence — do NOT cap."""
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="suspicious", risk_score=80,
        mitre_list=[{"technique_id": "T1027"}],
        lolbas_list=[_MockLolbas("regsvr32")],
        tradecraft_list=[],
    )
    assert v == "suspicious"
    assert r == 80
    assert reason is None


def test_no_cap_when_non_t1027_mitre_present():
    """Any non-T1027 technique = real semantic signal → do NOT cap."""
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="malicious", risk_score=90,
        mitre_list=[{"technique_id": "T1027"}, {"technique_id": "T1105"}],
        lolbas_list=[], tradecraft_list=[],
    )
    assert v == "malicious"
    assert r == 90
    assert reason is None


def test_no_cap_when_tradecraft_flag_present():
    """AMSI bypass / ETW disable / SBL disable / other tradecraft = do NOT cap."""
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="suspicious", risk_score=75,
        mitre_list=[{"technique_id": "T1027"}], lolbas_list=[],
        tradecraft_list=[_MockTradecraft("amsi_bypass")],
    )
    assert v == "suspicious"
    assert r == 75
    assert reason is None


def test_cap_uses_object_style_mitre_entries():
    """Callers pass MITRE entries as objects with `technique_id`
    attribute. The helper must handle both dict AND object shapes.
    """
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="suspicious", risk_score=80,
        mitre_list=[_MockTech("T1027")],
        lolbas_list=[], tradecraft_list=[],
    )
    assert v.lower() == "benign"
    assert r == 0
    assert reason is not None


def test_no_cap_when_verdict_already_benign():
    """If findings already say Benign, pass through unchanged (no
    reason attached because there was nothing to cap)."""
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="benign", risk_score=0,
        mitre_list=[{"technique_id": "T1027"}],
        lolbas_list=[], tradecraft_list=[],
    )
    assert v == "benign"
    assert r == 0
    assert reason is None


def test_empty_mitre_still_caps():
    """Verdict was escalated but even T1027 wasn't emitted — still cap
    since there's no evidence at all supporting the escalation."""
    v, r, reason = _apply_obfuscation_only_cap(
        verdict="suspicious", risk_score=50,
        mitre_list=[], lolbas_list=[], tradecraft_list=[],
    )
    assert v.lower() == "benign"
    assert r == 0
