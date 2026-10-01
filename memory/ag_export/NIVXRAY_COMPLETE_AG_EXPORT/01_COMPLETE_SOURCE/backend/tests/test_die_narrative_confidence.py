"""
Investigation Confidence + Deterministic Narrative tests
(Phase B.4 + B.6 · 2026-02-16 evening)
"""
from services.die.api import analyze
from services.die.confidence import score_investigation, DIMENSIONS
from services.die.narrative import generate_report


CHAIN = ('whoami & hostname & vssadmin delete shadows /all /quiet '
         '& schtasks /create /tn X /tr y.exe /sc onlogon')


def test_confidence_returns_all_eight_dimensions():
    env = analyze(CHAIN)
    conf = score_investigation(env)
    names = [d["name"] for d in conf["dimensions"]]
    assert names == DIMENSIONS


def test_confidence_bucketing():
    env = analyze(CHAIN)
    conf = score_investigation(env)
    for d in conf["dimensions"]:
        assert 0 <= d["score"] <= 100
        assert d["bucket"] in ("High", "Moderate", "Requires validation")


def test_confidence_deterministic():
    a = score_investigation(analyze(CHAIN))
    b = score_investigation(analyze(CHAIN))
    assert a == b


def test_report_has_twelve_sections_in_order():
    env = analyze(CHAIN)
    rep = generate_report(env, case_id="t", input_preview=CHAIN)
    titles = [s["title"] for s in rep["sections"]]
    assert titles == [
        "Executive Summary","Overall Assessment","Behavior Summary",
        "Attack Story","Recovered Artifacts","Technical Findings",
        "MITRE Coverage","Attack Intent","Evidence Summary",
        "Detection Opportunities","Recommendations","Confidence Summary",
    ]


def test_report_confidence_per_section():
    env = analyze(CHAIN)
    rep = generate_report(env, case_id="t")
    for s in rep["sections"]:
        assert 0 <= s["confidence"] <= 100
        assert s["bucket"] in ("High", "Moderate", "Requires validation")


def test_report_legend_shipped():
    env = analyze(CHAIN)
    rep = generate_report(env, case_id="t")
    assert rep["legend"] and len(rep["legend"]) == 3


def test_report_deterministic():
    a = generate_report(analyze(CHAIN), case_id="t")
    b = generate_report(analyze(CHAIN), case_id="t")
    assert a == b


def test_report_mitre_and_intent_populated():
    env = analyze(CHAIN)
    rep = generate_report(env, case_id="t")
    body = {s["title"]: s["body"] for s in rep["sections"]}
    assert "T1490" in body["MITRE Coverage"]
    assert "Primary Objective" in body["Attack Intent"]
