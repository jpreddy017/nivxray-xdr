"""PR-4 · Executive Summary + Attack Story enrichment tests.

Scope (ARB-approved):
  * Summary  — verdict / risk / risk_score / top_iocs / top_actions / bullets
  * Story    — events (unchanged) / chapters / narrative

Everything under test must be deterministic (identical bundle → byte-identical
JSON) and every emitted list item must carry an evidence anchor per §8.4.
"""
from __future__ import annotations

import json

from l2_investigation.services.attack_story import run as run_story
from l2_investigation.services.executive_summary import run as run_summary

from _fixtures import empty_bundle, synthetic_bundle


# ---------------------------------------------------------------------------
# Executive Summary
# ---------------------------------------------------------------------------


def test_summary_risk_bucket_and_score_deterministic():
    a = run_summary(synthetic_bundle("case-A"))
    b = run_summary(synthetic_bundle("case-A"))
    assert a.body["risk"] == b.body["risk"]
    assert a.body["risk_score"] == b.body["risk_score"]
    assert a.fingerprint == b.fingerprint


def test_summary_risk_bucket_high_or_critical_for_synthetic():
    out = run_summary(synthetic_bundle())
    assert out.body["risk"] in {"high", "critical"}
    assert 50 <= out.body["risk_score"] <= 100


def test_summary_risk_informational_for_empty():
    # empty_bundle inherits synthetic_certificate() which has
    # ready_for_behavioral_analysis=True → 0 residual-obfuscation contribution,
    # no family, no capabilities, no MITRE, no IOCs → score 0 → informational.
    out = run_summary(empty_bundle())
    assert out.body["risk"] == "informational"
    assert out.body["risk_score"] == 0


def test_summary_risk_score_bounded_0_to_100():
    for bundle in (synthetic_bundle(), empty_bundle()):
        out = run_summary(bundle)
        assert 0 <= out.body["risk_score"] <= 100


def test_summary_top_actions_have_anchors():
    out = run_summary(synthetic_bundle())
    actions = out.body["top_actions"]
    assert 1 <= len(actions) <= 3
    for a in actions:
        assert "action_id" in a
        assert "priority" in a
        assert "text" in a
        assert "anchor" in a
        assert a["anchor"]["kind"] in {"ioc", "capability", "mitre"}


def test_summary_bullets_have_anchors():
    out = run_summary(synthetic_bundle())
    bullets = out.body["bullets"]
    assert len(bullets) >= 1
    for b in bullets:
        assert "bullet_id" in b
        assert "text" in b
        assert "anchor" in b
        assert "kind" in b["anchor"]


def test_summary_top_actions_prioritise_ioc_first():
    out = run_summary(synthetic_bundle())
    actions = out.body["top_actions"]
    assert actions[0]["action_id"] == "act-block-primary-ioc"
    assert actions[0]["anchor"]["kind"] == "ioc"


def test_summary_bullets_ordered_verdict_first():
    out = run_summary(synthetic_bundle())
    assert out.body["bullets"][0]["bullet_id"] == "b-verdict"


def test_summary_json_stable_across_repeat_calls():
    b = synthetic_bundle()
    j1 = run_summary(b).to_json()
    j2 = run_summary(b).to_json()
    assert j1 == j2
    # Order-independent evidence must produce ordered JSON.
    parsed = json.loads(j1)
    assert list(parsed["body"]["bullets"][0]) == sorted(parsed["body"]["bullets"][0])


def test_summary_empty_bundle_produces_no_actions_but_still_bullets():
    out = run_summary(empty_bundle())
    assert out.body["top_actions"] == []
    # At least the verdict + canonical bullets always exist.
    ids = [b["bullet_id"] for b in out.body["bullets"]]
    assert "b-verdict" in ids
    assert "b-canonical" in ids


# ---------------------------------------------------------------------------
# Attack Story
# ---------------------------------------------------------------------------


def test_story_events_shape_backwards_compatible():
    """PR-3 scaffold contract: events remain iteration-ordered with an anchor."""
    out = run_story(synthetic_bundle())
    events = out.body["events"]
    assert len(events) == 4
    for e in events:
        assert e["anchor"]["kind"] == "transformation"
        assert "iteration" in e["anchor"]
        assert "transformation" in e["anchor"]
    # PR-4 additions.
    for e in events:
        assert "chapter" in e


def test_story_chapters_enumerated_in_order():
    out = run_story(synthetic_bundle())
    chapters = out.body["chapters"]
    names = [c["chapter"] for c in chapters]
    assert names == ["Unwrap", "Normalize", "Decode", "Interpret"]
    assert all(c["event_count"] >= 1 for c in chapters)


def test_story_narrative_is_deterministic_prose():
    out = run_story(synthetic_bundle())
    narrative = out.body["narrative"]
    assert isinstance(narrative, str)
    assert len(narrative) > 0
    assert "cobalt_strike" in narrative
    assert "canonical state" in narrative


def test_story_narrative_stable_across_calls():
    b = synthetic_bundle()
    assert run_story(b).body["narrative"] == run_story(b).body["narrative"]


def test_story_empty_bundle_produces_narrative_without_family():
    out = run_story(empty_bundle())
    assert out.body["events"] == []
    assert out.body["chapters"] == []
    assert "no attributed family" in out.body["narrative"]


def test_story_fingerprint_stable():
    b = synthetic_bundle("case-story-01")
    assert run_story(b).fingerprint == run_story(b).fingerprint
