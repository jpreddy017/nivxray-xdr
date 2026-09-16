"""Per-service content contract tests (scaffold-level)."""
from __future__ import annotations

from l2_investigation.services.attack_story import run as run_story
from l2_investigation.services.capability_explorer import run as run_caps
from l2_investigation.services.detection_rules import run as run_rules
from l2_investigation.services.executive_summary import run as run_summary
from l2_investigation.services.hunting_queries import run as run_hunt
from l2_investigation.services.ioc_intelligence import run as run_ioc
from l2_investigation.services.threat_assessment import run as run_threat

from _fixtures import empty_bundle, synthetic_bundle


def test_executive_summary_verdict_malicious_when_family_and_caps():
    out = run_summary(synthetic_bundle())
    assert out.body["verdict"] == "malicious"
    assert out.body["family"] == "cobalt_strike"
    assert len(out.body["top_iocs"]) == 2


def test_executive_summary_verdict_unknown_for_empty():
    out = run_summary(empty_bundle())
    assert out.body["verdict"] == "unknown"
    assert out.body["top_iocs"] == []


def test_attack_story_events_ordered_by_iteration():
    out = run_story(synthetic_bundle())
    events = out.body["events"]
    assert len(events) == 4
    iterations = [e["iteration"] for e in events]
    assert iterations == sorted(iterations)


def test_attack_story_anchors_transformations():
    out = run_story(synthetic_bundle())
    for e in out.body["events"]:
        assert e["anchor"]["kind"] == "transformation"
        assert "iteration" in e["anchor"]
        assert "transformation" in e["anchor"]


def test_ioc_intelligence_groups_by_type():
    out = run_ioc(synthetic_bundle())
    assert out.body["total"] == 2
    assert set(out.body["by_type"]) == {"url", "domain"}


def test_ioc_intelligence_empty_bundle():
    out = run_ioc(empty_bundle())
    assert out.body["total"] == 0
    assert out.body["by_type"] == {}


def test_capability_explorer_cross_references_mitre():
    out = run_caps(synthetic_bundle())
    items = out.body["items"]
    ids = [i["capability_id"] for i in items]
    assert ids == sorted(ids)
    for i in items:
        assert len(i["mitre"]) >= 1


def test_threat_assessment_high_severity_with_multi_signals():
    out = run_threat(synthetic_bundle())
    assert out.body["severity"] in {"high", "critical"}


def test_threat_assessment_informational_when_no_evidence():
    out = run_threat(empty_bundle())
    assert out.body["severity"] == "informational"


def test_detection_rules_supports_all_four_formats():
    out = run_rules(synthetic_bundle())
    assert set(out.body["rules"]) == {"sigma", "kql", "splunk", "yara"}
    for fmt, rules in out.body["rules"].items():
        assert isinstance(rules, list)


def test_hunting_queries_targets_are_declared():
    out = run_hunt(synthetic_bundle())
    assert set(out.body["queries"]) == {"splunk", "sentinel", "elastic", "crowdstrike"}
