"""
P0.2d · Rule ↔ Capability Matching — pytest gate.

Invariants under test:
  1. A parsed Sigma rule mapped against ONLY the currently-declared
     contracts (all detection=False) returns status=ENGINE_UNBOUND —
     never COMPATIBLE.  This preserves the DETECTION_ENGINE=0
     honesty guarantee.
  2. If a synthetic contract with detection=True and matching
     consumes[] is added, the SAME rule flips to status=COMPATIBLE.
  3. If a contract has matching consumes[] but detection=False, the
     rule surfaces it as CANDIDATE_ONLY (not COMPATIBLE, not silently
     ignored).
  4. If a contract has detection=True but non-matching consumes[],
     the pair is INCOMPATIBLE_INPUT, not COMPATIBLE.
  5. The matcher is deterministic — same inputs, same output.
  6. rule_required_evidence() maps windows/process_creation to a
     process.artifact-family list.
"""
from __future__ import annotations
import pytest

from detection_content.sigma_strict import strict_parse, StrictParseStatus
from detection_content.rule_binding import (
    match_rule_to_contracts, rule_required_evidence,
)


PROCESS_RULE = """
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


def _get_rule():
    r = strict_parse(PROCESS_RULE)
    assert r.status == StrictParseStatus.PARSED, r.error_message
    return r.rule


def test_engine_unbound_when_no_detection_engine_exists():
    rule = _get_rule()
    contracts = [
        {"engine_id": "e1", "classification": "ANALYZER",
         "consumes": ["canonical.artifact"],
         "execution": {"detection": False}},
        {"engine_id": "e2", "classification": "DECODER",
         "consumes": ["encoded.artifact"],
         "execution": {"detection": False}},
    ]
    r = match_rule_to_contracts(rule, contracts)
    assert r["status"] == "ENGINE_UNBOUND"
    assert r["counts"]["compatible"] == 0


def test_compatible_when_detection_engine_and_input_match():
    rule = _get_rule()
    contracts = [
        {"engine_id": "det",
         "classification": "DETECTION_ENGINE",
         "consumes": ["process.artifact"],
         "execution": {"detection": True}},
        {"engine_id": "other",
         "classification": "ANALYZER",
         "consumes": ["canonical.evidence"],
         "execution": {"detection": False}},
    ]
    r = match_rule_to_contracts(rule, contracts)
    assert r["status"] == "COMPATIBLE"
    assert r["counts"]["compatible"] == 1
    assert any(m["engine_id"] == "det"
                    and m["compatibility"] == "COMPATIBLE"
                    for m in r["matches"])


def test_candidate_only_when_input_match_but_no_detection():
    rule = _get_rule()
    contracts = [
        {"engine_id": "candidate",
         "classification": "ANALYZER",
         "consumes": ["canonical.evidence"],
         "execution": {"detection": False}},
    ]
    r = match_rule_to_contracts(rule, contracts)
    assert r["status"] == "CANDIDATE_ONLY"
    assert r["counts"]["candidate_only"] == 1


def test_incompatible_input_when_detection_true_but_no_input_overlap():
    rule = _get_rule()
    contracts = [
        {"engine_id": "wrong-input",
         "classification": "DETECTION_ENGINE",
         "consumes": ["network.artifact"],
         "execution": {"detection": True}},
    ]
    r = match_rule_to_contracts(rule, contracts)
    assert r["status"] == "ENGINE_UNBOUND"
    assert r["counts"]["compatible"] == 0
    assert any(m["compatibility"] == "INCOMPATIBLE_INPUT"
                    for m in r["matches"])


def test_matcher_is_deterministic():
    rule = _get_rule()
    contracts = [
        {"engine_id": "a", "classification": "ANALYZER",
         "consumes": ["canonical.evidence"],
         "execution": {"detection": False}},
        {"engine_id": "b", "classification": "DECODER",
         "consumes": ["encoded.artifact"],
         "execution": {"detection": False}},
    ]
    r1 = match_rule_to_contracts(rule, contracts)
    r2 = match_rule_to_contracts(rule, contracts)
    assert r1 == r2


def test_evidence_map_process_creation():
    rule = _get_rule()
    ev = rule_required_evidence(rule)
    assert "process.artifact" in ev
    assert "canonical.evidence" in ev
