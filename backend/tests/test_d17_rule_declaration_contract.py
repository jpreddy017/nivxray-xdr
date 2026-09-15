"""D17 · the rule declaration contract, and the gate that keeps it.

D8 built citations from DECLARED conditions and refused to infer which field
caused a match. It also left the declaration optional in practice: 30 of 36
runtime rules declared nothing, and nothing stopped a new rule from joining
them silently.

D17 makes the contract enforceable:

  * a rule that declares nothing must be on the FROZEN declaration-debt
    ledger — otherwise the gate fails, so undeclared evaluated fields
    cannot quietly enter production;
  * a declaration may only cite paths that exist in the canonical evidence
    model, with a supported operator and a human note;
  * a declaration must EXPLAIN the rule's own positive fixtures — a rule
    that fires while its citation explains nothing is a declaration defect,
    reported as one;
  * declaring conditions must never change what a rule matches.

Batch 1 (this gate): the Windows/ESXi endpoint command-line family.

EVIDENCE LABELLING — TEST/SYNTHETIC fixtures throughout.
"""
from __future__ import annotations

import pytest

from detection_content.library import REGISTRY
from detection_content.library import declaration_contract as dc
from detection_content.library.models import apply_operator
from detection_content.library.registry import RUNTIME_DETECTION_RULES
from detection_content.library.rules_enterprise import _D17_BATCH_1

RULES = {r.rule_id: r for r in RUNTIME_DETECTION_RULES}
BATCH = sorted(_D17_BATCH_1)


# ══ 1 · the gate ══════════════════════════════════════════════════
def test_no_rule_declares_nothing_without_being_on_the_frozen_ledger():
    report = dc.report(RUNTIME_DETECTION_RULES)
    assert report["contract_problems"] == [], report["contract_problems"]


def test_the_ledger_may_only_shrink():
    undeclared = {r.rule_id for r in RUNTIME_DETECTION_RULES
                  if not r.conditions}
    # every undeclared rule is accounted for, and nothing on the ledger has
    # been silently left undeclared-but-unlisted
    assert undeclared == set(dc.DECLARATION_DEBT), {
        "undeclared_not_on_ledger": sorted(undeclared - dc.DECLARATION_DEBT),
        "on_ledger_but_declared": sorted(dc.DECLARATION_DEBT - undeclared)}


def test_a_new_undeclared_rule_fails_the_gate():
    victim = RULES["DET-IM-001"]
    original = victim.conditions
    try:
        victim.conditions = []
        problems = dc.validate_rule(victim)
        assert problems, "an undeclared rule off the ledger must fail"
        assert "DECLARATION_DEBT" in problems[0]
    finally:
        victim.conditions = original


def test_a_declared_rule_still_listed_as_debt_fails_the_gate():
    rule = RULES["DET-EX-002"]
    frozen = dc.DECLARATION_DEBT
    try:
        dc.DECLARATION_DEBT = frozenset(frozen | {rule.rule_id})
        problems = dc.validate_rule(rule)
        assert any("still listed as declaration debt" in p
                   for p in problems), problems
    finally:
        dc.DECLARATION_DEBT = frozen


def test_declaration_coverage_moved_and_is_reported_honestly():
    report = dc.report(RUNTIME_DETECTION_RULES)
    declared = len(report["declared"])
    # 20 after D17 batch 1; 22 after D18 (DET-PS-001 declared on registry
    # evidence + DET-PS-005); 27 after D19 declared the five cloud/identity
    # rules whose fields D19 first had to make real; 28 after Microsoft
    # Phase 1a added the M365 unified-audit SOURCE that DET-PS-004 needed.
    assert declared == 28, report["declaration_coverage"]
    assert len(report["undeclared"]) == 9
    assert set(report["declared"]) >= set(BATCH)


# ══ 2 · what a declaration may say ════════════════════════════════
def test_every_declared_field_exists_in_the_canonical_evidence_model():
    for rule in RUNTIME_DETECTION_RULES:
        for c in rule.conditions:
            assert c.canonical_field in dc.CANONICAL_FIELDS, \
                f"{rule.rule_id}/{c.condition_id}: {c.canonical_field}"


def test_the_field_list_is_derived_from_the_model_not_hand_written():
    fields = dc.canonical_fields()
    # nested entity paths exist because the model has those entities
    for path in ("process.command_line", "process.executable_path",
                 "file.path", "host.hostname", "identity.username",
                 "network.dest_ip"):
        assert path in fields, path
    # and a plausible-looking path that the model does NOT produce is absent
    for path in ("registry.path", "process.target", "service_name"):
        assert path not in fields, path


def test_a_typo_in_a_declared_field_is_refused():
    rule = RULES["DET-EX-002"]
    victim = rule.conditions[0]
    original = victim.canonical_field
    try:
        victim.canonical_field = "process.comand_line"
        problems = dc.validate_rule(rule)
        assert any("not a path in the canonical evidence model" in p
                   for p in problems), problems
    finally:
        victim.canonical_field = original


def test_every_declared_operator_is_supported_and_implemented():
    for rule in RUNTIME_DETECTION_RULES:
        for c in rule.conditions:
            assert c.operator in dc.SUPPORTED_OPERATORS, c.operator
            # implemented, not merely named
            apply_operator(c.operator, "probe value", c.expected)


def test_every_declared_condition_says_what_it_means():
    for rule_id in BATCH:
        for c in RULES[rule_id].conditions:
            assert c.note, f"{rule_id}/{c.condition_id}"


# ══ 3 · the case-insensitive operators the predicates need ════════
@pytest.mark.parametrize("operator,observed,expected,result", [
    ("contains_ci", "CertUtil -URLCache", "urlcache", True),
    ("contains_ci", "certutil -dump", "urlcache", False),
    ("contains_any_ci", "BITSAdmin /Transfer", ["http", "ftp"], False),
    ("contains_any_ci", "bitsadmin /transfer http://x", ["http"], True),
    ("contains_all_ci", "WMIC process call CREATE", ["process", "call",
                                                     "create"], True),
    ("contains_all_ci", "wmic process list", ["process", "call"], False),
    ("basename_in_ci", "C:\\Windows\\System32\\CertUtil.exe",
     ["certutil.exe"], True),
    ("basename_in_ci", "C:\\Windows\\certutil.exe.bak", ["certutil.exe"],
     False),
    ("basename_in_ci", "/usr/bin/bash", ["bash"], True),
    ("basename_contains_any_ci", "C:\\temp\\AdFind.exe", ["adfind"], True),
    ("basename_contains_any_ci", "C:\\adfind\\net.exe", ["adfind"], False),
])
def test_the_ci_operators_behave_exactly_as_declared(operator, observed,
                                                     expected, result):
    assert apply_operator(operator, observed, expected) is result


def test_a_non_string_observation_never_matches_a_string_operator():
    for operator in ("contains_ci", "contains_any_ci", "contains_all_ci",
                     "basename_in_ci", "basename_contains_any_ci"):
        assert apply_operator(operator, None, ["x"]) is False
        assert apply_operator(operator, 5, ["x"]) is False


# ══ 4 · the declaration must EXPLAIN the match ════════════════════
@pytest.mark.parametrize("rule_id", BATCH)
def test_each_batch_rule_cites_its_own_positive_fixture(rule_id):
    proof = dc.citation_proof(RULES[rule_id])
    assert proof["positive_fixtures"] >= 1, proof
    assert proof["cited_fixtures"] >= 1, proof


def test_no_declared_rule_anywhere_fires_without_explaining_itself():
    report = dc.report(RUNTIME_DETECTION_RULES)
    assert report["declared_but_unexplained"] == [], \
        report["declared_but_unexplained"]


@pytest.mark.parametrize("rule_id", BATCH)
def test_a_batch_match_produces_a_complete_citation_through_the_registry(
        rule_id):
    rule = RULES[rule_id]
    fixture = next(f for f in rule.fixtures
                   if f.name == "positive_canonical" and f.should_match)
    event = {**fixture.event, "event_id": f"d17-{rule_id}"}
    matches = {m["rule_id"]: m for m in REGISTRY.evaluate_event(event)}
    assert rule_id in matches, sorted(matches)
    citation = matches[rule_id]["citation"]
    assert citation["declaration_state"] == "DECLARED"
    assert citation["citation_completeness"] == "CITED"
    assert citation["matched_conditions"], citation
    for row in citation["matched_conditions"]:
        assert row["canonical_field"] in dc.CANONICAL_FIELDS
        assert row["observed_value"], row
        assert row["evidence_ref"] == f"xdr_canonical_evidence/d17-{rule_id}"
    assert matches[rule_id]["rule_version"] == "2"


@pytest.mark.parametrize("rule_id", BATCH)
def test_a_negative_fixture_still_does_not_match(rule_id):
    rule = RULES[rule_id]
    for fixture in rule.fixtures:
        if fixture.should_match:
            continue
        assert rule.evaluate(fixture.event) is False, (rule_id, fixture.name)


# ══ 5 · declaring changes nothing about WHAT matches ══════════════
@pytest.mark.parametrize("rule_id", BATCH)
def test_the_predicate_remains_the_sole_authority(rule_id):
    rule = RULES[rule_id]
    # Every fixture must still get exactly the answer its author claimed:
    # declaring conditions may not promote or demote a single match.
    for fixture in rule.fixtures:
        if rule_id in dc.KNOWN_FIXTURE_DEFECTS and fixture.name == "positive":
            continue          # a recorded, deliberately unfixed defect
        assert rule.evaluate(fixture.event) is fixture.should_match, \
            (rule_id, fixture.name)


def test_the_gate_found_a_predicate_defect_and_did_not_hide_it():
    # DET-CR-002's authored positive fixture does not satisfy its own
    # predicate. D17 records it rather than widening the predicate, because
    # declaring conditions must never change what a rule matches.
    defect = dc.KNOWN_FIXTURE_DEFECTS["DET-CR-002"]
    assert "PREDICATE COVERAGE" in defect
    rule = RULES["DET-CR-002"]
    authored = next(f for f in rule.fixtures if f.name == "positive")
    assert authored.should_match is True
    assert rule.evaluate(authored.event) is False
    # and the declaration is still proved, against a fixture the predicate
    # genuinely matches
    assert dc.citation_proof(rule)["cited_fixtures"] >= 1


def test_declaring_conditions_did_not_change_the_original_fixtures():
    # every rule in the batch keeps its pre-D17 Sysmon-shaped fixtures
    for rule_id in BATCH:
        names = [f.name for f in RULES[rule_id].fixtures]
        assert "positive" in names and "negative" in names, (rule_id, names)


def test_a_rule_off_the_batch_is_untouched():
    rule = RULES["DET-EX-001"]
    assert rule.conditions == []
    assert rule.rule_version == "1"
    citation = rule.cite({"command_line": "powershell -enc AAA"})
    assert citation["declaration_state"] == "NOT_DECLARED"
    assert citation["evaluated_conditions"] == []
    assert "NOT inferred" in citation["note"]


# ══ 6 · telemetry gaps are named, not disguised ═══════════════════
def test_a_rule_blocked_by_a_telemetry_gap_says_so_instead_of_pretending():
    # the gaps that remain name fields the model genuinely cannot produce
    assert dc.TELEMETRY_GAPS
    for rule_id, gaps in dc.TELEMETRY_GAPS.items():
        for field in gaps:
            assert field not in dc.CANONICAL_FIELDS, (rule_id, field)


def test_a_gap_closed_by_new_evidence_is_recorded_as_closed():
    # D18 closed DET-PS-001 by ADDING registry evidence, not by weakening
    # the declaration. The history stays auditable.
    assert "DET-PS-001" in dc.CLOSED_TELEMETRY_GAPS
    assert "DET-PS-001" not in dc.DECLARATION_DEBT
    assert "DET-PS-001" not in dc.TELEMETRY_GAPS
    assert RULES["DET-PS-001"].conditions
    assert "registry.key_path" in dc.CANONICAL_FIELDS


def test_every_declared_gap_names_a_field_the_model_cannot_produce():
    for rule_id, gaps in dc.TELEMETRY_GAPS.items():
        assert rule_id in RULES, rule_id
        for field in gaps:
            assert field not in dc.CANONICAL_FIELDS, (rule_id, field)


def test_the_report_is_operator_readable():
    report = dc.report(RUNTIME_DETECTION_RULES)
    for key in ("rules_total", "declared", "undeclared", "declaration_debt",
                "declaration_coverage", "contract_problems",
                "declared_but_unexplained", "telemetry_gaps",
                "known_fixture_defects", "honesty_note"):
        assert key in report, key
    assert report["rules_total"] == len(RUNTIME_DETECTION_RULES)
