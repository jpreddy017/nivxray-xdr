"""D8 · detection citation acceptance.

Every test drives the REAL registry and the REAL rule declarations. Nothing
is stubbed, and no citation is constructed by the test itself — the test only
asserts what the engine recorded.

Owner acceptance list, in order:
  1 positive match          6 duplicate evidence
  2 negative match          7 malformed / unexpected value
  3 multiple-condition      8 rule version change
  4 missing canonical field  9 tenant isolation
  5 null field             10 persistence / retrieval of citations
"""
from __future__ import annotations

import os
import re

import pytest
from pymongo import MongoClient

from detection_content.library import REGISTRY
from detection_content.library.models import (RuleCondition, apply_operator,
                                              resolve_field)
from detection_content.library.rules_edr_linux import (
    EDR_LINUX_DETECTION_RULES)

RULES = {r.rule_id: r for r in EDR_LINUX_DETECTION_RULES}
EV_REF = "xdr_canonical_evidence/cev_test"


def ev(**over):
    """A canonical-shaped endpoint event. Only the fields a rule declares."""
    base = {
        "event_id": "cev_test",
        "tenant_id": "t-citation",
        "source_vendor": "NivXForge",
        "source_product": "LinuxSensor",
        "process": {"name": "bash", "executable_path": "/usr/bin/bash",
                    "command_line": "/bin/bash /tmp/payload.sh",
                    "parent_name": "python3.11"},
    }
    base.update(over)
    return base


# ── 1 · positive match ────────────────────────────────────────────────
def test_positive_match_cites_field_value_and_evidence():
    rule = RULES["EDR-LNX-002"]
    event = ev()
    assert rule.evaluate(event) is True

    cit = rule.cite(event, evidence_ref=EV_REF)
    assert cit["declaration_state"] == "DECLARED"
    assert cit["matched_conditions"], "a match must cite at least one condition"

    by_id = {c["condition_id"]: c for c in cit["evaluated_conditions"]}
    argv = by_id["argv.world_writable_script"]
    assert argv["result"] == "MATCH"
    # The observed value is the REAL value from the evidence, not a label.
    assert argv["observed_value"] == "/bin/bash /tmp/payload.sh"
    assert argv["canonical_field"] == "process.command_line"
    assert argv["evidence_ref"] == EV_REF


# ── 2 · negative match ────────────────────────────────────────────────
def test_negative_match_produces_no_citation_row():
    rule = RULES["EDR-LNX-002"]
    event = ev(process={"name": "curl", "executable_path": "/usr/bin/curl",
                        "command_line": "curl https://example.com"})
    assert rule.evaluate(event) is False
    assert REGISTRY.evaluate_event(event) == []


# ── 3 · multiple-condition match ──────────────────────────────────────
def test_multiple_conditions_are_each_reported_individually():
    rule = RULES["EDR-LNX-002"]
    cit = rule.cite(ev(), evidence_ref=EV_REF)
    results = {c["condition_id"]: c["result"]
               for c in cit["evaluated_conditions"]}
    # Scope conditions hold, the interpreter check holds, the argv check
    # holds — and the image-path branch genuinely does NOT, because the
    # image is /usr/bin/bash while the SCRIPT is in /tmp.
    assert results["scope.vendor"] == "MATCH"
    assert results["scope.product"] == "MATCH"
    assert results["image.is_interpreter"] == "MATCH"
    assert results["argv.world_writable_script"] == "MATCH"
    assert results["image.world_writable"] == "NO_MATCH"
    assert len(cit["matched_conditions"]) == 4
    assert len(cit["unmatched_conditions"]) == 1


# ── 4 · missing canonical field ───────────────────────────────────────
def test_missing_field_is_field_absent_not_no_match():
    rule = RULES["EDR-LNX-002"]
    event = ev(process={"executable_path": "/tmp/x/payload"})   # no cmdline
    cit = rule.cite(event, evidence_ref=EV_REF)
    by_id = {c["condition_id"]: c for c in cit["evaluated_conditions"]}
    assert by_id["argv.world_writable_script"]["result"] == "FIELD_ABSENT"
    assert by_id["argv.world_writable_script"]["field_state"] == "ABSENT"
    # An absent field must never be reported as an evaluated non-match:
    # "we did not collect it" is a different claim from "it did not match".
    assert by_id["argv.world_writable_script"]["result"] != "NO_MATCH"


# ── 5 · null field ────────────────────────────────────────────────────
def test_null_field_is_distinguished_from_absent_field():
    rule = RULES["EDR-LNX-002"]
    event = ev(process={"executable_path": "/usr/bin/bash",
                        "command_line": None})
    cit = rule.cite(event, evidence_ref=EV_REF)
    by_id = {c["condition_id"]: c for c in cit["evaluated_conditions"]}
    assert by_id["argv.world_writable_script"]["result"] == "FIELD_NULL"
    assert by_id["argv.world_writable_script"]["field_state"] == "NULL"


# ── 6 · duplicate evidence ────────────────────────────────────────────
def test_same_event_cited_twice_is_identical_and_side_effect_free():
    rule = RULES["EDR-LNX-002"]
    event = ev()
    first = rule.cite(event, evidence_ref=EV_REF)
    second = rule.cite(event, evidence_ref=EV_REF)
    assert first == second
    # Citing must not mutate the evidence it read.
    assert event == ev()


# ── 7 · malformed / unexpected value ──────────────────────────────────
@pytest.mark.parametrize("bad", [
    12345, [], {}, b"bytes", 3.14, True,
])
def test_malformed_values_never_raise_and_never_falsely_match(bad):
    rule = RULES["EDR-LNX-002"]
    event = ev(process={"executable_path": bad, "command_line": bad})
    assert rule.evaluate(event) is False
    cit = rule.cite(event, evidence_ref=EV_REF)
    for c in cit["evaluated_conditions"]:
        assert c["result"] in ("MATCH", "NO_MATCH", "FIELD_ABSENT",
                               "FIELD_NULL")
        if c["canonical_field"].startswith("process."):
            assert c["result"] != "MATCH", (
                f"{c['condition_id']} matched on a malformed value "
                f"{bad!r} — a type confusion would be a false positive")


def test_unknown_operator_is_reported_not_swallowed():
    rule = RULES["EDR-LNX-002"]
    broken = RuleCondition("x", "process.command_line", "no_such_operator")
    original = rule.conditions
    try:
        rule.conditions = [broken]
        cit = rule.cite(ev(), evidence_ref=EV_REF)
        row = cit["evaluated_conditions"][0]
        assert row["result"] == "EVALUATION_ERROR"
        assert "no_such_operator" in row["error"]
    finally:
        rule.conditions = original


# ── 8 · rule version change ───────────────────────────────────────────
def test_rule_version_is_declared_and_travels_with_the_match():
    for r in EDR_LINUX_DETECTION_RULES:
        assert r.rule_version, f"{r.rule_id} must declare a rule_version"
    matches = REGISTRY.evaluate_event(ev())
    assert matches
    m = next(x for x in matches if x["rule_id"] == "EDR-LNX-002")
    assert m["rule_version"] == RULES["EDR-LNX-002"].rule_version

    rule = RULES["EDR-LNX-002"]
    original = rule.rule_version
    try:
        rule.rule_version = "2"
        again = REGISTRY.evaluate_event(ev())
        m2 = next(x for x in again if x["rule_id"] == "EDR-LNX-002")
        assert m2["rule_version"] == "2"
        # A version bump must not silently change the match itself.
        assert m2["citation"]["matched_conditions"] == \
            m["citation"]["matched_conditions"]
    finally:
        rule.rule_version = original


# ── 9 · tenant isolation ──────────────────────────────────────────────
def test_citation_carries_only_its_own_tenant_and_evidence():
    a = REGISTRY.evaluate_event(ev(tenant_id="tenant-a",
                                   event_id="cev_a"))
    b = REGISTRY.evaluate_event(ev(tenant_id="tenant-b",
                                   event_id="cev_b"))
    ra = next(x for x in a if x["rule_id"] == "EDR-LNX-002")["citation"]
    rb = next(x for x in b if x["rule_id"] == "EDR-LNX-002")["citation"]
    refs_a = {c["evidence_ref"] for c in ra["evaluated_conditions"]}
    refs_b = {c["evidence_ref"] for c in rb["evaluated_conditions"]}
    assert refs_a == {"xdr_canonical_evidence/cev_a"}
    assert refs_b == {"xdr_canonical_evidence/cev_b"}
    assert refs_a.isdisjoint(refs_b), "no citation may reference another " \
                                      "tenant's evidence"


# ── 10 · persistence / retrieval ──────────────────────────────────────
def test_persisted_citations_are_retrievable_and_well_formed():
    """Reads what the LIVE pipeline actually wrote. Skips honestly rather
    than passing vacuously when no real match has been stored yet."""
    url = os.environ.get("MONGO_URL")
    if not url:
        pytest.skip("MONGO_URL not set")
    db = MongoClient(url)[os.environ.get("DB_NAME") or "test_database"]
    row = db["xdr_detection_matches"].find_one(
        {"declaration_state": "DECLARED"}, sort=[("_id", -1)])
    if not row:
        pytest.skip("no persisted citation yet — run the live pipeline first")

    for key in ("tenant_id", "canonical_event_id", "evidence_ref", "rule_id",
                "rule_version", "engine_id", "rule_result",
                "evaluated_conditions", "evaluated_at"):
        assert row.get(key) not in (None, ""), f"{key} missing"
    assert row["rule_result"] == "MATCH"
    assert row["evidence_ref"].endswith(row["canonical_event_id"])
    assert row["matched_conditions"], "a stored match must cite something"

    for c in row["evaluated_conditions"]:
        assert c["canonical_field"]
        assert c["result"] in ("MATCH", "NO_MATCH", "FIELD_ABSENT",
                               "FIELD_NULL", "EVALUATION_ERROR")
        assert c["evidence_ref"] == row["evidence_ref"]

    # The cited evidence must still exist and still hold the cited value.
    src = db["xdr_canonical_evidence"].find_one(
        {"event_id": row["canonical_event_id"]})
    assert src, "citation points at evidence that does not exist"
    for c in row["matched_conditions"]:
        observed, state = resolve_field(src, c["canonical_field"])
        assert state == "PRESENT"
        assert observed == c["observed_value"], (
            "the stored observed_value no longer matches the evidence it "
            "was read from")


# ── declaration hygiene ───────────────────────────────────────────────
def test_every_declared_condition_uses_a_known_operator():
    for r in EDR_LINUX_DETECTION_RULES:
        for c in r.conditions:
            try:
                apply_operator(c.operator, "probe", c.expected)
            except ValueError:
                pytest.fail(f"{r.rule_id}/{c.condition_id} declares unknown "
                            f"operator {c.operator!r}")
            except Exception:
                pass  # type mismatch on a probe string is fine


def test_declared_fields_are_covered_by_telemetry_requirements():
    """A rule may not cite a field it never told the platform it needs."""
    for r in EDR_LINUX_DETECTION_RULES:
        req = set(r.telemetry_requirements)
        for c in r.conditions:
            if c.condition_id.startswith("scope."):
                continue
            assert c.canonical_field in req, (
                f"{r.rule_id} declares condition on "
                f"{c.canonical_field!r} which is absent from "
                f"telemetry_requirements {sorted(req)}")
