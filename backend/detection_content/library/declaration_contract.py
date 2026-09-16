"""D17 · the rule declaration contract, and the gate that enforces it.

A detection rule must DECLARE the canonical fields it evaluates. The
declaration is what a citation is built from — the engine never infers which
field caused a match, because a wrong citation is worse than an absent one
(D8). Until now the declaration was optional in practice: 30 of 36 runtime
rules declared nothing, and a new rule could join them silently.

This module makes the contract checkable instead of aspirational:

  * `SUPPORTED_OPERATORS`  — what a declaration may say.
  * `canonical_fields()`   — the paths a declaration may cite, derived from
    the canonical evidence model itself, so the list cannot drift from the
    evidence the platform actually produces.
  * `validate_rule()`      — is this declaration well formed, and does it
    cite fields that exist?
  * `citation_proof()`     — does the declaration actually EXPLAIN the
    rule's own positive fixtures? A rule that fires while its declaration
    explains nothing is a declaration defect, and it is reported as one.
  * `DECLARATION_DEBT`     — the frozen ledger of rules that still declare
    nothing. A rule that is not on this list and declares nothing FAILS the
    gate, so undeclared evaluated fields cannot silently enter production.

Nothing here changes detection behaviour: `predicate` remains the sole
authority on whether a rule matched.
"""
from __future__ import annotations

from dataclasses import fields as dataclass_fields, is_dataclass
from typing import Any, Dict, List

from detection_content.telemetry.models import CanonicalTelemetryEvent

from .models import DetectionRuleContent

SUPPORTED_OPERATORS = frozenset({
    "exists", "equals", "contains", "contains_ci", "contains_any_ci",
    "contains_all_ci", "basename_in", "basename_in_ci",
    "basename_contains_any_ci", "starts_with_any", "matches",
    "any_argument_starts_with", "serialized_contains_any_ci",
})

#: Operators whose `expected` must be an iterable of values.
_SEQUENCE_OPERATORS = frozenset({
    "contains_any_ci", "contains_all_ci", "basename_in", "basename_in_ci",
    "basename_contains_any_ci", "starts_with_any",
    "any_argument_starts_with", "serialized_contains_any_ci",
})

#: Root aliases `CanonicalTelemetryEvent.to_dict()` adds for backward
#: compatibility. They are real canonical paths, so a declaration may cite
#: them — but the nested path is preferred and the contract says so.
_ROOT_ALIASES = frozenset({"timestamp", "command_line", "image",
                           "parent_image", "user_id", "host_id"})

#: Paths that live under `additional_fields` and are produced by a DSM
#: rather than by the dataclass. Declared explicitly so a typo cannot pass.
_ADDITIONAL_FIELD_PATHS = frozenset({
    "additional_fields.event_name",
    "additional_fields.event_source",
    "additional_fields.record_type",
    "additional_fields.syscall",
    "additional_fields.path_mapping",
    "additional_fields.working_directory",
})


def _paths(obj: Any, prefix: str = "") -> List[str]:
    out: List[str] = []
    for f in dataclass_fields(obj):
        path = f"{prefix}{f.name}"
        out.append(path)
        value = getattr(obj, f.name)
        if is_dataclass(value):
            out.extend(_paths(value, f"{path}."))
    return out


def canonical_fields() -> frozenset[str]:
    """Every path a declaration may cite, derived from the evidence model."""
    probe = CanonicalTelemetryEvent(
        event_id="", tenant_id="", source_vendor="", source_product="",
        source_event_id="", event_type="", event_time="", ingest_time="")
    return frozenset(_paths(probe)) | _ROOT_ALIASES | _ADDITIONAL_FIELD_PATHS


CANONICAL_FIELDS = canonical_fields()

#: D17 · the frozen declaration debt. Every rule here evaluates fields it
#: has not declared, so it can produce no citation. The list may only
#: SHRINK: a new rule that declares nothing is not on it and fails the gate.
DECLARATION_DEBT: frozenset[str] = frozenset({
    # content / behaviour lanes — next batches
    "DET-EX-001", "DET-IA-002", "DET-DE-001", "DET-DE-003", "DET-LM-002",
    "DET-IM-004", "DET-EM-002", "DET-CC-002",
    # no source exists for these at all — see TELEMETRY_GAPS
    "DET-PE-002",     # AD CS certificate telemetry (4886/4887): no DSM
    # D18 removed DET-PS-001 from this ledger by adding the registry entity
    # it needed, D19 removed the five cloud/identity rules the same way, and
    # Microsoft Phase 1a removed DET-PS-004 by adding the Microsoft 365
    # unified-audit SOURCE it was waiting for — each gap was closed with
    # evidence, never with a weaker declaration.
})

#: Fields a rule evaluates that the canonical model cannot produce today.
#: Declared per rule so the gap is visible instead of looking like an
#: unfinished declaration.
TELEMETRY_GAPS: Dict[str, List[str]] = {
    "DET-CR-001": ["process.target", "TargetImage"],
    "DET-LM-001": ["service_name", "registry.service_name"],
    # D19 · this one needs a SOURCE that does not exist yet, not a field.
    # Declaring it would produce a citation pointing at nothing.
    "DET-PE-002": ["certificate.template", "certificate.san",
                   "(AD CS 4886/4887 telemetry — no DSM)"],
}

#: Microsoft Phase 1a · standing findings where a rule's PREDICATE is
#: narrower or broader than the technique it advertises. Declaring what a
#: predicate already evaluates must never change what it matches, so these
#: are recorded for a detection-content gate instead of being silently
#: "fixed" while a telemetry gate is open.
PREDICATE_COVERAGE_FINDINGS: Dict[str, str] = {
    "DET-PS-004": (
        "the rule advertises inbox rules that forward or redirect "
        "EXTERNALLY, but its predicate tests only that a forwarding-style "
        "parameter is present — an internal ForwardTo would match too. "
        "Phase 1a deliberately did NOT tighten it: the Microsoft record "
        "carries the recipient address and `ExternalAccess`, so the "
        "evidence needed to distinguish internal from external forwarding "
        "is now preserved and a detection-content gate can narrow the "
        "predicate on real evidence."),
}

#: D18 · gaps CLOSED by adding real evidence rather than by lowering the
#: bar. Kept visible so the history of a rule's citability is auditable.
CLOSED_TELEMETRY_GAPS: Dict[str, str] = {
    "DET-PE-003": (
        "cloud.policy never existed; D19 added CloudContext.request_"
        "parameters (verbatim CloudTrail requestParameters) and the rule now "
        "declares it, searched as text by serialized_contains_any_ci."),
    "DET-CR-004": (
        "the rule read `event_id`, which on canonical evidence is NivX's own "
        "evidence id, and looked for RC4 in ticket_options. D19 pointed it "
        "at source_event_id and authentication.ticket_encryption, which is "
        "where the Windows DSM has always put them."),
    "DET-CR-005": (
        "preauth_type existed in the 4768 record and nowhere in the model; "
        "D19 added AuthEntity.preauth_type from Windows PreAuthType."),
    "DET-CR-006": (
        "the rule read network.destination_ip, a spelling that exists in no "
        "evidence model; the canonical field is network.dest_ip."),
    "DET-EM-001": (
        "principal_kind existed nowhere; D19 added CloudContext."
        "principal_type carrying the provider's own vocabulary verbatim "
        "(AWSService / AssumedRole / IAMUser)."),
    "DET-PS-001": (
        "registry.path had no canonical home until D18 added the registry "
        "entity (Sysmon 12/13/14, Windows Security 4657). The rule now "
        "declares registry.key_path / registry.target_object / "
        "registry.action, and its command-line half moved to DET-PS-005 so "
        "observed registry evidence and command-line inference stay "
        "separate."),
    "DET-PS-004": (
        "cloud.rule_name never existed because NivX had NO Microsoft audit "
        "source. Microsoft Phase 1a added the m365-unified-audit DSM "
        "(Office 365 Management Activity API), whose Exchange records carry "
        "the inbox-rule definition in `Parameters`; the rule now declares "
        "cloud.action + cloud.request_parameters and cites the verbatim "
        "recorded parameters."),
}

#: D17 · defects the contract gate FOUND and deliberately did NOT fix,
#: because fixing them would change what a rule matches — and declaring
#: conditions must never do that. Each entry is a standing finding for a
#: detection-content gate, not an excuse.
KNOWN_FIXTURE_DEFECTS: Dict[str, str] = {
    "DET-CR-002": (
        "the authored positive fixture "
        "`ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\temp\" q q` does "
        "NOT satisfy the rule's own predicate, which requires the literal "
        "string 'ntds.dit' on the command line. Real-world ntdsutil IFM "
        "extraction does not name ntds.dit, so this is a PREDICATE COVERAGE "
        "gap: the rule under-matches the technique it advertises. Widening "
        "the predicate changes detection behaviour and belongs to a "
        "detection-content gate — D17 only declares what the predicate "
        "already evaluates, and the declaration is proved instead against a "
        "canonical fixture that the predicate does match."),
}


def validate_rule(rule: DetectionRuleContent) -> List[str]:
    """Structural problems with this rule's declaration. Empty == valid."""
    problems: List[str] = []
    if not rule.conditions:
        if rule.rule_id not in DECLARATION_DEBT:
            problems.append(
                f"{rule.rule_id}: declares no conditions and is not on the "
                "frozen DECLARATION_DEBT ledger — an undeclared rule cannot "
                "cite the evidence it evaluated")
        return problems
    if rule.rule_id in DECLARATION_DEBT:
        problems.append(
            f"{rule.rule_id}: declares conditions but is still listed as "
            "declaration debt — remove it from DECLARATION_DEBT")
    seen: set[str] = set()
    for c in rule.conditions:
        if c.condition_id in seen:
            problems.append(f"{rule.rule_id}: duplicate condition_id "
                            f"{c.condition_id!r}")
        seen.add(c.condition_id)
        if c.operator not in SUPPORTED_OPERATORS:
            problems.append(f"{rule.rule_id}/{c.condition_id}: unsupported "
                            f"operator {c.operator!r}")
        if c.canonical_field not in CANONICAL_FIELDS:
            problems.append(
                f"{rule.rule_id}/{c.condition_id}: declares "
                f"{c.canonical_field!r}, which is not a path in the "
                "canonical evidence model")
        if c.operator in _SEQUENCE_OPERATORS and isinstance(
                c.expected, (str, bytes)) or (
                c.operator in _SEQUENCE_OPERATORS and c.expected is None):
            problems.append(
                f"{rule.rule_id}/{c.condition_id}: operator {c.operator!r} "
                "expects a sequence of values")
        if not c.note:
            problems.append(f"{rule.rule_id}/{c.condition_id}: every "
                            "declared condition must say what it means")
    return problems


def citation_proof(rule: DetectionRuleContent) -> Dict[str, Any]:
    """Does the declaration EXPLAIN this rule's own positive fixtures?

    Returns the per-fixture outcome plus `cited_fixtures`: how many positive
    fixtures produced a citation with at least one matched condition. Zero
    means the declaration explains nothing the rule fires on.
    """
    outcomes: List[Dict[str, Any]] = []
    cited = 0
    for fx in rule.fixtures:
        if not fx.should_match or not rule.evaluate(fx.event):
            continue
        citation = rule.cite(fx.event, evidence_ref="fixture")
        matched = citation.get("matched_conditions") or []
        evaluated = citation.get("evaluated_conditions") or []
        all_present = bool(evaluated) and all(
            row.get("field_state") == "PRESENT" for row in evaluated)
        if matched:
            cited += 1
        outcomes.append({
            "fixture": fx.name,
            "matched_conditions": len(matched),
            "all_declared_fields_present": all_present,
            "explained": bool(matched),
        })
    return {"rule_id": rule.rule_id, "positive_fixtures": len(outcomes),
            "cited_fixtures": cited, "fixtures": outcomes}


def report(rules: List[DetectionRuleContent]) -> Dict[str, Any]:
    """Operator-facing truth about declaration coverage."""
    declared = [r for r in rules if r.conditions]
    undeclared = [r for r in rules if not r.conditions]
    problems: List[str] = []
    for r in rules:
        problems.extend(validate_rule(r))
    unexplained = [p["rule_id"] for p in (citation_proof(r) for r in declared)
                   if p["positive_fixtures"] and not p["cited_fixtures"]]
    return {
        "rules_total": len(rules),
        "declared": sorted(r.rule_id for r in declared),
        "undeclared": sorted(r.rule_id for r in undeclared),
        "declaration_debt": sorted(DECLARATION_DEBT),
        "declaration_coverage": (f"{len(declared)}/{len(rules)}"),
        "contract_problems": problems,
        "declared_but_unexplained": unexplained,
        "telemetry_gaps": TELEMETRY_GAPS,
        "closed_telemetry_gaps": sorted(CLOSED_TELEMETRY_GAPS),
        "known_fixture_defects": sorted(KNOWN_FIXTURE_DEFECTS),
        "predicate_coverage_findings": sorted(PREDICATE_COVERAGE_FINDINGS),
        "honesty_note": (
            "a rule on the declaration debt ledger produces NO citation and "
            "says so; it is never back-filled by guessing which field "
            "matched. The ledger may only shrink — a new undeclared rule "
            "fails the contract gate."),
    }
