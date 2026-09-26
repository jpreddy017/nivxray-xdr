"""
NivXRay XDR — Enterprise Detection Content Models.
Provides strongly-typed models for high-fidelity enterprise detections.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any, Callable, Dict, List, Optional


class Tactic(str, Enum):
    INITIAL_ACCESS      = "Initial Access"
    EXECUTION           = "Execution"
    PERSISTENCE         = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION     = "Defense Evasion"
    CREDENTIAL_ACCESS   = "Credential Access"
    DISCOVERY           = "Discovery"
    LATERAL_MOVEMENT    = "Lateral Movement"
    COLLECTION          = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION        = "Exfiltration"
    IMPACT              = "Impact"


class Platform(str, Enum):
    WINDOWS    = "windows"
    LINUX      = "linux"
    MACOS      = "macos"
    CLOUD      = "cloud"
    IDENTITY   = "identity"
    HYPERVISOR = "hypervisor"
    CONTAINER  = "container"


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class DetectionFixture:
    """A positive or negative verification fixture for a rule."""
    name: str
    event: Dict[str, Any]
    should_match: bool
    rationale: str = ""


@dataclass
class RuleCondition:
    """D8 · a condition a rule DECLARES that it evaluates.

    The declaration is the only source of truth for what gets cited. The
    engine never infers which field caused a match after the fact: an
    undeclared rule produces no citation and says so, because a wrong
    citation is worse than an absent one.
    """
    condition_id: str
    canonical_field: str                 # dotted path into canonical evidence
    operator: str
    expected: Any = None                 # value / pattern / tuple of prefixes
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        exp = self.expected
        if hasattr(exp, "pattern"):
            exp = exp.pattern
        if not isinstance(exp, (str, int, float, bool, type(None))):
            exp = list(exp) if isinstance(exp, (list, tuple)) else str(exp)
        return {"condition_id": self.condition_id,
                "canonical_field": self.canonical_field,
                "operator": self.operator,
                "expected": exp,
                "note": self.note}


def resolve_field(event: Dict[str, Any], path: str) -> tuple:
    """Read a dotted path out of the canonical event.

    Returns `(value, state)` where state is `PRESENT`, `NULL` or `ABSENT`.
    The three are kept distinct on purpose: a field that was never
    collected is not the same claim as one observed to be empty.
    """
    cur: Any = event
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None, "ABSENT"
        cur = cur[part]
    if cur is None or cur == "":
        return cur, "NULL"
    return cur, "PRESENT"


def apply_operator(operator: str, observed: Any, expected: Any) -> bool:
    if operator == "exists":
        return True
    if operator == "equals":
        return observed == expected
    if operator == "contains":
        return isinstance(observed, str) and str(expected) in observed
    # D17 · the case-insensitive operators. Every command-line predicate in
    # the library lowercases before comparing, so a case-SENSITIVE
    # declaration would report NO_MATCH on the very event that fired the
    # rule. Adding the operator is what lets a declaration describe the
    # predicate faithfully instead of approximately.
    if operator == "contains_ci":
        return (isinstance(observed, str)
                and str(expected).lower() in observed.lower())
    if operator == "contains_any_ci":
        return (isinstance(observed, str)
                and any(str(e).lower() in observed.lower()
                        for e in expected))
    if operator == "contains_all_ci":
        return (isinstance(observed, str)
                and all(str(e).lower() in observed.lower()
                        for e in expected))
    if operator == "basename_in_ci":
        if not isinstance(observed, str):
            return False
        base = observed.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return base in {str(e).lower() for e in expected}
    # D19 · a cloud authorization decision lives inside a structured
    # request-parameter document. It is searched as TEXT, and the
    # declaration says so rather than pretending to understand the schema.
    if operator == "serialized_contains_any_ci":
        if observed in (None, "", {}, []):
            return False
        try:
            blob = json.dumps(observed, default=str).lower()
        except (TypeError, ValueError):
            blob = str(observed).lower()
        # JSON escaping is an artefact of serialising, not part of the
        # policy text: `"Action":"*"` must not become unmatchable as
        # `\"Action\":\"*\"` simply because it arrived nested as a string.
        blob = blob.replace('\\"', '"').replace("\\\\", "\\")
        return any(str(e).lower() in blob for e in expected)
    if operator == "basename_contains_any_ci":
        if not isinstance(observed, str):
            return False
        base = observed.replace("\\", "/").rsplit("/", 1)[-1].lower()
        return any(str(e).lower() in base for e in expected)
    if operator == "starts_with_any":
        return isinstance(observed, str) and observed.startswith(
            tuple(expected))
    if operator == "basename_in":
        return (isinstance(observed, str)
                and observed.rsplit("/", 1)[-1] in tuple(expected))
    if operator == "matches":
        return (bool(expected.search(observed))
                if isinstance(observed, str) else False)
    if operator == "any_argument_starts_with":
        if not isinstance(observed, str):
            return False
        return any(t.startswith(tuple(expected))
                   for t in observed.split()[1:])
    raise ValueError(f"unknown operator {operator!r}")


@dataclass
class DetectionRuleContent:
    """Authoritative representation of an enterprise detection rule."""
    rule_id: str
    name: str
    description: str
    tactic: Tactic
    technique_id: str
    technique_name: str
    platform: Platform
    severity: Severity
    confidence: str  # low | medium | high | confirmed
    lane: str  # event | endpoint | ioc | network | behavior | content
    predicate: Callable[[Dict[str, Any]], bool]
    telemetry_requirements: List[str]
    false_positive_notes: str = ""
    mitre_attack: List[str] = field(default_factory=list)
    fixtures: List[DetectionFixture] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    #: D8 · bumped by the author on ANY change to predicate or conditions.
    rule_version: str = "1"
    #: D8 · declared conditions. Empty means "not yet declared", which is
    #: reported honestly rather than inferred.
    conditions: List[RuleCondition] = field(default_factory=list)

    def evaluate(self, canonical_event: Dict[str, Any]) -> bool:
        """Evaluate rule predicate against canonical event safely."""
        try:
            return bool(self.predicate(canonical_event))
        except Exception:
            return False

    def cite(self, canonical_event: Dict[str, Any],
             evidence_ref: Optional[str] = None) -> Dict[str, Any]:
        """D8 · evaluate the DECLARED conditions and return the citation.

        This never decides whether the rule matched — `predicate` remains
        the sole authority, so declaring conditions cannot change detection
        behaviour. It records which declared conditions held, on what
        observed value, and from which evidence object.
        """
        if not self.conditions:
            return {"declaration_state": "NOT_DECLARED",
                    "evaluated_conditions": [], "matched_conditions": [],
                    "unmatched_conditions": [],
                    "note": ("this rule has not declared the canonical "
                             "fields it evaluates, so no citation can be "
                             "produced; the matched field is NOT inferred")}
        evaluated: List[Dict[str, Any]] = []
        for c in self.conditions:
            observed, state = resolve_field(canonical_event,
                                            c.canonical_field)
            row = {**c.to_dict(), "observed_value": observed,
                   "field_state": state, "evidence_ref": evidence_ref}
            if state == "ABSENT":
                row["result"] = "FIELD_ABSENT"
            elif state == "NULL":
                row["result"] = "FIELD_NULL"
            else:
                try:
                    row["result"] = ("MATCH" if apply_operator(
                        c.operator, observed, c.expected) else "NO_MATCH")
                except Exception as e:                            # noqa: BLE001
                    row["result"] = "EVALUATION_ERROR"
                    row["error"] = str(e)[:200]
            evaluated.append(row)
        matched = [r for r in evaluated if r["result"] == "MATCH"]
        return {"declaration_state": "DECLARED",
                "evaluated_conditions": evaluated,
                "matched_conditions": matched,
                "unmatched_conditions": [r for r in evaluated
                                         if r["result"] != "MATCH"]}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "tactic": self.tactic.value,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "platform": self.platform.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "lane": self.lane,
            "telemetry_requirements": self.telemetry_requirements,
            "false_positive_notes": self.false_positive_notes,
            "mitre_attack": self.mitre_attack,
            "tags": self.tags,
        }
