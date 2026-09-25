"""GATE 3 · the fabric's first REAL producer: the deterministic plane.

This analyzer invents no new detection engine. The platform already
derives deterministic detections during ingest and records them on
`edr_raw_events.derivations[]` with their content version and the rules
that matched. This projects that existing, authoritative outcome into the
frozen Finding contract, so the fabric has a genuine producer from day
one and every later engine (reputation, static, ML, behavioural) plugs in
beside it without changing anything downstream.

It preserves the three distinct outcomes the ingest plane already
records:

    DETECTION_MATCHED             -> FINDINGS
    DETECTION_EVALUATED_NO_MATCH  -> EVALUATED_NO_FINDING
    DETECTION_NOT_EVALUATED       -> NOT_EVALUATED (with the recorded reason)
    no detection derivation at all -> NOT_EVALUATED ("detection was not
                                      recorded for this evidence")
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from edr_plane.fabric.contracts import (AnalyzerClass, AnalyzerResult,
                                        Capability, EvidenceUnit, Finding,
                                        InferenceLocation, Outcome, Severity)
from edr_plane.fabric import registry

# The ingest plane records the verdict label it derived; it is a HINT to
# the verdict plane here, never an authority of this analyzer's own.
_SEVERITY_HINT: Dict[str, Severity] = {
    "MALICIOUS": Severity.HIGH,
    "SUSPICIOUS": Severity.MEDIUM,
    "LIKELY_BENIGN": Severity.LOW,
    "BENIGN": Severity.INFORMATIONAL,
}

_RULES = re.compile(r"rules?:\s*(.+)$", re.IGNORECASE)


def _rule_ids(reason: Optional[str]) -> List[str]:
    if not reason:
        return []
    m = _RULES.search(reason.strip())
    if not m:
        return []
    return [r.strip() for r in m.group(1).split(",") if r.strip()]


class DeterministicRuleAnalyzer:
    id = "deterministic.rule"
    analyzer_class = AnalyzerClass.DETERMINISTIC
    version = "1.0.0"
    inference_location = InferenceLocation.BACKEND

    def capability(self) -> Capability:
        return Capability(
            evaluates=["process activity against the platform's own "
                       "deterministic detection content"],
            cannot=["file reputation", "static file analysis",
                    "machine-learned scoring", "behavioural sequences",
                    "anomaly detection",
                    "anything the endpoint sensor does not observe "
                    "(files, network, registry)"],
            requires=["a detection derivation recorded at ingest "
                      "(detection_content_version)"])

    def evaluate(self, unit: EvidenceUnit) -> AnalyzerResult:
        detections = [d for d in unit.derivations
                      if str(d.get("outcome", "")).startswith("DETECTION_")]
        if not detections:
            return AnalyzerResult(
                analyzer_id=self.id, outcome=Outcome.NOT_EVALUATED,
                reason=("no detection derivation is recorded for this "
                        "evidence — the deterministic plane did not run, "
                        "which is not a statement that the activity was "
                        "benign"))

        findings: List[Finding] = []
        for d in detections:
            outcome = d.get("outcome")
            if outcome == "DETECTION_NOT_EVALUATED":
                return AnalyzerResult(
                    analyzer_id=self.id, outcome=Outcome.NOT_EVALUATED,
                    reason=(d.get("reason")
                            or "detection was not evaluated for this "
                               "evidence and no reason was recorded"))
            if outcome != "DETECTION_MATCHED":
                continue
            rules = _rule_ids(d.get("reason"))
            verdict_hint = str(d.get("verdict_version") or "")
            features = {"rule_ids": rules,
                        "detection_content_version":
                            d.get("detection_content_version"),
                        "ingest_verdict_label": verdict_hint or None}
            ref = d.get("event_id") or unit.evidence_ref
            findings.append(Finding(
                tenant_id=unit.tenant_id,
                endpoint_ref=unit.endpoint_ref,
                analyzer_id=self.id,
                analyzer_class=self.analyzer_class,
                analyzer_version=str(d.get("detection_content_version")
                                     or self.version),
                label=("deterministic detection content matched "
                       + (", ".join(rules) if rules
                          else "an unnamed rule (the rule id was not "
                               "recorded on the derivation)")),
                evidence_refs=[ref],
                observed_at=unit.observed_at,
                evaluation_time=str(d.get("derived_at")
                                    or unit.observed_at or ""),
                severity_hint=_SEVERITY_HINT.get(verdict_hint,
                                                 Severity.INFORMATIONAL),
                features=features,
                analysis_basis=("projected from the detection derivation "
                                "recorded at ingest; this analyzer does not "
                                "re-run detection and does not invent a "
                                "rule that was not recorded"),
                inference_location=self.inference_location,
            ))

        if findings:
            return AnalyzerResult(analyzer_id=self.id,
                                  outcome=Outcome.FINDINGS,
                                  findings=findings)
        return AnalyzerResult(analyzer_id=self.id,
                              outcome=Outcome.EVALUATED_NO_FINDING)


ANALYZER = registry.register(DeterministicRuleAnalyzer())
