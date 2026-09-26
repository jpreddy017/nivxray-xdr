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
                                        Capability, DetectionSource,
                                        EvidenceUnit, Finding,
                                        InferenceLocation,
                                        NOT_RECORDED_BY_SOURCE, Outcome,
                                        Severity)
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

#: The producing RULE's own severity vocabulary, as the detection content
#: records it. It is read, never re-scored.
_RULE_SEVERITY: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
}


def _attck(recorded) -> List[str]:
    """Technique ids exactly as the producing rule declared them."""
    out: List[str] = []
    for t in (recorded or []):
        if isinstance(t, dict):
            tid = t.get("id") or t.get("technique_id")
        else:
            tid = t
        if tid and str(tid) not in out:
            out.append(str(tid))
    return out


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
            ref = d.get("event_id") or unit.evidence_ref
            engine = str(d.get("detection_content_version")
                         or self.version)
            citations = [c for c in unit.detection_citations
                         if not c.get("rule_id") or not rules
                         or c.get("rule_id") in rules]
            for spec in (citations or [{"rule_id": r} for r in rules]
                         or [{}]):
                findings.append(self._project(
                    unit=unit, derivation=d, spec=spec, ref=ref,
                    engine=engine, verdict_hint=verdict_hint,
                    all_rules=rules))

        if findings:
            return AnalyzerResult(analyzer_id=self.id,
                                  outcome=Outcome.FINDINGS,
                                  findings=findings)
        return AnalyzerResult(analyzer_id=self.id,
                              outcome=Outcome.EVALUATED_NO_FINDING)

    def _project(self, *, unit: EvidenceUnit, derivation: Dict,
                 spec: Dict, ref: str, engine: str, verdict_hint: str,
                 all_rules: List[str]) -> Finding:
        """ONE finding per producing RULE, carrying the producing source's
        own recorded values. Nothing the source did not record is
        invented — an absent value is persisted as absent, with the
        reason it is absent."""
        rule_id = spec.get("rule_id")
        rule_severity = str(spec.get("severity") or "").strip().lower()
        severity = _RULE_SEVERITY.get(rule_severity)
        if severity is not None:
            severity_basis = (f"PRODUCING_RULE_SEVERITY · "
                              f"{spec.get('rule_id')} recorded "
                              f"'{rule_severity}'")
        elif verdict_hint:
            severity = _SEVERITY_HINT.get(verdict_hint)
            severity_basis = (
                f"DERIVED_FROM_SOURCE_VERDICT_LABEL · the producing rule "
                f"recorded no severity; the XDR pipeline recorded verdict "
                f"label '{verdict_hint}' for this evidence"
                if severity is not None else
                f"{NOT_RECORDED_BY_SOURCE} · neither the producing rule "
                f"nor the pipeline verdict label maps to a severity")
        else:
            severity_basis = (f"{NOT_RECORDED_BY_SOURCE} · the producing "
                              f"source recorded no severity for this "
                              f"detection")
        confidence_label = spec.get("confidence")
        confidence = (float(confidence_label)
                      if isinstance(confidence_label, (int, float))
                      else None)
        if confidence is not None:
            confidence_basis = ("PRODUCING_RULE_CONFIDENCE · numeric, on "
                                "the producing rule's own scale")
            confidence_scale = "PRODUCING_RULE_NUMERIC_SCALE"
            confidence_label = None
        elif confidence_label:
            confidence_basis = (
                f"PRODUCING_RULE_CONFIDENCE · the rule records a "
                f"CATEGORICAL label ('{confidence_label}'), not a numeric "
                f"score; no number is invented from it")
            confidence_scale = None
        else:
            confidence_basis = (f"{NOT_RECORDED_BY_SOURCE} · the producing "
                                f"source recorded no confidence for this "
                                f"detection")
            confidence_scale = None
            confidence_label = None
        attck = _attck(spec.get("mitre_attack"))
        attck_basis = ("PRODUCING_RULE_MITRE_MAPPING"
                       if attck else
                       f"{NOT_RECORDED_BY_SOURCE} · the producing rule "
                       f"declared no ATT&CK technique for this detection")
        features = {"rule_id": rule_id,
                    "all_matched_rule_ids": all_rules,
                    "source_canonical_event_id":
                        spec.get("canonical_event_id"),
                    "detection_content_version":
                        derivation.get("detection_content_version"),
                    "ingest_verdict_label": verdict_hint or None}
        return Finding(
            tenant_id=unit.tenant_id,
            endpoint_ref=unit.endpoint_ref,
            analyzer_id=self.id,
            analyzer_class=self.analyzer_class,
            analyzer_version=engine,
            detection_source=(
                DetectionSource.XDR_PLATFORM_DETERMINISTIC_DETECTION),
            detection_source_detail=(
                f"produced by the NivXRay XDR ingest detection pipeline "
                f"(engine {engine}); projected into the NivXForge EDR "
                f"finding plane without re-evaluation"),
            rule_id=rule_id,
            rule_version=(str(spec["rule_version"])
                          if spec.get("rule_version") is not None else None),
            rule_name=spec.get("rule_name"),
            severity=severity,
            severity_basis=severity_basis,
            confidence=confidence,
            confidence_scale=confidence_scale,
            confidence_label=(str(confidence_label)
                              if confidence_label else None),
            confidence_basis=confidence_basis,
            attck=attck,
            attck_basis=attck_basis,
            label=("deterministic detection content matched "
                   + (rule_id or "an unnamed rule (the rule id was not "
                                 "recorded on the derivation)")),
            evidence_refs=[ref],
            observed_at=unit.observed_at,
            evaluation_time=str(derivation.get("derived_at")
                                or unit.observed_at or ""),
            severity_hint=(severity or Severity.INFORMATIONAL),
            features=features,
            analysis_basis=("projected from the detection derivation "
                            "recorded at ingest; this analyzer does not "
                            "re-run detection and does not invent a "
                            "rule that was not recorded"),
            inference_location=self.inference_location,
        )


ANALYZER = registry.register(DeterministicRuleAnalyzer())
