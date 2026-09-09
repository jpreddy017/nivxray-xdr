"""Phase 1 orchestrator — canonical pipeline runner.

Executes the locked Phase 1 stages in order:

    Input Classification → Parser → Vendor Detection → Vendor
    Normalization → CEM → Artifact Discovery → Recursive Decoder →
    Evidence Extraction → Investigation Graph → Evidence Validation

Returns an `InvestigationState` — the single aggregate root
(Addendum A, Contract #5). Every future stage (Correlation, Timeline,
Attack Chain, Hypothesis, Root Cause, Narrative) will consume THIS.

The state also carries an `answer_contract` used by the Contract #11
Investigation Acceptance check (see `contract_check.py`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from nivxforge.investigation.cem import CanonicalEventModel
from .artifact_discovery import DiscoveredArtifactRef, discover
from .entity_resolution import EntityMerge, resolve_entities
from .evidence_extraction import EvidenceBundle, extract
from .evidence_validation import ValidationReport, validate
from .graph_builder import InvestigationGraph, build
from .input_classification import InputClassification, classify_input
from .normalizers import normalize
from .parser import ParsedInput, parse_input
from .recursive_decoder import DecodedLayer, decode
from .vendor_detection import VendorDetection, detect_vendor


@dataclass
class InvestigationState:
    """Contract #5 aggregate root for a Phase-1 investigation."""
    raw_input: str
    classification: InputClassification
    parsed: ParsedInput
    vendor: VendorDetection
    cem: CanonicalEventModel
    artifacts: List[DiscoveredArtifactRef]
    decoded: List[DecodedLayer]
    evidence: EvidenceBundle
    graph: InvestigationGraph
    validation: ValidationReport
    entity_merges: Tuple[EntityMerge, ...] = tuple()
    stage_trace: List[Dict[str, Any]] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.kind,
            "vendor": self.vendor.vendor,
            "vendor_confidence": self.vendor.confidence,
            "events": len(self.cem.events),
            "incidents": len(self.cem.incidents),
            "artifacts": len(self.artifacts),
            "decoded_layers": len(self.decoded),
            "graph_nodes": len(self.graph.nodes),
            "graph_edges": len(self.graph.edges),
            "validation": self.validation.summary(),
        }


def run_phase1(raw_input: str) -> InvestigationState:
    """Execute the locked Phase 1 pipeline in strict order."""
    trace: List[Dict[str, Any]] = []

    classification = classify_input(raw_input)
    trace.append({"stage": "input_classification",
                   "kind": classification.kind,
                   "confidence": classification.confidence})

    parsed = parse_input(raw_input, classification)
    trace.append({"stage": "parser",
                   "records": len(parsed.records),
                   "diagnostics": parsed.diagnostics})

    vendor = detect_vendor(parsed)
    trace.append({"stage": "vendor_detection",
                   "vendor": vendor.vendor,
                   "confidence": vendor.confidence,
                   "matched_keys": vendor.matched_keys})

    cem = normalize(parsed, vendor)
    trace.append({"stage": "vendor_normalization",
                   "events": len(cem.events),
                   "incidents": len(cem.incidents),
                   "route": cem.vendor_route})

    artifacts = discover(cem)
    trace.append({"stage": "artifact_discovery",
                   "artifacts": len(artifacts)})

    decoded = decode(artifacts)
    trace.append({"stage": "recursive_decoder",
                   "layers": len(decoded)})

    evidence = extract(cem, artifacts, decoded)
    trace.append({"stage": "evidence_extraction",
                   "items": len(evidence.items)})

    graph = build(cem, evidence)
    trace.append({"stage": "investigation_graph",
                   "nodes": len(graph.nodes),
                   "edges": len(graph.edges)})

    # Phase 2 · Entity Resolution — collapse HOST01 + 10.1.1.15 +
    # host01.contoso.local into a single canonical Host node so
    # every downstream stage (Timeline, Attack Chain, Correlation)
    # reasons about entities rather than duplicate identifiers.
    graph, entity_merges = resolve_entities(graph)
    trace.append({"stage": "entity_resolution",
                   "merges": len(entity_merges),
                   "nodes_after": len(graph.nodes)})

    validation = validate(graph)
    trace.append({"stage": "evidence_validation",
                   "findings": validation.summary()})

    return InvestigationState(
        raw_input=raw_input,
        classification=classification,
        parsed=parsed,
        vendor=vendor,
        cem=cem,
        artifacts=artifacts,
        decoded=decoded,
        evidence=evidence,
        graph=graph,
        validation=validation,
        entity_merges=entity_merges,
        stage_trace=trace,
    )


__all__ = ["InvestigationState", "run_phase1"]
