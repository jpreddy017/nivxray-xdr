"""Evidence Graph builder — walks an ``InvestigationResult`` and
produces the homogeneous DAG defined in :mod:`.models`.

Deterministic and side-effect-free.
"""
from __future__ import annotations

from ..cre.models import CommandReconstruction
from ..intent.models import IntentAssessment
from ..iu.models import ArtefactClassification
from ..rte.models import TransformationChain
from .models import EdgeKind, EvidenceEdge, EvidenceGraph, EvidenceNode, NodeKind


def build(
    *,
    input_text: str,
    iu: ArtefactClassification,
    cre: CommandReconstruction | None,
    rte: TransformationChain,
    intent: IntentAssessment,
) -> EvidenceGraph:
    """Assemble the Evidence Graph for a single investigation."""
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []

    # ── Input node ─────────────────────────────────────────────
    input_id = "input"
    nodes.append(EvidenceNode(
        id=input_id,
        kind=NodeKind.INPUT,
        label="Raw input",
        detail=(input_text[:160] + "…") if len(input_text) > 160 else input_text,
    ))

    # ── IU classification ──────────────────────────────────────
    iu_id = "iu"
    nodes.append(EvidenceNode(
        id=iu_id,
        kind=NodeKind.ARTEFACT_TYPE,
        label=iu.primary_type.value,
        detail=(f"IU classified the input as `{iu.primary_type.value}` "
                 f"with {len(iu.embedded)} embedded artefact(s)."),
        confidence=iu.confidence,
        source="input_understanding",
    ))
    edges.append(EvidenceEdge(src=input_id, dst=iu_id, kind=EdgeKind.PRODUCES))
    for i, ev in enumerate(iu.evidence):
        ev_id = f"iu_ev_{i}"
        nodes.append(EvidenceNode(
            id=ev_id, kind=NodeKind.EVIDENCE, label=ev.observation[:80],
            detail=ev.rationale, confidence=ev.confidence, source=ev.source,
        ))
        edges.append(EvidenceEdge(src=ev_id, dst=iu_id, kind=EdgeKind.SUPPORTS))

    # ── CRE wrapper chain ──────────────────────────────────────
    last_id = iu_id
    if cre and cre.chain:
        for i, step in enumerate(cre.chain):
            step_id = f"cre_{i}"
            nodes.append(EvidenceNode(
                id=step_id,
                kind=NodeKind.WRAPPER,
                label=step.wrapper,
                detail=(step.evidence or "")[:200],
                confidence=step.confidence,
                source=f"cre.{step.wrapper}",
            ))
            edges.append(EvidenceEdge(src=last_id, dst=step_id, kind=EdgeKind.DERIVES_FROM))
            last_id = step_id
        # Final effective payload
        eff_id = "cre_effective"
        nodes.append(EvidenceNode(
            id=eff_id, kind=NodeKind.LAYER, label="Effective payload",
            detail=(cre.effective_payload[:200] +
                     ("…" if len(cre.effective_payload) > 200 else "")),
            source="cre",
        ))
        edges.append(EvidenceEdge(src=last_id, dst=eff_id, kind=EdgeKind.PRODUCES))
        last_id = eff_id

    # ── RTE transformation chain ───────────────────────────────
    for i, step in enumerate(rte.steps):
        step_id = f"rte_step_{i}"
        nodes.append(EvidenceNode(
            id=step_id, kind=NodeKind.TRANSFORMATION,
            label=step.transformation,
            detail=(f"Transformation applied to layer {step.input_layer} "
                     f"→ layer {step.output_layer}."),
            confidence=step.confidence,
            source=f"rte.{step.transformation}",
        ))
        edges.append(EvidenceEdge(src=last_id, dst=step_id, kind=EdgeKind.DERIVES_FROM))
        # cite the step's evidence
        for ei, ev in enumerate(step.evidence):
            ev_id = f"rte_step_{i}_ev_{ei}"
            nodes.append(EvidenceNode(
                id=ev_id, kind=NodeKind.EVIDENCE, label=ev.observation[:80],
                detail=ev.rationale, confidence=ev.confidence, source=ev.source,
            ))
            edges.append(EvidenceEdge(src=ev_id, dst=step_id, kind=EdgeKind.SUPPORTS))
        # The new layer becomes ``last_id``
        layer_id = f"rte_layer_{step.output_layer}"
        target_artifact = rte.artifacts[step.output_layer] if step.output_layer < len(rte.artifacts) else None
        nodes.append(EvidenceNode(
            id=layer_id, kind=NodeKind.LAYER,
            label=f"Layer {step.output_layer}",
            detail=(target_artifact.content[:200] if target_artifact else "")
                    + ("…" if target_artifact and len(target_artifact.content) > 200 else ""),
            source="rte",
        ))
        edges.append(EvidenceEdge(src=step_id, dst=layer_id, kind=EdgeKind.PRODUCES))
        last_id = layer_id

    # ── Semantic Intent nodes ──────────────────────────────────
    for i, intn in enumerate(intent.intents):
        intent_id = f"intent_{i}"
        nodes.append(EvidenceNode(
            id=intent_id, kind=NodeKind.INTENT,
            label=intn.category.value,
            detail=intn.purpose,
            confidence=intn.confidence,
            source="intent",
            meta={"risk": intn.risk.value, "mitre_ids": list(intn.mitre_ids)},
        ))
        # Intent derives from the deepest artefact we could reach.
        edges.append(EvidenceEdge(src=last_id, dst=intent_id, kind=EdgeKind.DERIVES_FROM))
        for ei, ev in enumerate(intn.evidence):
            ev_id = f"intent_{i}_ev_{ei}"
            nodes.append(EvidenceNode(
                id=ev_id, kind=NodeKind.EVIDENCE, label=ev.observation[:80],
                detail=ev.rationale, confidence=ev.confidence, source=ev.source,
            ))
            edges.append(EvidenceEdge(src=ev_id, dst=intent_id, kind=EdgeKind.SUPPORTS))

    return EvidenceGraph(nodes=nodes, edges=edges)


__all__ = ["build"]
