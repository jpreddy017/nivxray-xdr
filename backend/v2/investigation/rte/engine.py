"""Recursive Transformation Engine (RTE) · orchestrator.

Repeatedly applies the highest-confidence applicable transformation,
reclassifying via Input Understanding after every step, until one of
the principled stop conditions is reached.

Guarantees:
    · every intermediate artefact is preserved
    · every step emits canonical Evidence
    · loops are detected via a content-hash set
    · maximum recursion depth is capped so runaway inputs cannot hang
    · deterministic — identical input produces byte-identical output
"""
from __future__ import annotations

import hashlib
import json

from ..evidence import Evidence
from ..iu import classify
from .models import (
    Artifact,
    StopReason,
    TransformationChain,
    TransformationStep,
)
from .transformations import TRANSFORMATION_REGISTRY, Transformation

# Safety cap. 24 layers is far beyond any real-world sample we've
# seen (the deepest observed adversarial chain to date is 8 layers).
DEFAULT_MAX_DEPTH = 24


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]


def _make_artifact(content: str, *, layer: int, parent_hash: str | None) -> Artifact:
    return Artifact(
        content=content,
        classification=classify(content),
        layer=layer,
        content_hash=_hash(content),
        parent_hash=parent_hash,
        meta={},
    )


def _pick(artifact: Artifact) -> tuple[Transformation, Evidence] | None:
    """Choose the highest-confidence applicable transformation.

    Ties are broken by registry order for determinism.
    """
    best: tuple[Transformation, Evidence] | None = None
    for t in TRANSFORMATION_REGISTRY:
        try:
            ev = t.applicable(artifact)
        except Exception:
            # A plugin MUST NOT raise on well-formed input; but if one
            # does, we must not derail the whole chain. Skip and move on.
            continue
        if ev is None:
            continue
        if best is None or ev.confidence > best[1].confidence:
            best = (t, ev)
    return best


def transform(text: str, *, max_depth: int = DEFAULT_MAX_DEPTH) -> TransformationChain:
    """Run the recursive transformation loop on ``text``.

    Returns a :class:`TransformationChain` capturing every layer and
    every transformation. Callers get the effective plaintext via
    ``result.final.content`` and the full history via ``result.artifacts``.
    """
    text = text or ""
    if not text.strip():
        original = _make_artifact(text, layer=0, parent_hash=None)
        chain = TransformationChain(
            artifacts=[original],
            steps=[],
            stop_reason=StopReason.EMPTY_INPUT,
        )
        chain.determinism_hash = _chain_hash(chain)
        return chain

    original = _make_artifact(text, layer=0, parent_hash=None)
    artifacts: list[Artifact] = [original]
    steps: list[TransformationStep] = []
    seen: set[str] = {original.content_hash}
    stop_reason = StopReason.NO_TRANSFORMATION

    while True:
        current = artifacts[-1]
        if current.layer >= max_depth:
            stop_reason = StopReason.MAX_DEPTH
            break

        picked = _pick(current)
        if picked is None:
            stop_reason = StopReason.NO_TRANSFORMATION
            break

        transformation, applicability_ev = picked
        try:
            new_content, apply_evidence = transformation.apply(current)
        except Exception as exc:
            # A plugin failing here is a bug — we do NOT fabricate a
            # transformation. Stop cleanly and record why.
            steps.append(TransformationStep(
                transformation=transformation.NAME,
                input_layer=current.layer,
                output_layer=current.layer,
                input_hash=current.content_hash,
                output_hash=current.content_hash,
                input_length=len(current.content),
                output_length=len(current.content),
                evidence=[
                    applicability_ev,
                    Evidence(
                        source=f"rte.{transformation.NAME}",
                        observation=f"apply() raised {type(exc).__name__}: {exc}",
                        confidence=0,
                        rationale=(
                            "Transformation was applicable but raised while "
                            "executing. Loop halted so no fabricated output is "
                            "emitted downstream."
                        ),
                        meta={},
                    ),
                ],
                confidence=applicability_ev.confidence,
            ))
            stop_reason = StopReason.UNSUPPORTED
            break

        new_hash = _hash(new_content)
        if new_hash in seen:
            # Loop guard — the transformation cycled back to a previous state.
            steps.append(TransformationStep(
                transformation=transformation.NAME,
                input_layer=current.layer,
                output_layer=current.layer,
                input_hash=current.content_hash,
                output_hash=new_hash,
                input_length=len(current.content),
                output_length=len(new_content),
                evidence=[
                    applicability_ev,
                    Evidence(
                        source=f"rte.{transformation.NAME}",
                        observation=f"output reproduced a previously-seen state ({new_hash})",
                        confidence=applicability_ev.confidence,
                        rationale=(
                            "Loop guard triggered: this transformation would "
                            "have re-produced an earlier layer. Halted to "
                            "prevent infinite recursion."
                        ),
                        meta={"repeated_hash": new_hash},
                    ),
                ],
                confidence=applicability_ev.confidence,
            ))
            stop_reason = StopReason.LOOP
            break

        seen.add(new_hash)
        new_layer = current.layer + 1
        new_artifact = Artifact(
            content=new_content,
            classification=classify(new_content),
            layer=new_layer,
            content_hash=new_hash,
            parent_hash=current.content_hash,
            meta={"produced_by": transformation.NAME},
        )
        artifacts.append(new_artifact)
        steps.append(TransformationStep(
            transformation=transformation.NAME,
            input_layer=current.layer,
            output_layer=new_layer,
            input_hash=current.content_hash,
            output_hash=new_hash,
            input_length=len(current.content),
            output_length=len(new_content),
            evidence=[applicability_ev, *apply_evidence],
            confidence=applicability_ev.confidence,
        ))

    chain = TransformationChain(
        artifacts=artifacts,
        steps=steps,
        stop_reason=stop_reason,
    )
    chain.determinism_hash = _chain_hash(chain)
    return chain


def _chain_hash(chain: TransformationChain) -> str:
    """SHA-256 of the canonical serialization — used to prove
    deterministic replay across runs."""
    blob = json.dumps({
        "layers": [{
            "layer": a.layer,
            "hash":  a.content_hash,
            "type":  a.classification.primary_type.value,
        } for a in chain.artifacts],
        "steps": [{
            "t":        s.transformation,
            "in":       s.input_hash,
            "out":      s.output_hash,
            "conf":     s.confidence,
        } for s in chain.steps],
        "stop": chain.stop_reason.value,
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


__all__ = ["transform", "DEFAULT_MAX_DEPTH"]
