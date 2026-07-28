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
    DecodeDiagnostic,
    StopReason,
    TransformationChain,
    TransformationStep,
)
from .transformations import TRANSFORMATION_REGISTRY, Transformation

# Safety cap. Historical observation cap was 24; v1.5.0 raised it to
# 64 (2026-07-28) to accommodate multi-stage PowerShell loaders that
# chain UTF-16LE base64 → gzip → base64 → deflate → … The stopping
# invariants (NO_TRANSFORMATION, LOOP via content-hash, MAX_DEPTH,
# UNSUPPORTED) remain the sole termination conditions.
DEFAULT_MAX_DEPTH = 64


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


def _collect_diagnostics(artifact: Artifact) -> list[DecodeDiagnostic]:
    """Ask every transformation plugin if it *detected* a pattern on
    this artifact but couldn't decode it.

    Called only at the point where the engine is about to stop with
    ``NO_TRANSFORMATION`` — the analyst deserves to know WHY. Any plugin
    that exposes an optional ``diagnose(artifact)`` method may return a
    :class:`DecodeDiagnostic` (or list thereof) explaining the
    detected-but-uncoded state.

    Determinism guarantee: diagnostics are returned in registry order
    and a raising plugin never derails the whole diagnostic pass.
    """
    diags: list[DecodeDiagnostic] = []
    for t in TRANSFORMATION_REGISTRY:
        diagnose = getattr(t, "diagnose", None)
        if diagnose is None:
            continue
        try:
            result = diagnose(artifact)
        except Exception:
            continue
        if result is None:
            continue
        if isinstance(result, DecodeDiagnostic):
            diags.append(result)
        elif isinstance(result, list):
            diags.extend(d for d in result if isinstance(d, DecodeDiagnostic))
    return diags


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
    diagnostics_at_stop: list[DecodeDiagnostic] = []

    while True:
        current = artifacts[-1]
        if current.layer >= max_depth:
            stop_reason = StopReason.MAX_DEPTH
            break

        picked = _pick(current)
        if picked is None:
            stop_reason = StopReason.NO_TRANSFORMATION
            # Before stopping, ask every plugin for a diagnostic on the
            # current layer. This gives the analyst a deterministic
            # "why did the pipeline stop" explanation instead of a
            # silent NO_TRANSFORMATION — required by v1.5.0 DoD.
            diagnostics_at_stop = _collect_diagnostics(current)
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
        diagnostics=diagnostics_at_stop,
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
        # v1.5.0 · include diagnostics in the determinism hash so
        # analysts can trust that identical inputs also produce
        # identical failure-explanations.
        "diagnostics": [{
            "layer":     d.layer,
            "detector":  d.detector,
            "outcome":   d.outcome,
            "attempted": d.attempted,
        } for d in chain.diagnostics],
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


__all__ = ["transform", "DEFAULT_MAX_DEPTH"]
