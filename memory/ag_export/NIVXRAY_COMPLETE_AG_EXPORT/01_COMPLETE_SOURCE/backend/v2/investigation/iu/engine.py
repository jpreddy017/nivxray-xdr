"""Input Understanding Engine.

`classify(text)` runs every detector, aggregates positive signals,
then produces an ArtefactClassification that answers the four
questions the stage is responsible for:
    1. What artefact(s) am I looking at?  (primary + embedded[])
    2. How confident am I?                (confidence + evidence)
    3. What evidence supports it?         (Evidence[] canonical)
    4. Which capabilities should run?     (dispatch[])
"""
from __future__ import annotations

import hashlib
import json

from ..evidence import Evidence
from .detectors import DETECTOR_REGISTRY
from .models import ArtefactClassification, ArtefactType, Capability


def classify(text: str) -> ArtefactClassification:
    """Deterministic multi-artefact classifier."""
    text = text or ""
    hits: list[tuple[Evidence, ArtefactType, tuple[Capability, ...]]] = []

    for detector in DETECTOR_REGISTRY:
        ev = detector.score(text)
        if ev is None:
            continue
        hits.append((ev, detector.ARTEFACT_TYPE, detector.CAPABILITIES))

    if not hits:
        # Nothing matched — classify as UNKNOWN but still emit an
        # evidence trail so the analyst sees WHY we couldn't classify.
        no_evidence = Evidence(
            source="input_understanding.engine",
            observation=(text[:80] + "…") if len(text) > 80 else text,
            confidence=0,
            rationale=("No detector matched this input — classified as "
                        "UNKNOWN so downstream engines fall back to "
                        "generic decoders. Add a detector for this "
                        "artefact type to close the gap."),
            meta={"detector": "engine.fallback"},
        )
        result = ArtefactClassification(
            primary_type=ArtefactType.UNKNOWN,
            embedded=[],
            confidence=0,
            evidence=[no_evidence],
            dispatch=[Capability.DECODER, Capability.IOC],
        )
        result.determinism_hash = _hash(result)
        return result

    # Pick the highest-confidence hit as PRIMARY. Ties broken by
    # registry order (which is roughly outermost-wrapper-first).
    hits.sort(key=lambda h: (-h[0].confidence, DETECTOR_REGISTRY.index(
        next(d for d in DETECTOR_REGISTRY if d.ARTEFACT_TYPE == h[1])
    )))
    primary_ev, primary_type, primary_caps = hits[0]

    # Every OTHER positive detector becomes an EMBEDDED artefact — a
    # first-class nested finding, per the multi-artefact architectural
    # decision. Preserved in registry order so wmic → cmd → ps → js
    # nesting is faithful to how the analyst reads the input.
    seen_types = {primary_type}
    embedded: list[ArtefactType] = []
    all_evidence: list[Evidence] = [primary_ev]
    all_caps: list[Capability] = list(primary_caps)
    for ev, at, caps in hits[1:]:
        all_evidence.append(ev)
        if at in seen_types:
            continue
        seen_types.add(at)
        embedded.append(at)
        for c in caps:
            if c not in all_caps:
                all_caps.append(c)

    # Aggregate confidence — capped at primary's own confidence
    # (nested artefacts can only strengthen it, never dilute it).
    conf = primary_ev.confidence

    result = ArtefactClassification(
        primary_type=primary_type,
        embedded=embedded,
        confidence=conf,
        evidence=all_evidence,
        dispatch=all_caps,
    )
    result.determinism_hash = _hash(result)
    return result


def _hash(c: ArtefactClassification) -> str:
    """SHA-256 of the canonical serialization for regression proofs."""
    blob = json.dumps({
        "primary":  c.primary_type.value,
        "embedded": [t.value for t in c.embedded],
        "conf":     c.confidence,
        "evidence": [e.to_dict() for e in c.evidence],
        "dispatch": [c_.value for c_ in c.dispatch],
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()
