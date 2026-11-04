"""
DIE · Preprocessor · Pipeline
─────────────────────────────
Single deterministic entry point.  Call ``preprocess(raw_text)`` and
receive a ``PreprocessResult`` that is safe to hand to the frozen
v1.1 DIE / DKP / Attack Story / Narrative / Confidence surfaces.

    Raw Input
        ↓
    Input Normalizer
        ↓
    Artifact Extractor
        ↓
    Artifact Classifier
        ↓
    Artifact Router
        ↓
    Command Normalizer
        ↓
    Family Recognizer      (applied per-artifact during Stage Builder)
        ↓
    Stage Builder
        ↓
    Process Relationship Builder
"""
from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List

from .artifact_extractor import extract
from .artifact_router import classify, route
from .command_normalizer import normalize_artifacts
from .decode_telemetry import reset as _reset_decode_layers, snapshot as _snapshot_decode_layers
from .input_normalizer import normalize
from .models import Artifact, ProcessEdge, Stage
from .process_relations import build_edges
from .recursive_decoder import peel_recursively
from .stage_builder import build_stages, add_prose_phrase_stages


@dataclass
class PreprocessResult:
    raw:               str
    normalized_text:   str
    artifacts:         List[Artifact]
    stages:            List[Stage]
    process_edges:     List[ProcessEdge]
    stats:             Dict[str, Any] = field(default_factory=dict)
    decode_layers:     List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw":             self.raw,
            "normalized_text": self.normalized_text,
            "artifacts":       [a.to_dict() for a in self.artifacts],
            "stages":          [s.to_dict() for s in self.stages],
            "process_edges":   [e.to_dict() for e in self.process_edges],
            "stats":           dict(self.stats),
            "decode_layers":   list(self.decode_layers),
        }

    # Convenience.
    def stage_count(self) -> int:
        return len(self.stages)

    def has_family(self, family_id: str) -> bool:
        return any(s.command_family == family_id for s in self.stages)

    def artifacts_by_type(self, type_: str) -> List[Artifact]:
        return [a for a in self.artifacts if a.type == type_]

    def normalized_commands(self) -> List[str]:
        return [s.normalized_command for s in self.stages
                if s.normalized_command and s.kind == "command"]


def preprocess(raw_text: str) -> PreprocessResult:
    if raw_text is None:
        raw_text = ""

    # Rule R24 · guarantee #5 — reset the per-call decode-layer buffer
    # so any decoder-emitted `record_layer()` between now and the end
    # of this call becomes part of THIS PreprocessResult's trace.
    _reset_decode_layers()

    # ── R23/R24 · Recursive Multi-Layer Decoder ────────────────────
    # Peel every recognisable encoding layer until nothing decodable
    # remains (bounded by MAX_LAYERS + no-progress detector).  This
    # is the fix for the "output equals input" / "decoded only one
    # layer" bug on multi-stage PowerShell loaders (Encoded →
    # FromBase64String → GZip → IEX).  Both the raw text AND the
    # fully-peeled text are fed to the extractor so every layer's
    # commands + IOCs surface.
    peeled_text, _peel_layers = peel_recursively(raw_text)
    if peeled_text and peeled_text != raw_text:
        # Feed BOTH the original and the peeled payload to the
        # extractor — the outer layers (cmd launcher, PS shim) stay
        # in the SSOT, the inner payload gets fully parsed.  This
        # preserves provenance while unlocking downstream analysis.
        combined_for_extraction = raw_text + "\n\n# --- decoded (recursive) ---\n" + peeled_text
    else:
        combined_for_extraction = raw_text

    ni = normalize(combined_for_extraction)
    artifacts = extract(ni)
    artifacts = classify(artifacts)
    artifacts = normalize_artifacts(artifacts)
    artifacts = route(artifacts)
    stages = build_stages(artifacts)
    stages = add_prose_phrase_stages(stages, ni.text, ni.line_starts)
    # Final deterministic renumber.
    for i, s in enumerate(stages, start=1):
        s.index = i
    edges = build_edges(stages)

    # Aggregate stats for observability / narrative surfaces.
    stats: Dict[str, Any] = {
        "input_bytes":      len(raw_text or ""),
        "artifact_count":   len(artifacts),
        "stage_count":      len(stages),
        "edge_count":       len(edges),
        "types":            {},
        "families":         {},
    }
    for a in artifacts:
        stats["types"][a.type] = stats["types"].get(a.type, 0) + 1
    for s in stages:
        if s.command_family:
            stats["families"][s.command_family] = \
                stats["families"].get(s.command_family, 0) + 1

    return PreprocessResult(
        raw=raw_text,
        normalized_text=ni.text,
        artifacts=artifacts,
        stages=stages,
        process_edges=edges,
        stats=stats,
        decode_layers=_snapshot_decode_layers(),
    )
