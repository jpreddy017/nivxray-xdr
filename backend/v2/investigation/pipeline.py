"""Unified Investigation Pipeline — the single source-of-truth entry
point analysts should use.

Analysts should not have to know that Input Understanding, Command
Reconstruction, Recursive Transformation, and Semantic Intent are
separate engines. They should experience a single investigation
flow:

    text
     │
     ▼
    Input Understanding      ← what is this artefact?
     │
     ▼
    Command Reconstruction   ← what will actually execute?
     │
     ▼
    Recursive Transformation ← reveal the hidden payload
     │
     ▼
    Semantic Intent          ← why does it matter?

The pipeline is deterministic, evidence-preserving, and Phase-5-
Evidence-Graph-ready.

Every intermediate output is exposed on the returned
``InvestigationResult`` so downstream engines (verdict, behaviour
correlation, analyst report generator) can consume the SAME payload
without re-invoking the underlying engines.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .cre import reconstruct
from .cre.models import CommandReconstruction
from .intent import IntentAssessment, assess as assess_intent
from .iu import classify
from .iu.models import ArtefactClassification, Capability
from .rte import TransformationChain, transform as run_rte

# Every capability the Brain currently supports. The pipeline
# emits a ``coverage`` map so callers can see WHICH stages fired
# on this specific artefact — an audit trail for regression proofs.
_SUPPORTED = {"iu", "cre", "rte", "intent"}


@dataclass
class InvestigationResult:
    """Full investigation output — one homogeneous payload the UI,
    Evidence Graph, verdict engine, and report generator can all
    consume without re-running any engine.
    """
    input:              str
    iu:                 ArtefactClassification
    cre:                CommandReconstruction | None
    rte:                TransformationChain
    intent:             IntentAssessment
    coverage:           list[str] = field(default_factory=list)
    determinism_hash:   str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "input":             self.input,
            "iu":                self.iu.to_dict(),
            "cre":               self.cre.to_dict() if self.cre else None,
            "rte":               self.rte.to_dict(),
            "intent":            self.intent.to_dict(),
            "coverage":          list(self.coverage),
            "determinism_hash":  self.determinism_hash,
        }


def investigate(text: str) -> InvestigationResult:
    """Run the full Investigation Brain pipeline against ``text``.

    Pipeline order (all deterministic, all evidence-preserving):

        1. Input Understanding  (`iu.classify`)
        2. Command Reconstruction Engine  (`cre.reconstruct`) — only
           when IU dispatched ``Capability.CRE``.
        3. Recursive Transformation Engine (`rte.transform`) on the
           CRE effective payload if available, otherwise on the raw
           input.
        4. Semantic Intent Layer  (`intent.assess`) on the RTE final
           artefact — the deepest plaintext the Brain could reach.
    """
    text = text or ""
    coverage: list[str] = []

    # ── 1. Input Understanding ─────────────────────────────────
    iu_result = classify(text)
    coverage.append("iu")

    # ── 2. Command Reconstruction (only when dispatched) ───────
    cre_result: CommandReconstruction | None = None
    effective_payload = text
    if Capability.CRE in iu_result.dispatch:
        try:
            cre_result = reconstruct(text)
            coverage.append("cre")
            if cre_result.effective_payload:
                effective_payload = cre_result.effective_payload
        except Exception:
            # CRE must never crash the pipeline. Fall back to raw text.
            cre_result = None

    # ── 3. Recursive Transformation ────────────────────────────
    rte_result = run_rte(effective_payload)
    coverage.append("rte")

    # ── 4. Semantic Intent — on the deepest layer we can reach ─
    final_text = rte_result.final.content if rte_result.artifacts else effective_payload
    intent_meta = {
        "iu_primary_type":    iu_result.primary_type.value,
        "iu_dispatch":        [c.value for c in iu_result.dispatch],
        "cre_dispatch_hint":  cre_result.dispatch_hint if cre_result else None,
        "rte_depth":          rte_result.depth,
        "rte_stop_reason":    rte_result.stop_reason.value,
    }
    intent_result = assess_intent(final_text, meta=intent_meta)
    coverage.append("intent")

    result = InvestigationResult(
        input=text,
        iu=iu_result,
        cre=cre_result,
        rte=rte_result,
        intent=intent_result,
        coverage=coverage,
    )
    result.determinism_hash = _hash(result)
    return result


def _hash(result: InvestigationResult) -> str:
    """Deterministic hash of the full investigation — proves replay
    across every runtime."""
    blob = json.dumps({
        "iu_hash":     result.iu.determinism_hash,
        "cre_hash":    result.cre.determinism_hash if result.cre else None,
        "rte_hash":    result.rte.determinism_hash,
        "intent_hash": result.intent.determinism_hash,
        "coverage":    result.coverage,
    }, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


__all__ = ["investigate", "InvestigationResult"]
