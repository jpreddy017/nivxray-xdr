"""Attack Story service · Blueprint §9 (Story lens) · PR-4.

Produces an ordered, evidence-anchored narrative of the attack. Each
story event links back to an iteration in the Convergence Certificate
(Blueprint §8.4 Evidence Navigation Contract).

PR-4 adds:
  * Human-readable ``narrative`` composed deterministically from the
    ordered events plus sample metadata. No LLM. No wall-clock time.
  * Optional ``chapter`` grouping (structural / content / decoder /
    semantic) so the Story lens can render section headings.

The ``events`` field is UNCHANGED from PR-3 scaffold (protected by
contract tests). PR-4 extends each event with a stable ``chapter``
attribute; downstream consumers that only read the original keys are
unaffected.
"""
from __future__ import annotations

from typing import Any

from ..schemas import EvidenceBundle, ServiceOutput
from .base import BaseService, register_service

_NAME = "attack_story"
_VERSION = "0.2.0-pr4"


_PASS_CHAPTER = {
    "structural": "Unwrap",
    "content":    "Normalize",
    "decoder":    "Decode",
    "semantic":   "Interpret",
}

_PASS_VERB = {
    "structural": "unwrapped",
    "content":    "normalized",
    "decoder":    "decoded",
    "semantic":   "interpreted",
}


def _events(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for idx, t in enumerate(bundle.transformations):
        if not t.changed:
            continue
        events.append({
            "event_id": f"evt-{idx:04d}",
            "iteration": t.iteration,
            "pass_name": t.pass_name,
            "chapter": _PASS_CHAPTER.get(t.pass_name, t.pass_name),
            "transformation": t.transformation,
            "text": f"{t.pass_name} pass applied {t.transformation}",
            "anchor": {
                "kind": "transformation",
                "iteration": t.iteration,
                "transformation": t.transformation,
            },
        })
    return events


def _narrative(bundle: EvidenceBundle, events: list[dict[str, Any]]) -> str:
    """Deterministic prose stitched from ordered events + metadata.

    Structure (each part optional and evidence-anchored):
      1. Opening sentence with family attribution if present.
      2. Ordered decode/unwrap sentence per pass, mentioning the
         transformation ids.
      3. Closing sentence stating canonical readiness.
    """
    lines: list[str] = []

    family = bundle.sample.family
    technique = bundle.sample.technique
    if family and technique:
        lines.append(
            f"The sample was attributed to {family} using the {technique} technique."
        )
    elif family:
        lines.append(f"The sample was attributed to {family}.")
    elif technique:
        lines.append(f"The sample exhibits the {technique} technique.")
    else:
        lines.append("The sample has no attributed family; analysis proceeds on evidence alone.")

    # Group events by pass in iteration order, preserving first-seen order.
    seen_passes: list[str] = []
    per_pass: dict[str, list[str]] = {}
    for e in events:
        p = e["pass_name"]
        if p not in per_pass:
            per_pass[p] = []
            seen_passes.append(p)
        per_pass[p].append(e["transformation"])

    for p in seen_passes:
        verb = _PASS_VERB.get(p, p)
        ts = per_pass[p]
        if len(ts) == 1:
            lines.append(f"The {p} pass {verb} the artefact via {ts[0]}.")
        else:
            joined = ", ".join(ts[:-1]) + f" and {ts[-1]}"
            lines.append(f"The {p} pass {verb} the artefact via {joined}.")

    ready = bundle.certificate.get("ready_for_behavioral_analysis", False)
    if ready:
        lines.append("Convergence reached a canonical state; the artefact is ready for behavioural analysis.")
    else:
        lines.append("Residual obfuscation remains; the artefact did not reach a canonical state.")

    return " ".join(lines)


def _chapters(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Ordered chapter list for section headings — deterministic."""
    order: list[str] = []
    counts: dict[str, int] = {}
    for e in events:
        c = e["chapter"]
        if c not in counts:
            order.append(c)
            counts[c] = 0
        counts[c] += 1
    return [{"chapter": c, "event_count": counts[c]} for c in order]


def run(bundle: EvidenceBundle) -> ServiceOutput:
    events = _events(bundle)
    body: dict[str, Any] = {
        "events": events,
        "chapters": _chapters(events),
        "narrative": _narrative(bundle, events),
    }
    return ServiceOutput(
        service=_NAME,
        version=_VERSION,
        case_id=bundle.case_id,
        body=body,
    )


SERVICE = register_service(BaseService(name=_NAME, version=_VERSION, run=run))

__all__ = ["run", "SERVICE"]
