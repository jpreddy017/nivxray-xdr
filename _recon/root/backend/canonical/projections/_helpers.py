"""Internal projection helpers — pure functions only.

NO I/O, NO CLOCK, NO RANDOM (P4-FW1).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..ssot import AuthoritativeSSOT
from ..ssot.models import GraphNode, ReasoningStep


# ── Node accessors ──────────────────────────────────────────────────────
def nodes_of_kind(ssot: AuthoritativeSSOT, kind: str) -> List[GraphNode]:
    """Return evidence-graph nodes of the given `kind`, in stored order."""
    return [n for n in ssot.evidence_graph.nodes if n.kind == kind]


def ioc_nodes(ssot: AuthoritativeSSOT) -> List[GraphNode]:
    return nodes_of_kind(ssot, "ioc")


def command_nodes(ssot: AuthoritativeSSOT) -> List[GraphNode]:
    return nodes_of_kind(ssot, "command")


def mitre_nodes(ssot: AuthoritativeSSOT) -> List[GraphNode]:
    return nodes_of_kind(ssot, "mitre_technique")


def ti_nodes(ssot: AuthoritativeSSOT) -> List[GraphNode]:
    return nodes_of_kind(ssot, "ti_hit")


def health_nodes(ssot: AuthoritativeSSOT) -> List[GraphNode]:
    return nodes_of_kind(ssot, "input_health")


# ── Reasoning-step accessors ────────────────────────────────────────────
def reasoning_by_rule_prefix(ssot: AuthoritativeSSOT,
                             prefix: str) -> List[ReasoningStep]:
    return [r for r in ssot.reasoning_steps if r.rule.startswith(prefix)]


# ── Executed capability inspection ──────────────────────────────────────
def executed_capabilities(ssot: AuthoritativeSSOT) -> List[str]:
    return [t.capability for t in ssot.execution_trace if t.status == "executed"]


def skipped_capabilities(ssot: AuthoritativeSSOT) -> List[str]:
    return [t.capability for t in ssot.execution_trace if t.status == "skipped"]


# ── Deterministic ordering helpers ──────────────────────────────────────
def unique_sorted(items: Iterable[str]) -> List[str]:
    return sorted({x for x in items if x})


# ── Ioc-classification helpers ──────────────────────────────────────────
def ioc_by_kind(ssot: AuthoritativeSSOT, ioc_kind: str) -> List[str]:
    out = []
    for n in ioc_nodes(ssot):
        if n.attrs.get("ioc_kind") == ioc_kind:
            out.append(n.label)
    return unique_sorted(out)


# ── Provenance/reasoning-step factory (pure — no clock) ─────────────────
def make_reasoning_note(projection: str, message: str) -> Dict[str, Any]:
    """Return a projection reasoning note.

    Notes are attached to projection outputs (not appended into
    reasoning_steps — that would violate P4-FW2). They are stable
    dictionaries deterministically ordered.
    """
    return {"projection": projection, "note": message}


# ── Reference-oracle normalisers (P4-FW5) ───────────────────────────────
def canonical_normalise(text: str) -> str:
    """Deterministic canonical normaliser for prose comparison.

    - lowercase
    - strip leading/trailing whitespace
    - collapse runs of whitespace into single spaces
    - strip trailing punctuation that varies across legacy templates
    """
    import re
    if text is None:
        return ""
    t = text.lower().strip()
    t = re.sub(r"\s+", " ", t)
    t = t.rstrip(".!?,:;")
    return t


def token_set(text: str) -> frozenset:
    """Return the token set of a normalised piece of prose (P4-FW5)."""
    return frozenset(canonical_normalise(text).split(" ")) - {""}


def length_band(text: str, band: int = 20) -> int:
    """Return the length band bucket for `text` (band = 20 chars)."""
    return len(canonical_normalise(text)) // band


def strict_prose_equal(a: str, b: str, band: int = 20) -> bool:
    """Strict comparison per §5 amendment 2: token-set + length-band."""
    return token_set(a) == token_set(b) and length_band(a, band) == length_band(b, band)
