"""Canonical Behaviour Graph · v1.3.4.

The Behaviour Graph is a *lightweight* abstraction over the existing
:class:`Intent` layer. It exposes a small, closed set of normalised
behaviour nodes so that the Verdict Engine, Analyst Report, and
future Behaviour Correlation can all speak the same language.

Design principles (locked with the SME):
    * ONE graph — reuses the fired :class:`Intent` set. It never
      re-derives intent from raw text and never adds new
      detection surface.
    * SMALL — only the behaviours the current detectors support. New
      kinds are added ONLY when a real-world sample proves a
      genuine gap (same rule as the Intent categories).
    * DETERMINISTIC — same intent set → byte-identical graph.
    * EVIDENCE-ANCHORED — every node carries the canonical Evidence
      objects that produced it. Nothing fabricated.

Canonical data flow::

    Input → IU → CRE / RTE → Intent Layer → Behaviour Graph
      → Verdict Engine → Evidence Graph → Analyst Report
      → Behaviour Correlation (future)
"""
from __future__ import annotations

from .builder import build
from .models import (
    BehaviorArgKind,
    BehaviorEdge,
    BehaviorEdgeKind,
    BehaviorGraph,
    BehaviorKind,
    BehaviorNode,
)

__all__ = [
    "build",
    "BehaviorArgKind",
    "BehaviorEdge",
    "BehaviorEdgeKind",
    "BehaviorGraph",
    "BehaviorKind",
    "BehaviorNode",
]
