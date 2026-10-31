"""Cross-surface graph-only narrative override.

Every legacy prose builder (`_prose_executive`, `_prose_analyst`,
`_prose_technical`, `investigation_report.incident_overview`,
`customer_report.compose_customer_report`) delegates to this helper
before generating its own text. When Phase 1 has produced an
Investigation Graph for the current CIO, the graph-only Incident
Narrative Engine takes over — so every UI surface reads from the same
source of truth and the operator-locked lexicon rule (no
`pipeline` / `decoder` / `verdict engine` / …) is enforced everywhere.

The helper is idempotent: the Phase 1 state is computed once per CIO
and cached on `cio.metadata['phase1_state']`.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


def _raw_input_from_cio(cio: Any) -> Optional[str]:
    """Return the ORIGINAL pre-ingress raw payload if the /decode/smart
    router stashed one, otherwise fall back to CIO fields."""
    md = getattr(cio, "metadata", None)
    if isinstance(md, dict):
        raw = md.get("raw_input")
        if isinstance(raw, str) and raw.strip():
            return raw
    for attr in ("input_text", "raw_input", "input"):
        v = getattr(cio, attr, None)
        if isinstance(v, str) and v.strip():
            return v
    return None


def _get_phase1_state(cio: Any) -> Optional[Any]:
    """Return (and lazily compute + cache) the Phase 1 investigation
    state for `cio`. Never raises."""
    md = getattr(cio, "metadata", None)
    if isinstance(md, dict):
        cached = md.get("phase1_state")
        if cached is not None:
            return cached
    raw = _raw_input_from_cio(cio)
    if not raw:
        return None
    try:
        from nivxforge.investigation.pipeline.orchestrator import run_phase1
        state = run_phase1(raw)
    except Exception:  # noqa: BLE001
        return None
    if isinstance(md, dict):
        md["phase1_state"] = state
    return state


def get_incident_narrative(cio: Any) -> Optional[Any]:
    """Return the Incident Narrative Engine result for `cio`, or None
    if a graph-only narrative cannot be produced from the current
    Investigation Graph. Cached on cio.metadata['phase1_narrative']."""
    md = getattr(cio, "metadata", None)
    if isinstance(md, dict):
        cached = md.get("phase1_narrative")
        if cached is not None:
            return cached
    state = _get_phase1_state(cio)
    if state is None:
        return None
    # Require a graph with at least one node to produce narrative.
    try:
        if not state.graph.nodes:
            return None
    except AttributeError:
        return None
    try:
        from nivxforge.investigation.pipeline.narrative_engine import (
            compose_incident_narrative,
        )
        narr = compose_incident_narrative(state)
    except Exception:  # noqa: BLE001
        return None
    if not narr or not narr.paragraphs:
        return None
    if isinstance(md, dict):
        md["phase1_narrative"] = narr
    return narr


def executive_summary_paragraph(cio: Any) -> Optional[str]:
    """Return the first paragraph of the incident narrative (the
    analyst tl;dr) or None. Used by every executive-summary surface."""
    narr = get_incident_narrative(cio)
    if narr is None:
        return None
    return narr.executive_summary or (
        narr.paragraphs[0] if narr.paragraphs else None
    )


def full_incident_markdown(cio: Any) -> Optional[str]:
    """Return the complete graph-only narrative as markdown, or None
    if unavailable."""
    narr = get_incident_narrative(cio)
    if narr is None:
        return None
    return narr.to_markdown()


__all__ = [
    "get_incident_narrative",
    "executive_summary_paragraph",
    "full_incident_markdown",
]
