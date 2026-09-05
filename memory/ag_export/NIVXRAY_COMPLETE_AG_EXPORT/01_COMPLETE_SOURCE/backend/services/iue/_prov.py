"""Provenance factories — one per IUE stage.

Composes ``canonical.ssot.models.Provenance`` so every payload
dataclass in the IUE package carries the SAME provenance schema the
rest of NivXRay already uses.  No parallel representation.

Callers may pass an ``upstream`` Provenance whose ``engine`` /
``upstream_evidence_ids`` are recorded so lineage is walkable end-to-end.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from canonical.ssot.models import Provenance


_VERSION = "1.0"


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _chain(upstream: Optional[Provenance], own_id: str) -> List[str]:
    """Extend upstream lineage with the caller's own evidence id."""
    prior: List[str] = list(upstream.upstream_evidence_ids) if upstream else []
    if upstream is not None:
        # Upstream's own engine tag is added so lineage is human-readable.
        prior.append(f"{upstream.engine}:{upstream.at}")
    if own_id:
        prior.append(own_id)
    return prior


def intake_prov(upstream: Optional[Provenance] = None,
                 own_id: str = "") -> Provenance:
    return Provenance(engine="iue.intake", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))


def collect_prov(upstream: Optional[Provenance] = None,
                  own_id: str = "") -> Provenance:
    return Provenance(engine="iue.collectors.log", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))


def parse_prov(parser_name: str,
                upstream: Optional[Provenance] = None,
                own_id: str = "") -> Provenance:
    return Provenance(engine=f"iue.parsers.{parser_name}", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))


def normalize_prov(upstream: Optional[Provenance] = None,
                    own_id: str = "") -> Provenance:
    return Provenance(engine="iue.normalizers.field_map", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))


def aggregate_prov(upstream: Optional[Provenance] = None,
                    own_id: str = "") -> Provenance:
    return Provenance(engine="iue.aggregator", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))


def failure_prov(stage: str,
                  upstream: Optional[Provenance] = None,
                  own_id: str = "") -> Provenance:
    return Provenance(engine=f"iue.failure.{stage}", version=_VERSION,
                       at=_utc_iso(),
                       upstream_evidence_ids=_chain(upstream, own_id))
