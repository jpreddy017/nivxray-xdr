"""Canonical Projections — Phase 4 (D2-d projection tier).

Every projection is a **pure function** of an AuthoritativeSSOT:

    projection = project_X(ssot: AuthoritativeSSOT) -> <projection_type>

Firewalls (see /app/memory/adr/0005-phase4-spec.md §2):
    P4-FW1  no I/O, no clock, no random, no network
    P4-FW2  never mutate authoritative fields
    P4-FW3  NO generic-recommendation fallback
    P4-FW4  legacy composers are oracles only
    P4-FW5  every diff explicitly labelled byte_identity | canonical_normalised

Public API:
    from canonical.projections import (
        project_verdict, project_attck, project_attack_chain,
        project_attack_story, project_evidence_graph_view,
        project_analyst_summary, project_executive_summary,
        project_recommendations, project_timeline, project_lolbas,
        project_iocs, project_activity, project_canonical,
        project_evidence_bundle, project_reports,
    )
"""
from .verdict            import project_verdict
from .attck              import project_attck
from .attack_chain       import project_attack_chain
from .attack_story       import project_attack_story
from .evidence_graph_view import project_evidence_graph_view
from .analyst_summary    import project_analyst_summary
from .executive_summary  import project_executive_summary
from .recommendations    import project_recommendations
from .timeline           import project_timeline
from .lolbas             import project_lolbas
from .iocs               import project_iocs
from .activity           import project_activity
from .canonical          import project_canonical
from .evidence_bundle    import project_evidence_bundle
from .reports            import project_reports

__all__ = [
    "project_verdict",
    "project_attck",
    "project_attack_chain",
    "project_attack_story",
    "project_evidence_graph_view",
    "project_analyst_summary",
    "project_executive_summary",
    "project_recommendations",
    "project_timeline",
    "project_lolbas",
    "project_iocs",
    "project_activity",
    "project_canonical",
    "project_evidence_bundle",
    "project_reports",
]

PROJECTION_VERSION = "1.0.0-phase4"
