"""project_attack_story — canonical narrative reconstruction.

Prose. canonical_normalised comparison. NEVER fabricates content — if
the SSOT lacks evidence, story is empty and stages a note.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..ssot import AuthoritativeSSOT
from ._helpers import (
    command_nodes,
    ioc_nodes,
    mitre_nodes,
    reasoning_by_rule_prefix,
)
from .attack_chain import project_attack_chain


def project_attack_story(ssot: AuthoritativeSSOT) -> Optional[Dict[str, Any]]:
    """Return an ordered narrative (opening, chapters, closing).

    Returns None when no evidence — projection must not invent a story.
    """
    mnodes = mitre_nodes(ssot)
    cnodes = command_nodes(ssot)
    inodes = ioc_nodes(ssot)

    if not (mnodes or cnodes or inodes):
        return None

    chain = project_attack_chain(ssot)
    chapters: List[Dict[str, Any]] = []

    for stage in chain:
        chapters.append({
            "stage": stage["stage"],
            "title": stage["title"],
            "techniques": stage["techniques"],
            "narrative": (
                f"During {stage['title']}, the sample exercised "
                f"{len(stage['techniques'])} technique(s): "
                f"{', '.join(stage['techniques'])}."
            ),
        })

    opening = (
        f"Canonical SSOT observed "
        f"{len(mnodes)} MITRE technique(s), "
        f"{len(cnodes)} command(s), and "
        f"{len(inodes)} IOC(s)."
    )
    closing = (
        f"End of canonical narrative. {len(chapters)} stage(s) reconstructed "
        f"from evidence."
    )

    return {
        "opening": opening,
        "chapters": chapters,
        "closing": closing,
    }
