"""Projections · Behavior → external framework mappings.

Every framework (ATT&CK, kill-chain, impacts, D3FEND, NIST, CIS)
gets its own module here.  Callers never touch the map dictionaries
directly — they call ``project_*`` functions that consume a sequence
of ``Behavior`` objects and return the framework-specific result.

Design (per user directive · 2026-02-05):

    Behavior                       (minimal semantic object · no
       │                            framework fields on it)
   ┌───┼──────────────┐
   ▼   ▼              ▼
  MITRE Kill Chain  Impacts  (independent projections · this package)
                             + future D3FEND / NIST / CIS

Each projection is a PURE DETERMINISTIC LOOKUP.  Adding a new
framework never requires editing the ``Behavior`` class.
"""
from .mitre       import BEHAVIOR_TO_MITRE, project_to_mitre
from .kill_chain  import BEHAVIOR_TO_KILL_CHAIN, project_to_kill_chain
from .impact      import BEHAVIOR_TO_IMPACTS, project_to_impacts

__all__ = [
    "BEHAVIOR_TO_MITRE",  "project_to_mitre",
    "BEHAVIOR_TO_KILL_CHAIN", "project_to_kill_chain",
    "BEHAVIOR_TO_IMPACTS", "project_to_impacts",
]
