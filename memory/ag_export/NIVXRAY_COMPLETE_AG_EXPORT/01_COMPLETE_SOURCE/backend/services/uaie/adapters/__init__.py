"""R28.8 · Phase 0 · Universal Input Adapters.

Every uploaded/pasted input passes through EXACTLY ONE adapter here
BEFORE the artifact router.  Adapters are the single boundary between
"an unstructured blob the user gave us" and "typed artifacts the
UAIE orchestrator can plan on".

Architecture invariants (locked):

    1. Adapters produce ARTIFACTS, never make security decisions.
    2. Adapters are format-only.  Zero malware / family knowledge.
    3. Adapters never call each other.  The orchestrator's recursive
       loop re-recognises every child artifact — deeper structure
       (a PDF's embedded PowerShell, a DOCX's embedded VBA) is
       reached automatically through the same UAIE loop.
    4. Adapter selection is content-based (magic bytes / MIME / URL
       scheme) — never file-extension-based, never user-declared.
    5. Adapters ALWAYS succeed at producing at least one artifact.
       If a format is malformed, they emit a diagnostic-tagged
       ``raw_bytes`` artifact so the pipeline never dead-ends.
"""
from __future__ import annotations

from ._base       import (Adapter, AdapterResult, adapter_registry,
                             route_input, register_adapter)
from ._registry   import ADAPTERS

__all__ = [
    "Adapter", "AdapterResult", "route_input",
    "register_adapter", "adapter_registry", "ADAPTERS",
]
