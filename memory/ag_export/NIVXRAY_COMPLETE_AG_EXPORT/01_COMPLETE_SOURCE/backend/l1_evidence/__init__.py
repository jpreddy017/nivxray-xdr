"""L1 Evidence Services · read-down bridge between L0 output and L2 services.

For PR-2 the L1 layer's only responsibility is *persistence*:

  * Store an EvidenceBundle produced by (eventually) the L0 pipeline.
  * Store the Workspace State (Blueprint §8.3).
  * Store the Investigation State Machine transitions (Blueprint §8.1).

PR-2 does not connect L0 → EvidenceBundle. That bridge lands with PR-3
(input surface) or a dedicated PR. For now, the case-creation endpoint
accepts a pre-built bundle payload, which is enough to expose all L2
services over HTTP with deterministic behaviour.
"""
from __future__ import annotations

from .case_store import CaseStore, CaseRecord, CaseNotFound

__all__ = ["CaseStore", "CaseRecord", "CaseNotFound"]
