"""Staging archetypes learned via Auto-Archetype Learner.

This file holds archetype dicts approved through /api/learner/approve/{id}.
It is imported by wrapper_archetypes.py (best-effort) and appended AFTER the
built-in ARCHETYPES list, so learned handlers act as fallbacks.

Rules:
  * Never edit by hand — use the Learner UI (Approve button) so the change
    is recorded in the archetype_versions collection with a rollback point.
  * Each entry MUST include id (unique, LEARNED_* prefix), description,
    handler (callable), match (callable), chain (list[str]), terminal (bool),
    and a `learned` metadata dict {version, approved_by, approved_at, ...}.
  * The regression gate (/api/learner/approve) will refuse to merge if
    /app/backend/tests/test_nxgec_regression.py fails.
"""
from __future__ import annotations
from typing import Any, Dict, List

LEARNED_ARCHETYPES: List[Dict[str, Any]] = []
