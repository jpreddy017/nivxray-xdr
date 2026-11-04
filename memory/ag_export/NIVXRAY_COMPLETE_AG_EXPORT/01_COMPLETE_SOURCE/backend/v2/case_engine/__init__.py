"""NivXRay v2 · Case Engine (Phase 2a).

Owns Case-scoped storage: cases + case_events + case_entities +
case_relationships + case_behaviors + audit_log.

Phase 2a ships SCHEMA ONLY — collections and index specs. No writes
happen at import time. `ensure_indexes()` is NEVER auto-called; it
must be invoked explicitly from a v2 code path once the CASE_ENGINE
flag is at least SHADOW.
"""
from v2.case_engine.schema import COLLECTIONS, INDEX_SPECS  # noqa: F401
from v2.case_engine.store import ensure_indexes            # noqa: F401
