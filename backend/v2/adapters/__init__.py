"""NivXRay v2 · Adapter framework namespace.

Adapter STUBS only in Phase 1. Zero logic. Zero runtime effect.
All shadow-mode gated behind `NIVX_FLAG_ADAPTERS`.
"""
from v2.adapters.registry import (  # noqa: F401
    register,
    ADAPTERS,
    discover,
    reset_registry,
)
