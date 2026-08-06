"""
Session · Investigation Session envelope (Rule R22 · 2026-03-02).

Thin adapter that wraps the Canonical Investigation Object (SSOT)
into a session-shaped envelope for the analyst-facing L4 workspace.
Additive only — IDA / DIE / ICE remain untouched.
"""
from .adapter import build_session, promote_investigation_inputs  # noqa: F401
