"""NivXRay · Security module (ADR-0010b · P0 Security Hardening Gate).

This package hosts the P0 Security Hardening Gate primitives:

- ``cors``          — explicit CORS origin parsing + safe-credentials policy
- ``rate_limit``    — in-process sliding-window rate limiter (login-shape)
- ``archive_guard`` — safe archive extraction with size / depth / count /
                      ratio guards (zip-bomb defence)

Design constraints (per PRD.md P0 directive):
- Server-side enforcement only. Never trust extension / MIME / filename.
- Deterministic errors. Fail-loud, structured, no partial state.
- Minimal surface. No new frameworks. No new dependencies.
- No NIVX_FLAG_* introduced. Standard environment variables only.
"""
from __future__ import annotations

__all__ = ["cors", "rate_limit", "archive_guard"]
