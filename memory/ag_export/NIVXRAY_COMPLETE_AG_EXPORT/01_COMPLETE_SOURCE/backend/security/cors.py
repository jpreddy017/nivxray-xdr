"""CORS origin policy · P0 Security Hardening Gate.

Rules enforced here (browser-spec compliant):

- If ``CORS_ORIGINS`` is set to an explicit comma-separated list of origins,
  we honour it AND allow credentials (the strong-trust case).
- If ``CORS_ORIGINS`` is unset OR equals ``"*"``, we still send a wildcard
  origin but **force ``allow_credentials=False``**. Browsers reject
  ``*`` + credentials anyway; forcing it server-side prevents a stale
  legacy configuration from silently sending Set-Cookie into a wildcarded
  response.
- Empty strings, whitespace, and trailing slashes are stripped.
- ``localhost`` / ``127.0.0.1`` remain allowed for dev only when a real
  list is configured; otherwise wildcard mode covers them.

Config surface:

    CORS_ORIGINS = "*"                                        # wildcard-safe
    CORS_ORIGINS = "https://app.example.com"                  # single explicit
    CORS_ORIGINS = "https://a.example.com,https://b.example.com"  # multi

Nothing here reads or writes any NIVX_FLAG_*.
"""
from __future__ import annotations
import os
from typing import Tuple, List


def resolve_cors_policy(
    env: dict | None = None,
) -> Tuple[List[str], bool, bool]:
    """Return ``(allow_origins, allow_credentials, wildcard_mode)``.

    ``wildcard_mode`` is a signal for the caller (server.py) so it can
    log the resolved policy without leaking secrets.
    """
    raw = (env or os.environ).get("CORS_ORIGINS", "*")
    parts = [p.strip().rstrip("/") for p in raw.split(",") if p.strip()]
    if not parts or parts == ["*"]:
        # Wildcard mode: browsers refuse ``*`` + credentials, so we
        # force credentials off. This closes the ADR-0007 §12.19 gap.
        return ["*"], False, True
    return parts, True, False
