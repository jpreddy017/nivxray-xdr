"""IUE tenancy propagator (STEP 3 §4).

Every IUE payload carries a ``tenant_id``.  Prod-mode strictly requires
a real tenant from ``services.session.adapter``; Prev-mode falls back
to the sentinel ``"__prev_public__"`` documented in the design as an
intentional dispensation.
"""
from __future__ import annotations

from typing import Optional


PREV_PUBLIC_TENANT = "__prev_public__"


def resolve_tenant(session_ctx: Optional[dict] = None,
                    *, allow_prev_fallback: bool = True) -> str:
    """Return the tenant_id for the current call.

    - Reads ``session_ctx.tenant_id`` when present.
    - Falls back to ``PREV_PUBLIC_TENANT`` if allowed (Prev-mode paste).
    - Returns empty string when Prod-mode has no tenant — callers MUST
      short-circuit with a ``tenant_context_missing`` IUEFailure.
    """
    if session_ctx and session_ctx.get("tenant_id"):
        return str(session_ctx["tenant_id"])
    if allow_prev_fallback:
        return PREV_PUBLIC_TENANT
    return ""
