"""Phase 5.1 · Canonical UIL Entry Adapter.

Owner directive 2026-08-10 · scope:
  - Feature flag NIVX_CANONICAL_UIL_INVESTIGATE (default OFF in code).
  - When ON, route runs the full canonical lifecycle for
    POST /api/uil/investigate.
  - When OFF, this module is not called; the legacy code path is
    byte-identical to Phase 3.y exit.

Firewalls:
  - Does NOT import or call `services.die.investigation_results.render`.
  - Does NOT import or call `services.session.adapter.build_session`.
  - Does NOT touch `routers/cases.py` or any other route.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from canonical.executor import Executor
from canonical.iue import RawInput
from canonical.iue import classify as _canonical_classify
from canonical.ssot import InMemorySSOTStore, Source
from services.uil import (
    KIND_LABEL,
    InputKind,
    split_mixed,
)
from services.uil import (
    classify as _uil_classify,
)
from services.uil import (
    normalize as _uil_normalize,
)

from .canonical_session import build_canonical_session

_FLAG_ENV = "NIVX_CANONICAL_UIL_INVESTIGATE"
_FLAG_DEFAULT = "off"
_log = logging.getLogger("nivxray.canonical.uil.5_1")

# Executor budget kept at ExecutorBudget defaults (no 5.1-specific override).
_STORE = InMemorySSOTStore()


def canonical_flag_enabled() -> bool:
    """Return True iff NIVX_CANONICAL_UIL_INVESTIGATE=on (case-insensitive).

    Default OFF per owner Q2=a. Any value other than the literal string
    "on" (case-insensitive) MUST be treated as OFF — no truthiness
    coercion that could yield unexpected activation.
    """
    value = os.environ.get(_FLAG_ENV, _FLAG_DEFAULT).strip().lower()
    return value == "on"


def investigate_canonical(*,
                           payload: bytes,
                           filename: str | None,
                           text_input: str | None,
                           correlation_id: str,
                           ) -> dict[str, Any]:
    """Run the canonical lifecycle for `POST /api/uil/investigate`.

    Direct path (Q1=b):
        RawInput → Canonical IUE → Canonical Executor → Phase 4
        projections → canonical_session envelope.

    Returns the session-v1-compatible envelope with Wave-N labels
    (`wave="5.1"`, `lifecycle="canonical"`, `canonical_ssot_ref=...`).
    """
    # ── Preserve UIL classify/normalize on the string front-side so the
    # `uil` block of the envelope keeps its shape (analyst-visible chip).
    uil_kind = _uil_classify(payload, filename=filename)
    uil_norm = _uil_normalize(payload, uil_kind, filename=filename)
    fragments = split_mixed(uil_norm.text) if uil_kind is InputKind.MIXED else []

    uil_meta = {
        "kind":       uil_kind.value,
        "kind_label": KIND_LABEL.get(uil_kind, uil_kind.value),
        "ready":      uil_norm.ready,
        "reason":     uil_norm.reason,
        "metadata":   uil_norm.metadata,
        "fragments":  [f.to_dict() for f in fragments],
    }

    # ── Front-door gating (FIX A · 2026-08-10) ─────────────────────────
    # Only return the honest "not ready" envelope when BOTH:
    #   (i)  legacy UIL normalize says not-ready, AND
    #   (ii) the canonical lifecycle does NOT handle this kind either.
    # This ensures DOCX/PDF/ZIP/etc. — which the canonical executor
    # handles via ARCHIVE_EXTRACT + TEXT_EXTRACT_FROM_ARCHIVE — do NOT
    # short-circuit here.
    _CANONICAL_HANDLED = {
        "docx", "pdf", "xlsx", "pptx", "zip", "email", "html",
        "json", "xml", "yaml", "csv", "text", "url",
        "command", "powershell", "bash", "mixed",
    }
    if (not uil_norm.ready) and (uil_kind.value not in _CANONICAL_HANDLED):
        return {
            "session": None,
            "uil":     uil_meta,
        }

    # ── Canonical lifecycle ────────────────────────────────────────────
    raw = RawInput(
        payload=payload,
        filename=filename,
        source_channel="uil.investigate.canonical.5_1",
    )
    iue = _canonical_classify(raw)
    source = Source(
        surface="uil",
        endpoint="/api/uil/investigate",
        correlation_id=correlation_id,
        channel="canonical.5.1",
    )
    result = Executor(store=_STORE).run(iue, raw, source=source, depth=0)
    ssot = result.ssot
    ssot_ref = result.ssot_ref

    _log.info(
        "phase5_1.uil.investigate.canonical route=%s wave=5.1 lifecycle=canonical "
        "ssot_ref=%s fingerprint=%s uil_kind=%s uil_ready=%s "
        "executed_capabilities=%s size=%d",
        "/api/uil/investigate",
        ssot_ref,
        ssot.fingerprint(),
        uil_kind.value,
        uil_norm.ready,
        sorted({t.capability for t in ssot.execution_trace
                if t.status == "executed"}),
        raw.size(),
    )

    envelope = build_canonical_session(
        ssot=ssot,
        ssot_ref=ssot_ref,
        input_text=uil_norm.text if uil_norm.ready else "",
        uil_meta=uil_meta,
        store=_STORE,           # FIX B · aggregate child-SSOT projections
    )
    return {"session": envelope}


__all__ = [
    "canonical_flag_enabled",
    "investigate_canonical",
]
