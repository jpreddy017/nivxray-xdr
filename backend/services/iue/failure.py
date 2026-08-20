"""IUE unified failure envelope (STEP 3 §2.7 · §3.6).

Failure is data, not exception.  Every IUE module returns an envelope
even on error.  ``IUEFailure.to_report_extraction_fragment()`` reproduces
Fix 1's exact on-wire ``acquisition_failed`` shape when the failure was
raised at the URL collect stage — this is the compatibility contract
that lets Lane B keep byte-identical output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# Closed vocabulary — see STEP 3 §3.6.  Adding a code is a design amendment.
ERROR_CODES = frozenset({
    "intake_unknown_kind",
    "collect_size_exceeded",
    "collect_timeout",
    "collect_denied_by_policy",
    "parse_malformed_record",
    "parse_encoding_failed",
    "normalize_unmappable_field",
    "normalize_alias_ambiguous",
    "aggregate_provenance_missing",
    "understand_engine_error",
    "recurse_depth_exceeded",
    "recurse_cycle_detected",
    "tenant_context_missing",
})

STATUSES = frozenset({"ok", "recoverable", "terminal"})
STAGES = frozenset({"intake", "collect", "parse", "normalize",
                     "aggregate", "understand", "recurse"})


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class IUEFailure:
    status: str                # "ok" | "recoverable" | "terminal"
    stage: str                 # STAGES
    error_code: str            # ERROR_CODES
    message: str
    recoverable: bool
    hint: str = ""
    input_id: str = ""
    tenant_id: str = ""
    at: str = field(default_factory=_utc_iso)

    def __post_init__(self):
        # Vocabulary enforcement — silent drift causes silent regressions.
        if self.status not in STATUSES:
            raise ValueError(f"IUEFailure.status={self.status!r} not in {STATUSES}")
        if self.stage not in STAGES:
            raise ValueError(f"IUEFailure.stage={self.stage!r} not in {STAGES}")
        if self.error_code not in ERROR_CODES:
            raise ValueError(
                f"IUEFailure.error_code={self.error_code!r} not in ERROR_CODES"
            )

    def to_dict(self) -> dict:
        return asdict(self)
