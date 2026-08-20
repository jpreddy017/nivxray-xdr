"""IUE unified failure envelope (STEP 3 §2.7 · §3.6).

Failure is data, not exception.  Every IUE module returns an envelope
even on error.  ``IUEFailure.to_report_extraction_fragment()`` reproduces
Fix 1's exact on-wire ``acquisition_failed`` shape when the failure was
raised at the URL collect stage — this is the compatibility contract
that lets Lane B keep byte-identical output.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

from canonical.ssot.models import Provenance
from ._prov import failure_prov


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
    # Kept for backwards compat with a couple of callers; provenance
    # now carries the authoritative timestamp via Provenance.at.
    from datetime import datetime, timezone
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
    provenance: Provenance = field(default_factory=lambda: failure_prov("unknown"))

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
        # Re-tag the default provenance with the actual stage if the caller
        # didn't specify one.  We can't reassign a frozen field, so we
        # object.__setattr__ here — bounded to the failure envelope only.
        if self.provenance.engine == "iue.failure.unknown":
            from ._prov import failure_prov as _fp
            object.__setattr__(self, "provenance", _fp(self.stage))

    def to_dict(self) -> dict:
        return asdict(self)
