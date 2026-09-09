"""Lane-B URL collector — thin wrapper over ``services.ida.acquisition``.

Contract:
    URL → intake (already resolved) → THIS COLLECTOR → RawPayload
                                                       or IUEFailure

Reuse, do NOT rewrite acquisition.  ``services.ida.acquisition.acquire_url``
is the sole owner of URL fetching (SSRF, size caps, cascade, VEEE etc.).
On failure this collector emits an IUEFailure whose
``to_report_extraction_fragment()`` reproduces Fix 1's on-wire
``acquisition_failed`` shape byte-for-byte.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from canonical.ssot.models import Provenance
from .._prov import collect_prov
from ..failure import IUEFailure
from .log_collector import RawPayload


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass(frozen=True)
class URLRawPayload:
    """RawPayload for Lane B.  Carries the full AcquiredResource dict
    (`acquired.to_dict()`) plus the same fields RawPayload exposes so
    parsers/normalizers can iterate it uniformly."""
    acquired:        Dict[str, Any]                # AcquiredResource.to_dict()
    mime:            str
    encoding:        str
    source_file_id:  str
    input_id:        str
    tenant_id:       str
    parent_input_id: Optional[str] = None
    discovery_depth: int = 0
    provenance:      Provenance = field(default_factory=collect_prov)

    # Compatibility shim so shared helpers that peek at .bytes_ don't blow up.
    @property
    def bytes_(self) -> bytes:  # noqa: N802 (match RawPayload attr name)
        return (self.acquired.get("article_text") or "").encode("utf-8", errors="ignore")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "acquired_url":     self.acquired.get("url"),
            "final_url":        self.acquired.get("final_url"),
            "mime":             self.mime,
            "encoding":         self.encoding,
            "source_file_id":   self.source_file_id,
            "input_id":         self.input_id,
            "tenant_id":        self.tenant_id,
            "parent_input_id":  self.parent_input_id,
            "discovery_depth":  self.discovery_depth,
            "bytes_len":        len(self.bytes_),
            "provenance":       self.provenance.__dict__ if hasattr(self.provenance, "__dict__") else {},
        }


def collect_url(url: str,
                 *, input_id: str,
                 tenant_id: str,
                 upstream: Optional[Provenance] = None,
                 parent_input_id: Optional[str] = None,
                 discovery_depth: int = 0):
    """Fetch a URL via existing acquisition; return URLRawPayload OR
    IUEFailure.  Never raises.  Fix 1's envelope is preserved on failure."""
    from services.ida.acquisition import acquire_url

    try:
        acquired = acquire_url(url)
    except Exception as e:
        return IUEFailure(
            status="terminal", stage="collect",
            error_code="collect_denied_by_policy",
            message=f"acquire_url raised: {type(e).__name__}: {e}",
            recoverable=False,
            hint="acquisition layer raised; upstream contract violation",
            input_id=input_id, tenant_id=tenant_id,
        )

    if not acquired.ok:
        # Fix 1 preservation — the failure envelope MUST contain the
        # AcquiredResource dict verbatim so downstream (Prev-mode render
        # and any consumer) can build the same on-wire acquisition_failed
        # shape.  The IUEFailure only carries the pointer; the callers
        # attach the acquired dict when they assemble the wire.
        return IUEFailure(
            status="terminal", stage="collect",
            error_code=_fix1_error_code(acquired.error_code),
            message=acquired.error_detail or f"acquisition failed: {acquired.error_code}",
            recoverable=False,
            hint=(
                "Preview environment IP may be blocked by the remote WAF; "
                "the same URL may succeed in production. See Fix 1 envelope."
            ),
            input_id=input_id, tenant_id=tenant_id,
        ), acquired.to_dict()

    source_file_id = _sha256_hex(url.encode("utf-8"))[:32]
    payload_bytes = (acquired.article_text or "").encode("utf-8", errors="ignore")

    return URLRawPayload(
        acquired=acquired.to_dict(),
        mime="text/html",
        encoding="utf-8",
        source_file_id=source_file_id,
        input_id=input_id,
        tenant_id=tenant_id,
        parent_input_id=parent_input_id,
        discovery_depth=discovery_depth,
        provenance=collect_prov(upstream=upstream, own_id=source_file_id),
    )


# ── error-code bridge ─────────────────────────────────────────────
# Fix 1 uses IDA's error_code vocabulary; IUE has its own closed set
# (STEP 3 §3.6).  This map preserves the semantic meaning without
# introducing a new vocabulary — the ORIGINAL IDA code is preserved
# on the wire via ``acquisition_failure.error_code`` (Fix 1 envelope).
_IDA_TO_IUE = {
    "blocked_scheme": "collect_denied_by_policy",
    "private_host":   "collect_denied_by_policy",
    "timeout":        "collect_timeout",
    "http_error":     "collect_denied_by_policy",
    "content_type":   "collect_denied_by_policy",
    "empty":          "collect_denied_by_policy",
    "exception":      "collect_denied_by_policy",
}


def _fix1_error_code(ida_code: str) -> str:
    return _IDA_TO_IUE.get(ida_code or "", "collect_denied_by_policy")
