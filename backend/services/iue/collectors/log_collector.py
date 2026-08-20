"""Structured-log collector (STEP 3 §2.2 · STEP 4 §1.1 step 4).

Accepts trusted local bytes and emits a labelled envelope.  Does NOT
parse and does NOT touch the network.  Size caps enforced up-front.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from ..failure import IUEFailure
from ..security import enforce_raw_size, SecurityCapExceeded


def _sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RawPayload:
    bytes_: bytes
    mime: str
    encoding: str
    source_file_id: str
    input_id: str
    tenant_id: str
    parent_input_id: Optional[str] = None
    discovery_depth: int = 0
    at: str = field(default_factory=_utc_iso)

    def to_dict(self) -> dict:
        d = asdict(self)
        # bytes_ isn't JSON-serialisable — replace with size marker.
        d["bytes_len"] = len(self.bytes_)
        d.pop("bytes_", None)
        return d


def collect(payload_bytes: bytes,
             *, mime: str,
             input_id: str,
             tenant_id: str,
             parent_input_id: Optional[str] = None,
             discovery_depth: int = 0,
             encoding: str = "utf-8"):
    """Return either a ``RawPayload`` or an ``IUEFailure``.  Never raises."""
    try:
        enforce_raw_size(len(payload_bytes))
    except SecurityCapExceeded as e:
        return IUEFailure(
            status="terminal", stage="collect",
            error_code="collect_size_exceeded",
            message=str(e), recoverable=False,
            hint=f"Increase IUE_MAX_RAW_BYTES or split the file.",
            input_id=input_id, tenant_id=tenant_id,
        )

    return RawPayload(
        bytes_=payload_bytes,
        mime=mime,
        encoding=encoding,
        source_file_id=_sha256_hex(payload_bytes)[:32],
        input_id=input_id,
        tenant_id=tenant_id,
        parent_input_id=parent_input_id,
        discovery_depth=discovery_depth,
    )
