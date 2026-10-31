"""ssot_ref — reference to a stored AuthoritativeSSOT (D6-r).

Format: "cssot:sha256:<64-hex>"
"""
from __future__ import annotations

import re
from typing import Optional

# String alias (Phase 2 uses plain str for JSON compatibility).
SSOTRef = str

_REF_RE = re.compile(r"^cssot:sha256:[0-9a-f]{64}$")


def make_ssot_ref(fingerprint_sha256: str) -> SSOTRef:
    """Construct an ssot_ref from a canonical-JSON sha256 fingerprint."""
    fp = fingerprint_sha256.lower().strip()
    if len(fp) != 64 or not all(c in "0123456789abcdef" for c in fp):
        raise ValueError(f"not a sha256 fingerprint: {fingerprint_sha256!r}")
    return f"cssot:sha256:{fp}"


def validate_ref(ref: str) -> bool:
    """Return True iff `ref` looks like a valid ssot_ref."""
    return isinstance(ref, str) and _REF_RE.match(ref) is not None


def parse_fingerprint(ref: SSOTRef) -> str:
    """Extract the sha256 fingerprint from an ssot_ref."""
    if not validate_ref(ref):
        raise ValueError(f"not an ssot_ref: {ref!r}")
    return ref.split(":", 2)[2]
