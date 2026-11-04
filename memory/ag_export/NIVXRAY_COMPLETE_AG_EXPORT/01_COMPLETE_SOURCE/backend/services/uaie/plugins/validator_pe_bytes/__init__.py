"""Plugin · PE Bytes Validator  (QA-Layer · R28.3).

Rejects children claiming ``pe_bytes`` type unless they have a valid
DOS header (``MZ``) and the ``e_lfanew`` pointer resolves to the ``PE\\0\\0``
signature.  This prevents garbage cascades where a decoder produces
noise and something downstream claims it as a Portable Executable.

There are no repair candidates — if the DOS header isn't there, there
is no deterministic way to reconstruct one.  The artifact is ruled
UNREACHABLE and the analyst sees exactly why in the certificates.
"""
from __future__ import annotations

import struct

from ...artifact import Artifact
from ...qa       import (INVALID_MISSING_MAGIC, INVALID_SIZE_BELOW_MIN,
                            INVALID_STRUCTURAL, ValidationResult,
                            register_validator)


NAME = "validator.pe_bytes"


class _Validator:
    name = NAME
    validates_artifact_type = ["pe_bytes"]

    def validate(self, artifact: Artifact) -> ValidationResult:
        buf = artifact.payload or b""
        n = len(buf)
        if n < 64:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_SIZE_BELOW_MIN,
                detail=f"size={n} < 64B (DOS header minimum)",
                repair_candidates=[],   # no deterministic repair
            )
        if buf[0:2] != b"MZ":
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_MISSING_MAGIC,
                detail=f"first 2 bytes = {buf[0:2]!r} (expected b'MZ')",
                repair_candidates=[],
            )
        # e_lfanew at 0x3C, u32 little-endian
        try:
            e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
        except struct.error:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_STRUCTURAL,
                detail="unable to read e_lfanew at 0x3C",
                repair_candidates=[],
            )
        if e_lfanew + 4 > n:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_STRUCTURAL,
                detail=f"e_lfanew=0x{e_lfanew:x} exceeds size={n}",
                repair_candidates=[],
            )
        if buf[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_STRUCTURAL,
                detail=(f"e_lfanew=0x{e_lfanew:x} bytes="
                          f"{buf[e_lfanew:e_lfanew+4]!r} (expected b'PE\\x00\\x00')"),
                repair_candidates=[],
            )
        return ValidationResult(
            valid=True, validator=NAME, confidence=0.99,
            detail=f"MZ + PE at 0x{e_lfanew:x}, size={n}",
        )


validator = _Validator()
register_validator(validator)
