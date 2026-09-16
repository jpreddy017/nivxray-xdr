"""Plugin · Shellcode Bytes Validator  (QA-Layer · R28.3).

Rejects children claiming ``shellcode_bytes`` when they are:
    · below 16 bytes (nothing meaningful executes in less than 4 asm
      instructions)
    · all-zero (a very common decoder-noise artifact — a zero-filled
      buffer is not shellcode)
    · low-entropy printable-only ASCII (that's text, not shellcode)

No repair candidates — if the bytes aren't shellcode, no
transformation makes them shellcode.
"""
from __future__ import annotations

from ...artifact import Artifact
from ...qa       import (INVALID_ALL_ZERO, INVALID_SIZE_BELOW_MIN,
                            INVALID_STRUCTURAL, ValidationResult,
                            register_validator)


NAME = "validator.shellcode_bytes"


class _Validator:
    name = NAME
    validates_artifact_type = ["shellcode_bytes"]

    def validate(self, artifact: Artifact) -> ValidationResult:
        buf = artifact.payload or b""
        n = len(buf)
        if n < 16:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.98,
                reason=INVALID_SIZE_BELOW_MIN,
                detail=f"size={n} < 16B (shellcode floor)",
                repair_candidates=[],
            )
        if buf == b"\x00" * n:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.99,
                reason=INVALID_ALL_ZERO,
                detail=f"all-zero buffer size={n}",
                repair_candidates=[],
            )
        # Pure printable ASCII of substantial size is text, not shellcode.
        printable = sum(1 for b in buf if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
        if printable / n >= 0.95 and n >= 64:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.85,
                reason=INVALID_STRUCTURAL,
                detail=f"printable_ratio={printable / n:.2f} (looks like text, not shellcode)",
                repair_candidates=[],
            )
        # Very low entropy also rejects — real shellcode has entropy > 3.0.
        if artifact.entropy < 1.0 and n >= 64:
            return ValidationResult(
                valid=False, validator=NAME, confidence=0.90,
                reason=INVALID_STRUCTURAL,
                detail=f"entropy={artifact.entropy} < 1.0 (uniform noise)",
                repair_candidates=[],
            )
        return ValidationResult(
            valid=True, validator=NAME, confidence=0.90,
            detail=f"size={n} entropy={artifact.entropy}",
        )


validator = _Validator()
register_validator(validator)
