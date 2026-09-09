"""Plugin · GZip Bytes Validator + Partial-Recovery Repair
(QA-Layer · R28.3).

Validator diagnoses gzip payloads:
    · missing 0x1F 0x8B magic         → UNREACHABLE (no repair possible)
    · truncated stream (< 18 bytes)   → UNREACHABLE (impossible)
    · valid magic but inflates poorly → proposes ``gzip_partial_inflate``

Repair (``gzip_partial_inflate``) uses ``zlib.decompressobj(wbits=31)``
to stream-inflate and returns the readable prefix WITH a ``truncated_at``
marker in meta so the analyst can see how far the stream got before
mangling.

This is the structural solution to the Sophos/mangled-clipboard case
where the gzip stream corrupts mid-flight at offset ~1472.
"""
from __future__ import annotations

import zlib

from ...artifact import Artifact
from ...qa       import (INVALID_MISSING_MAGIC, INVALID_SIZE_BELOW_MIN,
                            INVALID_TRUNCATED, RepairCandidate, RepairResult,
                            REPAIR_FAIL_IRREVERSIBLE, REPAIR_FAIL_TRUNCATED,
                            ValidationResult, register_repair, register_validator)


V_NAME = "validator.gzip_bytes"
R_NAME = "repair.gzip.partial_inflate"


class _Validator:
    name = V_NAME
    validates_artifact_type = ["gzip_bytes"]

    def validate(self, artifact: Artifact) -> ValidationResult:
        buf = artifact.payload or b""
        n = len(buf)
        if n < 18:
            return ValidationResult(
                valid=False, validator=V_NAME, confidence=0.99,
                reason=INVALID_SIZE_BELOW_MIN,
                detail=f"size={n} < 18B (gzip minimum: 10-byte header + 8-byte trailer)",
                repair_candidates=[],
            )
        if buf[0] != 0x1F or buf[1] != 0x8B:
            return ValidationResult(
                valid=False, validator=V_NAME, confidence=0.99,
                reason=INVALID_MISSING_MAGIC,
                detail=f"magic={buf[0:2].hex()} (expected 1f8b)",
                repair_candidates=[],
            )
        # Try a full inflate.  If it succeeds → valid.  If it truncates,
        # we still accept (the artifact IS gzip) BUT propose the partial
        # repair strategy so the orchestrator can produce a healed
        # child from the readable prefix.
        try:
            zlib.decompress(buf, wbits=31)
            return ValidationResult(
                valid=True, validator=V_NAME, confidence=0.99,
                detail=f"gzip inflates cleanly ({n}B compressed)",
            )
        except zlib.error as e:
            return ValidationResult(
                valid=False, validator=V_NAME, confidence=0.95,
                reason=INVALID_TRUNCATED,
                detail=f"zlib.error: {e}",
                repair_candidates=[RepairCandidate(
                    strategy="gzip_partial_inflate",
                    confidence=0.85,
                    reason=INVALID_TRUNCATED,
                    detail=f"attempt streaming inflate; upstream error: {e}",
                )],
            )


class _Repair:
    name     = R_NAME
    strategy = "gzip_partial_inflate"

    def repair(self, artifact: Artifact,
                candidate: RepairCandidate) -> RepairResult:
        buf = artifact.payload or b""
        if len(buf) < 18 or buf[0] != 0x1F or buf[1] != 0x8B:
            return RepairResult(
                success=False, strategy=self.strategy,
                reason=REPAIR_FAIL_IRREVERSIBLE,
                detail="missing gzip magic",
            )
        decompressor = zlib.decompressobj(wbits=31)
        out = bytearray()
        consumed = 0
        try:
            # decompressobj yields whatever it can and raises on the
            # first invalid block.  We stream in 4KB chunks so we can
            # report the offset at which the stream broke.
            chunk_size = 4096
            offset = 0
            while offset < len(buf):
                chunk = buf[offset:offset + chunk_size]
                try:
                    out.extend(decompressor.decompress(chunk))
                except zlib.error:
                    break
                offset += len(chunk)
            consumed = offset
            # Force flush of any residual state (may raise; we ignore).
            try:
                out.extend(decompressor.flush())
            except zlib.error:
                pass
        except Exception as e:  # pragma: no cover
            return RepairResult(
                success=False, strategy=self.strategy,
                reason=REPAIR_FAIL_IRREVERSIBLE,
                detail=f"{type(e).__name__}: {e}",
            )
        if not out:
            return RepairResult(
                success=False, strategy=self.strategy,
                reason=REPAIR_FAIL_TRUNCATED,
                detail="partial inflate produced 0 bytes",
            )
        return RepairResult(
            success=True, strategy=self.strategy,
            repaired_payload=bytes(out),
            repaired_artifact_type="gzip_decoded",   # partial inflate = decode
            detail=(f"partial inflate recovered {len(out)}B "
                      f"from {consumed}B/{len(buf)}B compressed input"),
            meta={
                "recovered_bytes":       len(out),
                "consumed_bytes":        consumed,
                "compressed_input_size": len(buf),
                "truncated_at_offset":   consumed if consumed < len(buf) else None,
            },
        )


validator = _Validator()
repair    = _Repair()
register_validator(validator)
register_repair(repair)
