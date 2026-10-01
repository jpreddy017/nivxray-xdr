"""ps_indirect_compression_stream · variable-bound base64 → compression.

v1.5.0 Decoder Convergence · P0 gap identified 2026-07-28.

Handles the classic Windows evasion idiom where the base64 literal is
bound to a variable via ``New-Object IO.MemoryStream`` **before** the
compression stream reads it:

    $s = New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sI..."));
    IEX (New-Object IO.StreamReader(
           New-Object IO.Compression.GzipStream(
             $s, [IO.Compression.CompressionMode]::Decompress))).ReadToEnd();

The strict-order :mod:`ps_compression_stream` cannot match this shape
because its regex assumes ``GzipStream`` appears BEFORE
``FromBase64String`` in source order. This plugin closes that gap by
delegating to :func:`v2.semantic.ps_deobfuscate._resolve_variable_bound_compression_stream`
which links assignments and consumers by variable name.

Deterministic — only fires when the base64 argument is a LITERAL,
the variable name matches exactly, and decompression succeeds.
"""
import base64
import binascii
import gzip as _gzip_lib
import re
import zlib as _zlib_lib
from typing import TYPE_CHECKING

from ...evidence import Evidence
from ..diagnostic_codes import (
    CODE_BROTLI_DECOMPRESSION_FAILED,
    CODE_DEFLATE_DECOMPRESSION_FAILED,
    CODE_GZIP_DECOMPRESSION_FAILED,
    CODE_INVALID_BASE64_ALPHABET,
    CODE_INVALID_BASE64_LENGTH,
    CODE_UNSUPPORTED_COMPRESSION_STREAM,
    severity_of,
)
from ..models import Artifact

if TYPE_CHECKING:  # avoid runtime circular import
    from ..models import DecodeDiagnostic
try:
    from ..models import DecodeDiagnostic
except Exception:  # pragma: no cover - forward compat
    DecodeDiagnostic = None  # type: ignore


def _resolve():
    from ....semantic.ps_deobfuscate import (
        _resolve_variable_bound_compression_stream,
    )
    return _resolve_variable_bound_compression_stream


# Two markers must BOTH appear in the artefact for this plugin to even
# consider firing. This keeps ``applicable()`` cheap on non-matching
# artefacts (constant-time regex scan of the whole text).
_ASSIGN_MARKER_RE = re.compile(r"(?i)convert\]?\s*::\s*frombase64string")
_CONSUMER_MARKER_RE = re.compile(
    r"(?i)io\.compression\.(?:gzip|deflate|brotli)stream|"
    r"deflatestream|gzipstream|brotlistream",
)

# Detection-only regexes used by ``diagnose()``. Duplicated (not
# imported) from ps_deobfuscate so a failure to hot-reload one file
# never breaks diagnostics on the other. Kept intentionally minimal —
# only the SHAPE, not the value, matters for diagnostics.
_DIAG_ASSIGN_RE = re.compile(
    r"(?ixs)"
    r"\$(\w+)\s*=\s*"
    r"(?:new-object\s+(?:system\.)?io\.memorystream\s*\(\s*,?\s*)?"
    r"\[?\s*(?:system\.)?convert\]?\s*::\s*frombase64string\s*\(\s*"
    r"(['\"])([^'\"]{16,})\2\s*\)"
)
_DIAG_CONSUMER_RE = re.compile(
    r"(?ixs)"
    r"\[?\s*(?:system\.)?io\.compression\.(gzip|deflate|brotli)stream\]?"
    r"\s*(?:::new)?\s*"
    r"\(\s*\$(\w+)\s*,\s*"
    r".{0,200}?compressionmode\]?\s*::\s*decompress"
)


def _diagnose_pattern(txt: str) -> tuple[str, str, str, dict, str, str] | None:
    """Return ``(kind, var, reason, meta, code, failure_type)`` for a
    detected-but-uncoded variable-bound compression pattern, or
    ``None`` if no such pattern exists.

    Kept separate from the "success" resolver so diagnostics can never
    accidentally emit fabricated content.

    Diagnostic-wording discipline
    -----------------------------
    Only report what the decoder can deterministically prove:

        * the extracted base64 length,
        * ``length mod 4`` (base64 alignment),
        * base64 decode failure with the underlying exception,
        * decompression failure with the underlying exception,
        * possible causes listed as *possibilities*, never conclusions.

    Never assert the cause ("this is chat-transmission corruption").
    The engine cannot prove *why* a payload is incomplete — only that
    it is.

    Machine-readable payload (v1.5.0 follow-up)
    -------------------------------------------
    Every return also carries a stable ``code`` (from
    :mod:`v2.investigation.rte.diagnostic_codes`) and a
    ``failure_type`` string. Consumers should key off these instead of
    parsing ``reason`` text.
    """
    assignments: dict[str, str] = {}
    for m in _DIAG_ASSIGN_RE.finditer(txt):
        assignments[m.group(1)] = m.group(3)
    if not assignments:
        return None

    _COMMON_CAUSES = (
        "This commonly occurs due to copy/paste truncation, logging "
        "limits, EDR field-length caps, or transport corruption — "
        "the decoder cannot determine the specific cause."
    )
    _COMPRESSION_CODES = {
        "gzip":    (CODE_GZIP_DECOMPRESSION_FAILED,    "GZIP_DECOMPRESSION_ERROR"),
        "deflate": (CODE_DEFLATE_DECOMPRESSION_FAILED, "DEFLATE_DECOMPRESSION_ERROR"),
        "brotli":  (CODE_BROTLI_DECOMPRESSION_FAILED,  "BROTLI_DECOMPRESSION_ERROR"),
    }

    for cm in _DIAG_CONSUMER_RE.finditer(txt):
        var = cm.group(2)
        if var not in assignments:
            continue
        kind = cm.group(1).lower()
        blob = assignments[var]

        # ── Machine-readable fact set (always present) ──────────
        base_meta: dict = {
            "blob_length":     len(blob),
            "blob_mod4":       len(blob) % 4,
            "expected_padding": (-len(blob)) % 4,
            "inflate_attempted": False,
            "compression_kind": kind,
            "variable":         var,
        }

        # ── Layer 1 · base64 alignment (deterministic fact) ─────
        alignment_fact = None
        if len(blob) % 4 != 0:
            alignment_fact = (
                f"Detected invalid Base64 length ({len(blob)} characters, "
                f"length mod 4 = {len(blob) % 4}). The embedded payload "
                f"appears incomplete or malformed."
            )

        # ── Layer 2 · base64 decode ─────────────────────────────
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except binascii.Error as exc:
            # Base64 alphabet violation.
            reason = (
                (alignment_fact + " " if alignment_fact else "")
                + f"Base64 decode failed: {exc}. "
                + _COMMON_CAUSES
            )
            meta = {
                **base_meta,
                "base64_exception": f"{type(exc).__name__}: {exc}",
            }
            return (kind, var, reason, meta,
                    CODE_INVALID_BASE64_ALPHABET,
                    "INVALID_BASE64_ALPHABET")

        # ── Layer 3 · decompression ─────────────────────────────
        base_meta["inflate_attempted"] = True
        base_meta["bytes_available"]   = len(raw)
        base_meta["magic_bytes"]       = raw[:4].hex()

        try:
            if kind == "gzip":
                _gzip_lib.decompress(raw)
            elif kind == "deflate":
                _zlib_lib.decompress(raw, -_zlib_lib.MAX_WBITS)
            elif kind == "brotli":
                try:
                    import brotli  # noqa: WPS433
                except ImportError:
                    reason = (
                        "Detected Brotli compression consumer but the "
                        "`brotli` library is not installed in this "
                        "runtime, so the payload cannot be inflated here."
                    )
                    return (kind, var, reason, base_meta,
                            CODE_UNSUPPORTED_COMPRESSION_STREAM,
                            "BROTLI_LIBRARY_UNAVAILABLE")
                brotli.decompress(raw)
            # Decompression succeeded — the resolver should have fired
            # and inlined. Fall through to the next consumer if any.
            continue
        except Exception as exc:
            # Report facts, list causes as possibilities.
            reason_parts = []
            if alignment_fact:
                reason_parts.append(alignment_fact)
                # Base64 length invalid AND inflate failed — attribute
                # to the more root-cause code (invalid length).
                code_for_alignment_failure = CODE_INVALID_BASE64_LENGTH
            else:
                reason_parts.append(
                    f"Base64 payload decoded to {len(raw)} bytes "
                    f"(length={len(blob)} characters, aligned)."
                )
                code_for_alignment_failure = None
            reason_parts.append(
                f"{kind.title()} inflate failed: {type(exc).__name__}: {exc}."
            )
            reason_parts.append(_COMMON_CAUSES)
            code, failure_type = _COMPRESSION_CODES.get(
                kind,
                (CODE_UNSUPPORTED_COMPRESSION_STREAM,
                 "UNKNOWN_COMPRESSION_STREAM"),
            )
            # If the root cause is the base64 alignment, expose that
            # more-specific code — analysts can then key dashboards
            # off DX1001 instead of DX1101 for this class of failure.
            if code_for_alignment_failure is not None:
                code = code_for_alignment_failure
                failure_type = "INVALID_BASE64_LENGTH"
            meta = {
                **base_meta,
                "inflate_exception": f"{type(exc).__name__}: {exc}",
            }
            return (kind, var, " ".join(reason_parts), meta,
                    code, failure_type)
    return None


class PsIndirectCompressionStreamTransformation:
    NAME = "ps_indirect_compression_stream"

    def _try(self, artifact: Artifact) -> tuple[str, bool] | None:
        # Cheap prefilter — both idioms must be present or we can't
        # possibly match.
        if not _ASSIGN_MARKER_RE.search(artifact.content):
            return None
        if not _CONSUMER_MARKER_RE.search(artifact.content):
            return None
        new_txt, changed = _resolve()(artifact.content, [])
        if not changed:
            return None
        return new_txt, True

    def applicable(self, artifact: Artifact) -> Evidence | None:
        result = self._try(artifact)
        if result is None:
            return None
        return Evidence(
            source=f"rte.{self.NAME}",
            observation="variable-bound base64 → compression stream detected",
            confidence=94,
            rationale=(
                "PowerShell script binds a `[Convert]::FromBase64String(\"…\")` "
                "literal to a variable and later consumes that variable inside "
                "`[IO.Compression.*Stream]($var, …::Decompress)`. Deterministic "
                "decompression."
            ),
            meta={},
        )

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        result = self._try(artifact)
        assert result is not None
        new_content, _ = result
        ev = Evidence(
            source=f"rte.{self.NAME}",
            observation=new_content[:120],
            confidence=94,
            rationale=(
                "Linked the variable-bound base64 assignment to its downstream "
                "compression consumer and inlined the decompressed plaintext."
            ),
            meta={
                "in_len":  len(artifact.content),
                "out_len": len(new_content),
            },
        )
        return new_content, [ev]

    def diagnose(self, artifact: Artifact):
        """Optional RTE protocol · emit a deterministic explanation when
        the plugin DETECTED a variable-bound compression pattern but
        could not decode it (corrupt / truncated / unsupported payload).

        Called by the engine only when the main loop is about to stop
        with ``NO_TRANSFORMATION`` — the analyst deserves to see the
        reason, not a silent halt.
        """
        # If applicable() would have fired we don't want a duplicate
        # diagnostic — the transformation itself will handle it.
        if self._try(artifact) is not None:
            return None
        d = _diagnose_pattern(artifact.content)
        if d is None or DecodeDiagnostic is None:
            return None
        kind, var, reason, meta, code, failure_type = d
        # Stage numbering — analyst-facing. Layer 0 is the input; the
        # first transformation would emit at stage 1. The stage this
        # diagnostic *would* correspond to is one past the current
        # artefact's layer.
        meta = {**meta, "stage": artifact.layer + 1}
        return DecodeDiagnostic(
            layer=artifact.layer,
            detector=self.NAME,
            attempted=(
                f"variable-bound `${var} = [Convert]::FromBase64String(\"…\")` "
                f"→ `[IO.Compression.{kind.title()}Stream]($ {var}, …::Decompress)`"
            ),
            outcome="decode_failed",
            reason=reason,
            meta=meta,
            code=code,
            failure_type=failure_type,
            severity=severity_of(code),
            # Plugin-level diagnostic — this IS the root cause in its
            # own layer, so ``caused_by`` is empty. The engine-level
            # orchestration diagnostic (DX2xxx) that fires after this
            # will point back to us via its own ``caused_by``.
            caused_by="",
        )


TRANSFORMATION = PsIndirectCompressionStreamTransformation()
