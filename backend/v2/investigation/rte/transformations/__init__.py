"""Transformation plugin registry.

Every plugin implements the ``Transformation`` protocol and is
registered here so the engine can discover it. Adding a new
transformation is a one-file change:

    1. Create ``transformations/my_new_transform.py`` implementing
       the protocol.
    2. Import its ``TRANSFORMATION`` singleton here and append it
       to ``TRANSFORMATION_REGISTRY``.

Ordering in the registry is a TIE-BREAKER only. The engine picks the
transformation with the highest ``applicable()`` confidence for a
given artefact — registry order is used only when two transformations
would fire with identical confidence, in which case the earlier one
wins for determinism.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from ...evidence import Evidence
from ..models import Artifact


@runtime_checkable
class Transformation(Protocol):
    """Contract every transformation plugin must honour.

    A transformation is a DETERMINISTIC operation on an ``Artifact``.
    Never runs user code. Never fabricates output. If the operation
    cannot be performed with full determinism (e.g. runtime key is
    required), the plugin MUST return ``None`` from ``applicable()``
    so the engine stops rather than producing false plaintext.
    """

    NAME: str

    def applicable(self, artifact: Artifact) -> Evidence | None:
        """Return an ``Evidence`` object with a confidence 1-100 if this
        transformation can be applied to ``artifact`` deterministically;
        return ``None`` otherwise. Side-effect-free. MUST NOT raise on
        any well-formed artefact."""
        ...

    def apply(self, artifact: Artifact) -> tuple[str, list[Evidence]]:
        """Perform the transformation. Return the NEW content plus any
        additional evidence collected while transforming. The engine
        wraps the result into a new ``Artifact`` after reclassifying
        via Input Understanding. MUST be deterministic."""
        ...


# ── Registry ────────────────────────────────────────────────────
from .base64_utf16le import TRANSFORMATION as _T_B64_UTF16LE          # noqa: E402
from .base64_utf8 import TRANSFORMATION as _T_B64_UTF8                # noqa: E402
from .base64_bytes import TRANSFORMATION as _T_B64_BYTES              # noqa: E402
from .gzip_stream import TRANSFORMATION as _T_GZIP                    # noqa: E402
from .zlib_stream import TRANSFORMATION as _T_ZLIB                    # noqa: E402
from .hex_string import TRANSFORMATION as _T_HEX                      # noqa: E402
from .ps_char_array import TRANSFORMATION as _T_PS_CHAR               # noqa: E402
from .ps_format import TRANSFORMATION as _T_PS_FORMAT                 # noqa: E402
from .ps_iex_peel import TRANSFORMATION as _T_PS_IEX                  # noqa: E402
from .ps_encoded_command import TRANSFORMATION as _T_PS_ENC           # noqa: E402
from .ps_static_base64 import TRANSFORMATION as _T_PS_STATIC_B64      # noqa: E402
from .ps_compression_stream import TRANSFORMATION as _T_PS_COMPRESS   # noqa: E402


TRANSFORMATION_REGISTRY: list[Transformation] = [
    # Command-level peel first so ``powershell -EncodedCommand`` becomes
    # its plaintext script BEFORE the generic base64 detectors fire.
    _T_PS_ENC,
    # PS-language surface transformations (format-string / char-array /
    # IEX unwrap) preferred over raw base64/hex when they apply so we
    # peel the syntactic wrapper first.
    _T_PS_FORMAT,
    _T_PS_CHAR,
    _T_PS_IEX,
    # PS-embedded static base64 and compression calls come next so a
    # `[Convert]::FromBase64String("...")` inside a larger script fires
    # before the whole-artefact base64 plugins.
    _T_PS_STATIC_B64,
    _T_PS_COMPRESS,
    # Raw binary encodings — order matters: UTF-16LE-decoded base64
    # (the classic Windows form) is preferred over utf-8/latin-1 base64
    # when both would decode.
    _T_B64_UTF16LE,
    _T_B64_UTF8,
    _T_B64_BYTES,
    # Compression handled AFTER base64 because compressed blobs are
    # usually delivered inside a base64 wrapper.
    _T_GZIP,
    _T_ZLIB,
    # Hex-encoded byte strings.
    _T_HEX,
]

__all__ = ["Transformation", "TRANSFORMATION_REGISTRY"]
