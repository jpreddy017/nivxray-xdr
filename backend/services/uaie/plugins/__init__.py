"""UAIE Plugins · Phase 2 · Migrated Legacy Decoders (R26 strict).

Each plugin is a ``Recognizer + Capability`` pair that wraps the
byte-identical legacy decoder from
``services.die.preprocessor.recursive_decoder``.  This preserves
legacy behaviour exactly — no logic changes, no output changes —
which is the R26 requirement for Phase 2 migration.

Layout
──────
    plugins/
        base64_bare/            · standalone long base64 blob
        base64_frombase64string/· [Convert]::FromBase64String("…")
        powershell_encoded_command/  · powershell -EncodedCommand
        gzip_inflate/           · gzip magic on @@RAWBYTES@@
        zlib_inflate/           · zlib magic on @@RAWBYTES@@
        shellcode_string_scan/  · IP/URL/domain scan on raw bytes

Plugin contract (R26 · frozen)
──────────────────────────────
    · one decoder = one plugin
    · plugins never touch the queue
    · pure functions (no hidden state)
    · self-tests co-located with the plugin
    · byte-for-byte equivalent to legacy

CI Gate
───────
``tests/test_plugins_match_legacy.py`` iterates every plugin over a
shared corpus and asserts ``plugin.execute(a) == legacy(a.payload)``
bit-for-bit before UAIE integration is permitted.
"""
from __future__ import annotations

from typing import List

from ..recognizer import Recognizer
from ..capability import Capability

# Plugin registry (populated by side-effect on import).
_PLUGINS: List[dict] = []


def register_plugin(name: str, version: str,
                    recognizer: Recognizer, capability: Capability,
                    *,
                    wraps_legacy: str) -> None:
    """Register a Recognizer+Capability plugin pair.

    ``wraps_legacy`` is the fully-qualified legacy symbol this plugin
    wraps (e.g. ``"recursive_decoder._decode_bare_base64"``) so the
    CI gate can locate the reference implementation for byte-equivalence
    checks.
    """
    _PLUGINS.append({
        "name":          name,
        "version":       version,
        "recognizer":    recognizer,
        "capability":    capability,
        "wraps_legacy":  wraps_legacy,
    })


def all_plugins() -> List[dict]:
    return list(_PLUGINS)


# ── Load every plugin so registration side-effects fire ────────────
from . import base64_bare              # noqa: F401,E402
from . import base64_frombase64string  # noqa: F401,E402
from . import powershell_encoded_command  # noqa: F401,E402
from . import gzip_inflate             # noqa: F401,E402
from . import zlib_inflate             # noqa: F401,E402
from . import shellcode_string_scan    # noqa: F401,E402
