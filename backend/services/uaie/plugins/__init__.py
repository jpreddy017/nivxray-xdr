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


def all_recognizers() -> List[Recognizer]:
    """Every registered plugin's Recognizer — pass this list directly
    to ``Orchestrator(recognizers=all_recognizers())``.  R25/R26: order
    is registration order; deterministic across runs."""
    return [p["recognizer"] for p in _PLUGINS]


# ── Load every plugin so registration side-effects fire ────────────
from . import base64_bare              # noqa: F401,E402
from . import base64_frombase64string  # noqa: F401,E402
from . import powershell_encoded_command  # noqa: F401,E402
from . import gzip_inflate             # noqa: F401,E402
from . import zlib_inflate             # noqa: F401,E402
from . import shellcode_string_scan    # noqa: F401,E402
from . import shellcode_analyzer      # noqa: F401,E402  · Capability Pack 1 · #1
from . import pe_analyzer             # noqa: F401,E402  · Capability Pack 1 · #2
from . import cs_beacon_config_parser # noqa: F401,E402  · Capability Pack 1 · #3
from . import xor_brute               # noqa: F401,E402  · Capability Pack 1 · #4 (via adapter)
# ── Priority 2 · PowerShell stack (via adapter) ────────────────────
from . import ps_alias_normalizer     # noqa: F401,E402
from . import ps_backtick_normalizer  # noqa: F401,E402
from . import ps_hex_escape           # noqa: F401,E402
from . import ps_reconstruct          # noqa: F401,E402
# ── Priority 3 · function-only PS transformers (via transformer_op_adapter) ─
from . import op_ps_encodedcommand_multilayer  # noqa: F401,E402
from . import op_ps_hex_csv_inline             # noqa: F401,E402
from . import op_ps_xor_inline_key             # noqa: F401,E402
from . import op_ps_normalize                  # noqa: F401,E402
from . import op_ps_reverse_string             # noqa: F401,E402
from . import op_ps_reverse_regex_swap         # noqa: F401,E402
from . import op_ps_semantic_mini              # noqa: F401,E402
# ── Priority 4 · Universal Family Recognizer (all artifact types) ──
from . import family_universal_recognizer      # noqa: F401,E402
# ── Priority 5 · Crypto Stack (RC4 / AES / ciphertext-shape / annotator) ─
from . import crypto_rc4                        # noqa: F401,E402
from . import crypto_aes_cbc                    # noqa: F401,E402
from . import crypto_shape_detector             # noqa: F401,E402
from . import op_rc4_inline_decrypt             # noqa: F401,E402
from . import op_crypto_api_annotator           # noqa: F401,E402
# ── Priority 6 · PE Extractor + .NET Recognizer ────────────────────
from . import pe_extractor                       # noqa: F401,E402
from . import pe_dotnet_recognizer               # noqa: F401,E402
# ── R28.3 · Artifact Quality Assurance Layer ───────────────────────
# Validators (diagnose only) MUST be imported before repairs so the
# validator registry is populated before any downstream consumer.
from . import validator_base64_text               # noqa: F401,E402
from . import validator_pe_bytes                  # noqa: F401,E402
from . import validator_shellcode_bytes           # noqa: F401,E402
from . import validator_gzip_bytes                # noqa: F401,E402
# Repair capabilities (transform only) — one strategy per plugin.
from . import repair_base64_strip_html_entities   # noqa: F401,E402
from . import repair_base64_surgical              # noqa: F401,E402
# validator_gzip_bytes also registers its repair capability inline.
# ── R28.7.2 · Plugin 1 · Contract-only registration (proves R28.7.1
# wiring).  This plugin registers EXCLUSIVELY via the Capability
# Registry — no orchestrator, planner, lifecycle, QA, or termination
# change was required to land it.
from . import transformer_byte_array_xor_loop            # noqa: F401,E402
# ── R28.7.3 · Plugins 2 & 3 — vertical chain (binary_bytes →
# configuration → IOC artifacts).  Contract-only registrations.
from . import extractor_binary_configuration              # noqa: F401,E402
from . import promoter_configuration_iocs                 # noqa: F401,E402
