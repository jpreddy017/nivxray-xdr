"""Plugin · XOR Brute (Cap Pack 1 · #4 · Priority 1) · via ADAPTER.

Uses the semantic-typed Capability Registry Adapter to wrap the existing
``decoders.xor_brute.XorBruteDecoder`` (production module) into UAIE
without any hand-crafted wrapper.  This is the pattern for onboarding
the remaining 40+ decoders under ``decoders/``.

Semantic type
─────────────
``decoder`` — emits a child ``xor_decoded`` artifact when a key is
found.  The child re-enters the orchestrator queue so any downstream
capability (PE analyzer, CS beacon config parser, shellcode analyzer)
can consume the plaintext.

Profiles: ``malware``, ``enterprise``, ``universal``.
"""
from __future__ import annotations

from ...capability_adapter import adapt_and_register
from decoders.xor_brute import XorBruteDecoder as _LEGACY


plugin = adapt_and_register(
    legacy=_LEGACY,
    semantic="decoder",
    child_artifact_type="xor_decoded",
    artifact_types=["text", "shellcode_bytes", "gzip_decoded",
                    "base64_decoded", "pe_bytes"],
    profiles=["malware", "enterprise", "universal"],
    name_override="crypto.xor_brute",
    version="1.0.0",
)
