"""Plugin · transformer.byte_array_xor_loop  (R28.7.2 · Plugin 1 / 3)

Generic transformer that recognises the classic malware-loader pattern:

    [Byte[]]$buf = [System.Convert]::FromBase64String('<BASE64>')
    for ($i = 0; $i -lt $buf.Count; $i++) {
        $buf[$i] = $buf[$i] -bxor <KEY>
    }

This capability knows NOTHING about Cobalt Strike, Metasploit, Sophos,
Talos, or any specific malware family.  It knows about ONE technique:

    · byte-array literal decoded from base64
    · single-byte XOR loop applied to that array with a constant key

Given a script artifact whose text contains BOTH patterns, the plugin:
    1. Extracts the base64 blob and the XOR key deterministically.
    2. Decodes the base64 payload.
    3. Applies XOR with the extracted key to every byte.
    4. Emits ONE new child artifact of type ``binary_bytes`` whose
       payload is the XOR-decoded bytes.

The plugin is registered EXCLUSIVELY via the Capability Registry
(R28.6).  No orchestrator, planner, lifecycle, QA, or termination
change is needed — the R28.7.1 wiring picks it up automatically.

Acceptance metric (R28.7.2, user-stipulated 2026-02-15):
    · New contracts added:   1
    · Orchestrator changes:  0
    · Planner changes:       0
    · Registry changes:      0
    · Lifecycle changes:     0
    · QA changes:            0
    · SSOT changes:          0
    · Termination changes:   0
"""
from __future__ import annotations

import base64
import re
from typing import Optional, Tuple

from ...artifact   import make_artifact
from ...capability import CapabilityResult
from ...contract   import (CAT_EXECUTOR, CapabilityContract, IMPROVES_ANALYSIS,
                              IMPROVES_DECODE, register)


# ── Deterministic patterns ─────────────────────────────────────────
# Base64 literal inside FromBase64String('...') or FromBase64String("...").
# We accept optional whitespace and both quote styles.
_B64_RE = re.compile(
    r"""FromBase64String\s*\(\s*['"]([A-Za-z0-9+/=\s]+)['"]\s*\)""",
    re.IGNORECASE | re.DOTALL,
)

# The XOR-loop signature.  We accept both decimal keys and 0x-prefixed
# hex keys.  We deliberately require the ``-bxor`` operator to avoid
# matching irrelevant subtract expressions.
_XOR_LOOP_RE = re.compile(
    r"""[\$]\w+\s*\[\s*\$?\w+\s*\]\s*=\s*[\$]\w+\s*\[\s*\$?\w+\s*\]\s*
        -bxor\s+(0[xX][0-9a-fA-F]+|\d+)""",
    re.VERBOSE,
)


def _extract(text: str) -> Optional[Tuple[bytes, int]]:
    """Return ``(base64-decoded bytes, xor_key)`` if the text contains
    BOTH patterns, else ``None``.  Never raises."""
    m_b64 = _B64_RE.search(text)
    m_xor = _XOR_LOOP_RE.search(text)
    if not m_b64 or not m_xor:
        return None
    b64_blob = re.sub(r"\s+", "", m_b64.group(1))
    key_str  = m_xor.group(1)
    try:
        key = int(key_str, 16) if key_str.lower().startswith("0x") else int(key_str)
    except ValueError:
        return None
    if not (0 <= key <= 0xFF):
        return None
    try:
        raw = base64.b64decode(b64_blob, validate=False)
    except Exception:
        return None
    if not raw:
        return None
    return raw, key


# ══════════════════════════════════════════════════════════════════
# Capability implementation (Capability protocol · legacy shape)
# ══════════════════════════════════════════════════════════════════
class _Impl:
    """Executor implementation.  Registered EXCLUSIVELY via the
    Capability Registry — never touches ``capability._REGISTRY``."""
    name = "transformer.byte_array_xor_loop"
    requires_artifact_type = ["text", "powershell", "powershell_normalized",
                                "gzip_decoded"]
    requires_evidence      = []

    def execute(self, artifact) -> CapabilityResult:
        try:
            text = artifact.payload.decode("utf-8", errors="ignore")
        except Exception:
            return CapabilityResult()
        pair = _extract(text)
        if pair is None:
            return CapabilityResult()
        raw, key = pair
        decoded = bytes(b ^ key for b in raw)
        child = make_artifact(
            decoded, "binary_bytes",
            parent_uri=artifact.uri,
            depth=artifact.depth + 1,
            discovered_by=self.name,
            meta={
                "byte_array_xor_loop": {
                    "xor_key_dec": key,
                    "xor_key_hex": f"0x{key:02x}",
                    "base64_length_bytes":  len(raw),
                    "decoded_length_bytes": len(decoded),
                },
            },
        )
        return CapabilityResult(child_artifacts=[child])


# ══════════════════════════════════════════════════════════════════
# Contract + registration (side-effect on import)
# ══════════════════════════════════════════════════════════════════
_impl = _Impl()

register(
    CapabilityContract(
        id="transformer.byte_array_xor_loop",
        version="1.0",
        category=CAT_EXECUTOR,
        # Any script-shaped text can contain the pattern.  We list the
        # concrete script/text types we've seen in the wild; add more
        # in ``requires`` as new decoders emit new types.
        requires=("text", "powershell", "powershell_normalized",
                    "gzip_decoded"),
        produces=("binary_bytes",),
        consumes=(),
        improves=(IMPROVES_DECODE, IMPROVES_ANALYSIS),
        confidence_gain=0.55,
        produces_confidence=(
            ("decode_confidence",   0.55),
            ("analysis_confidence", 0.20),
        ),
        cost=2,
        priority_hint=3,          # Prefer over generic analyzers when applicable
        parallelizable=True,
        deterministic=True,
        description=(
            "Extracts a byte-array-from-base64 literal + single-byte XOR "
            "loop from any script-shaped text and emits the XOR-decoded "
            "bytes as a `binary_bytes` child.  Generic — no malware-family "
            "logic."
        ),
    ),
    impl=_impl,
)


__all__ = ["_impl"]
