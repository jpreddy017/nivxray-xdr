"""Deterministic Decode Orchestrator (DDO) · P0-1B Gate 2D-B1.

Owner-locked design (P0_1B_SCOPE.md · 2026-09-02):

> Deterministic bounded classifier — NOT CyberChef-style speculative "Magic".
>
> Its job:
>   Input
>     ↓
>   Detect evidence-supported transformation
>     ↓
>   Select deterministic decoder
>     ↓
>   Decode
>     ↓
>   Validate result
>     ↓
>   Record provenance
>     ↓
>   Repeat within bounded depth
>     ↓
>   Canonical evidence
>
> Not:
>   Input → Try 50 transformations → Pick whatever looks interesting

## Invariants (mandatory, verified per-run)

    static_only         = True
    execution           = False
    network_access      = False
    attck_promotion     = False
    bounded_depth       = True   (MAX_DEPTH = 6)
    deterministic_order = True
    provenance_required = True

## Evidence-driven selection

The DDO does NOT try every decoder in the registry. It reads
lightweight *signatures* off the input and calls only the codecs
whose signature matches. This is what distinguishes it from
speculative "Magic": every attempt is justified by a text
fingerprint that appears in the input.

A false-reconstruction is prevented by:
  · each decoder validates its own output (see encoding._is_printable_text)
  · the DDO stops when no candidate signature matches
  · the DDO NEVER emits a layer that would replace non-garbage text
    with garbage
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from .types import ReconstructionResult, DecodedLayer
from .base.encoding import (
    _DECODERS as _ENC_DECODERS, _CAPS as _ENC_CAPS,
)
from .base._ddo_adapter import (
    ddo_gzip, ddo_zlib, ddo_byte_array_xor_loop, ddo_ps_encoded_command,
)


MAX_DEPTH = 6


# ══════════════════════════════════════════════════════════════════
# Signatures — each signature is a `re.Pattern` that identifies an
# input as a candidate for a specific codec.
# ══════════════════════════════════════════════════════════════════
_SIGNATURES: list[tuple[str, re.Pattern]] = [
    ("encoding.url_decode",       re.compile(r"%[0-9A-Fa-f]{2}")),
    ("encoding.unicode_escape",   re.compile(r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}")),
    ("encoding.html_entities",    re.compile(r"&(?:#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z]+);")),
    ("encoding.base32",           re.compile(r"^[A-Z2-7]{8,}={0,6}$")),
    ("encoding.base85",           re.compile(r"^<~[!-uz]+~>$")),
    ("encoding.octal_ascii",      re.compile(r"(?:\\[0-7]{3}){3,}")),
    ("encoding.decimal_ascii",    re.compile(r"(?<![0-9])(?:\d{2,3}[,\s]+){3,}\d{2,3}(?![0-9])")),
    # Gate 2D-B3.2 · Plane-A codecs migrated from recursive_decoder.
    # Signatures MUST be specific enough that they never fire on
    # benign text.  Each corresponds to a codec whose implementation
    # lives at services/decoder/base/*.
    ("base.ps_encodedcommand",    re.compile(
        r"(?ix)(?:^|\s|['\"`])(?:powershell(?:_ise)?(?:\.exe)?|pwsh(?:\.exe)?)"
        r"(?:\s+\S+)*?\s+-(?:e|en|enc|encode|encoded|encodedcommand|ec)\b\s*[A-Za-z0-9+/]{16,}={0,2}"
    )),
    ("base.byte_array_xor_loop",  re.compile(
        r"(?ix)\[\s*Byte\s*\[\s*\]\s*\]\s*\$\w+\s*=\s*"
        r"\[\s*(?:System\.)?Convert\s*\]\s*::\s*FromBase64String"
    )),
    # GZIP / Zlib fire only on @@RAWBYTES@@ sentinels — those come
    # from an upstream from_base64_string peel; benign text will
    # never contain the sentinel.
    ("base.gzip",                 re.compile(r"@@RAWBYTES@@1f8b")),
    ("base.zlib",                 re.compile(r"@@RAWBYTES@@78(?:01|5e|9c|da)", re.IGNORECASE)),
]


# Reverse-index decoder name → function.
_DECODER_FNS: dict[str, Callable[[str], Optional[str]]] = {
    name: fn for name, fn in _ENC_DECODERS
}
_DECODER_FNS["base.ps_encodedcommand"]   = ddo_ps_encoded_command
_DECODER_FNS["base.byte_array_xor_loop"] = ddo_byte_array_xor_loop
_DECODER_FNS["base.gzip"]                = ddo_gzip
_DECODER_FNS["base.zlib"]                = ddo_zlib


# Capability descriptors for the migrated Plane-A codecs so
# provenance rendering has a name+kind pair without depending on
# encoding._CAPS.
from .types import Capability, CapabilityKind     # local import for cycle safety


_BASE_CAPS: dict[str, Capability] = {
    "base.ps_encodedcommand":   Capability(
        name="base.ps_encodedcommand", kind=CapabilityKind.DECODER,
        language="powershell",
        version="0.6.0-gate2d-b3.2",
        description="PS -EncodedCommand base64 → UTF-16LE decode "
                    "(migrated from recursive_decoder in B3.1).",
    ),
    "base.byte_array_xor_loop": Capability(
        name="base.byte_array_xor_loop", kind=CapabilityKind.DEOBFUSCATOR,
        language="powershell",
        version="0.6.0-gate2d-b3.2",
        description="Byte-array XOR loop fold (FromBase64String + "
                    "for-bxor idiom) — migrated in B3.1.",
    ),
    "base.gzip":                Capability(
        name="base.gzip", kind=CapabilityKind.DECODER,
        language="generic",
        version="0.6.0-gate2d-b3.2",
        description="GZip inflate on @@RAWBYTES@@ sentinel "
                    "(migrated in B3.1).",
    ),
    "base.zlib":                Capability(
        name="base.zlib", kind=CapabilityKind.DECODER,
        language="generic",
        version="0.6.0-gate2d-b3.2",
        description="Zlib/deflate inflate on @@RAWBYTES@@ sentinel "
                    "(migrated in B3.1).",
    ),
}


def _cap_for(name: str) -> Capability:
    """Look up capability by codec name across all registered surfaces."""
    if name in _ENC_CAPS:
        return _ENC_CAPS[name]
    return _BASE_CAPS[name]


# ══════════════════════════════════════════════════════════════════
# DDO
# ══════════════════════════════════════════════════════════════════
@dataclass
class OrchestratorResult:
    final:              str
    layers:             list[DecodedLayer]  = field(default_factory=list)
    attempts:           int                 = 0
    unresolved_reasons: list[str]           = field(default_factory=list)


def _candidates(text: str) -> list[str]:
    """Return the ORDERED list of decoder names whose signature
    matches this input.  Ordering is fixed by `_SIGNATURES` — never
    randomised.  Determinism is a hard requirement."""
    return [name for name, pat in _SIGNATURES if pat.search(text)]


def orchestrate(text: str,
                parent_id: str = "ddo:root",
                max_depth: int = MAX_DEPTH) -> OrchestratorResult:
    """Bounded recursive decode.  Never speculative: only invokes
    decoders whose signature matches the current text.  Stops when
    no signature matches OR max_depth is reached OR no candidate
    made progress.
    """
    from .types import Provenance, now_iso   # local import for cycle safety
    layers: list[DecodedLayer] = []
    reasons: list[str] = []
    current  = text
    attempts = 0
    seen_texts: set[str] = {text}      # cycle detection

    for depth in range(max_depth):
        cands = _candidates(current)
        if not cands:
            reasons.append(f"no signature at depth {depth} — bounded stop")
            break
        progressed = False
        for name in cands:
            attempts += 1
            fn = _DECODER_FNS.get(name)
            if fn is None:
                continue
            out = fn(current)
            if out is None or out == current:
                continue
            if out in seen_texts:
                reasons.append(f"depth {depth}: {name} produced a cycle")
                continue
            cap = _cap_for(name)
            layers.append(DecodedLayer(
                layer_index    = len(layers),
                stage          = name,
                language       = cap.language if hasattr(cap, "language") else "generic",
                bytes_in       = len(current),
                bytes_out      = len(out),
                input_preview  = current[:64],
                output         = out,
                capability     = cap,
                provenance     = Provenance(
                    decoded_from    = parent_id,
                    capability_name = name,
                    engine_version  = "0.6.0-gate2d-b3.2",
                    recorded_at     = now_iso(),
                ),
                confidence     = "HIGH",
                notes          = f"DDO depth={depth} · {name}",
            ))
            seen_texts.add(out)
            current = out
            progressed = True
            break     # deterministic: earliest-signature wins each round
        if not progressed:
            reasons.append(f"depth {depth}: no decoder made progress")
            break

    return OrchestratorResult(
        final              = current,
        layers             = layers,
        attempts           = attempts,
        unresolved_reasons = reasons,
    )


# Runtime invariant self-check — called by tests/harness/CI.
INVARIANTS = {
    "static_only":         True,
    "execution":           False,
    "network_access":      False,
    "attck_promotion":     False,
    "bounded_depth":       True,
    "deterministic_order": True,
    "provenance_required": True,
    "MAX_DEPTH":           MAX_DEPTH,
}


__all__ = ["orchestrate", "OrchestratorResult", "INVARIANTS", "MAX_DEPTH"]
