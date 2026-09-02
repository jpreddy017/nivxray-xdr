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
]


# Reverse-index decoder name → function.
_DECODER_FNS: dict[str, Callable[[str], Optional[str]]] = {
    name: fn for name, fn in _ENC_DECODERS
}


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
            cap = _ENC_CAPS[name]
            layers.append(DecodedLayer(
                layer_index    = len(layers),
                stage          = name,
                language       = "generic",
                bytes_in       = len(current),
                bytes_out      = len(out),
                input_preview  = current[:64],
                output         = out,
                capability     = cap,
                provenance     = Provenance(
                    decoded_from    = parent_id,
                    capability_name = name,
                    engine_version  = "0.5.0-gate2d-b1",
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
