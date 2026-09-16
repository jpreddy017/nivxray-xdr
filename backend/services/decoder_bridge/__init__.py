"""Decoder-in-Pipeline plumbing (P0-0 remediation).

Bridges the *existing* recursive decoder engine into the incident
investigation pipeline.  This module writes ZERO new decoder or
codec logic — every transformation is delegated to
`services.die.preprocessor.recursive_decoder.peel_recursively`
which was already shipped, tested, and API-exposed.

What we add here:
  · A stable `decode_commandline(text, canonical_id)` API that
    returns a list of `CanonicalDecodedLayer` records.
  · Each layer carries `provenance.decoded_from=<parent_canonical_id>`
    so IOC / ATT&CK / Verdict / Narration surfaces can trace any
    downstream claim back to its originating raw evidence.
  · A `project_iocs(layers)` helper that runs the existing
    `services.die.ioc_semantic.extract_iocs` over every layer so
    decoded IOCs actually reach the incident.

Invariants (owner-locked):
  · Technique claim → supporting evidence required.
  · Decoded IOC → provenance back to original evidence required.
  · No evidence → no claim.
  · The LLM explains evidence.  It does NOT create evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
import uuid

from services.die.preprocessor.recursive_decoder import peel_recursively


@dataclass(frozen=True)
class CanonicalDecodedLayer:
    """One decoded layer as a canonical evidence CHILD of its parent."""
    canonical_id:    str
    parent_id:       str
    layer_index:     int
    stage:           str           # e.g. "ps_encodedcommand", "gzip_bytes"
    bytes_in:        int
    bytes_out:       int
    elapsed_ms:      float
    text:            str           # decoded payload (bounded)
    meta:            dict[str, Any]
    provenance:      dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _new_id(parent_id: str, layer_index: int) -> str:
    salt = uuid.uuid4().hex[:8]
    return f"{parent_id}::decoded[{layer_index}]::{salt}"


def decode_commandline(
    text: str,
    parent_canonical_id: str,
    *,
    max_layers: int = 8,
    text_cap: int = 32 * 1024,
) -> tuple[str, list[CanonicalDecodedLayer]]:
    """Run the EXISTING recursive decoder and project each layer as
    a canonical child of `parent_canonical_id`.

    Returns:
        `(final_text, layers[])`.  `final_text` is the fully-peeled
        payload (or `text` unchanged if no decoder made progress).
    """
    if not text:
        return text, []
    final_text, raw_layers = peel_recursively(
        text, max_layers=max_layers)
    now = datetime.now(timezone.utc).isoformat()
    out: list[CanonicalDecodedLayer] = []
    for lyr in raw_layers or []:
        stage = str(lyr.get("stage") or "")
        if stage.startswith("abort") or stage.endswith("_error"):
            # Non-progress layers still get recorded honestly so
            # analysts can see attempted decodes that failed.
            payload_text = ""
        else:
            payload_text = (final_text or "")[:text_cap] \
                if lyr is raw_layers[-1] else ""
        out.append(CanonicalDecodedLayer(
            canonical_id = _new_id(parent_canonical_id,
                                                    lyr.get("layer", 0)),
            parent_id    = parent_canonical_id,
            layer_index  = int(lyr.get("layer", 0)),
            stage        = stage,
            bytes_in     = int(lyr.get("bytes_in",  0)),
            bytes_out    = int(lyr.get("bytes_out", 0)),
            elapsed_ms   = float(lyr.get("elapsed_ms", 0.0)),
            text         = payload_text,
            meta         = dict(lyr.get("meta") or {}),
            provenance   = {
                "decoded_from": parent_canonical_id,
                "engine":       "services.die.preprocessor.recursive_decoder",
                "stage":        stage,
                "layer_index":  int(lyr.get("layer", 0)),
                "recorded_at":  now,
                # Honest-state invariant — decoding is EVIDENCE, not a
                # verdict.  This flag is enforced by pytest.
                "attck_promotion": False,
            },
        ))
    return final_text, out


def project_iocs(
    layers: list[CanonicalDecodedLayer],
) -> list[dict[str, Any]]:
    """Run the EXISTING IOC extractor over every decoded layer's
    payload and stamp provenance back to the layer that produced it.

    Uses `services.die.ioc_semantic.extract_iocs(source="decoded")`
    — no new IOC logic is written here.
    """
    from services.die.ioc_semantic import extract_iocs   # deferred
    projected: list[dict[str, Any]] = []
    for lyr in layers:
        if not lyr.text:
            continue
        try:
            iocs = extract_iocs(lyr.text, source="decoded") or []
        except Exception:
            iocs = []
        for ioc in iocs:
            projected.append({
                **ioc,
                "provenance": {
                    "decoded_from":         lyr.parent_id,
                    "decoded_layer_id":     lyr.canonical_id,
                    "decoded_stage":        lyr.stage,
                    "decoded_layer_index":  lyr.layer_index,
                    "attck_promotion":      False,
                },
            })
    return projected


def has_progress(layers: list[CanonicalDecodedLayer]) -> bool:
    """True iff at least one layer actually produced decoded output."""
    return any(l.bytes_out > 0 and l.text for l in layers)
