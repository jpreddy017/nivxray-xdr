"""Stage-2 Verdict Engine · deterministic fingerprint.

Owner rule #6: separate deterministic verdict content from
operational metadata.  ``generated_at`` (and any other volatile
metadata) MUST NOT enter the fingerprint.

The fingerprint answers: "Is this Stage-2 output byte-identical to
what a re-computation with the same canonical inputs would produce?"
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List


# Fields excluded from the fingerprint — operational only.
_VOLATILE_FIELDS = frozenset({"generated_at"})


def _canonicalise(obj: Any) -> Any:
    """Recursively canonicalise dicts/lists for deterministic
    JSON serialisation.  Sorts keys, strips None values, coerces
    tuples/sets to sorted lists."""
    if isinstance(obj, dict):
        return {k: _canonicalise(v) for k, v in sorted(obj.items())
                if v is not None and k not in _VOLATILE_FIELDS}
    if isinstance(obj, (list, tuple)):
        return [_canonicalise(v) for v in obj]
    if isinstance(obj, set):
        return sorted(_canonicalise(v) for v in obj)
    return obj


def inputs_hash(canonical_inputs: Dict[str, Any]) -> str:
    """Deterministic sha256 of the canonical Stage-2 input snapshot.

    ``canonical_inputs`` is the normalised input dict produced by
    ``services.verdict_stage2.inputs.build_inputs``.  It contains
    Timeline events, tactics, objectives, v3.x verdict, and case
    identity — every deterministic input to the rule engine.
    """
    payload = json.dumps(_canonicalise(canonical_inputs),
                            sort_keys=True, ensure_ascii=False,
                            default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def verdict_fingerprint(verdict_dict: Dict[str, Any]) -> str:
    """Deterministic sha256 of a Stage-2 verdict envelope.

    ``verdict_dict`` is the ``Stage2Verdict.to_dict()`` output.  The
    ``generated_at`` and ``fingerprint`` fields are stripped before
    hashing so two verdicts produced from the same inputs at different
    times produce IDENTICAL fingerprints.
    """
    scrubbed = {k: v for k, v in verdict_dict.items()
                  if k not in _VOLATILE_FIELDS and k != "fingerprint"}
    payload = json.dumps(_canonicalise(scrubbed),
                            sort_keys=True, ensure_ascii=False,
                            default=str).encode()
    return hashlib.sha256(payload).hexdigest()


__all__ = ["inputs_hash", "verdict_fingerprint"]
