"""ADR-0014 · Phase 2 · Evidence priority weights (§1.1.17).

Every node kind carries a numeric weight in [0..10]. High-signal
evidence drives verdicts; low-signal metadata cannot dominate an
investigation.

The table below is the single source of truth. Any future engine
that assigns weights MUST use `weight_for(...)` from this module.
Callers may down-weight via classification (e.g. an IOC classified as
`vendor_infrastructure` overrides its base weight to 0), never up-weight.
"""
from __future__ import annotations

from typing import Optional


# Base weight table (ADR-0014 §1.1.17 governance).
#
# Keys are lower-case tokens describing evidence class. Values are
# integer weights in [0..10]. Reasoning engines multiply the weight
# by node confidence to produce contribution scores.

WEIGHTS: dict[str, int] = {
    # ── Behavioural evidence (highest signal) ────────────────────
    "child_process_execution":   10,
    "malware_disposition":       10,
    "quarantine_action":         10,
    "sha_matched_family":        10,
    "network_beacon":             9,
    "persistence":                9,
    "credential_access":          9,
    "lateral_movement":           9,
    "lsass_access":               9,
    # ── Semantic evidence ────────────────────────────────────────
    "lolbin":                     7,
    "signed_binary_proxy":        7,
    "encoded_powershell":         6,
    "obfuscated_command":         6,
    "reflective_injection":       8,
    # ── Structural / metadata (lower signal) ─────────────────────
    "external_ioc_url":           6,
    "external_ioc_domain":        6,
    "external_ioc_ip":            7,
    "hash_ioc":                   7,
    "mitre_technique":            5,
    # ── Zero-weight (must never dominate) ────────────────────────
    "vendor_infrastructure":      0,
    "certificate_infrastructure": 0,
    "internal_asset":             1,
    "vendor_metadata":            0,
    "schema_url":                 0,
    # ── Fallback ─────────────────────────────────────────────────
    "unknown":                    0,
}


def weight_for(kind: str, *, category: Optional[str] = None) -> int:
    """Return the priority weight in [0..10] for a given evidence
    kind, honouring the classification category override.

    `category` is an IOC classification (see `ioc_classifier`). If
    supplied, it can DOWN-WEIGHT the base kind (e.g. an `ioc.url`
    classified as `vendor_infrastructure` returns 0).
    """
    if category and category in WEIGHTS:
        cat_w = WEIGHTS[category]
        base_w = WEIGHTS.get(kind, 0)
        # Rule: classification NEVER up-weights.
        return min(cat_w, base_w) if cat_w == 0 else base_w
    return WEIGHTS.get(kind, 0)


def is_high_signal(weight: int) -> bool:
    """Convenience: is this evidence sufficient to drive a verdict?"""
    return weight >= 7


def is_dominant(weight: int) -> bool:
    """Convenience: is this evidence a verdict-driver on its own?"""
    return weight >= 9


__all__ = ["WEIGHTS", "weight_for", "is_high_signal", "is_dominant"]
