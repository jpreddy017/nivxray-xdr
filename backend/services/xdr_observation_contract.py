"""
NivXRay XDR — Observation Contract (Platform-Wide)

Codifies the CAPABILITY ≠ DETECTION ≠ CORRELATION ≠ VERDICT principle
as a reusable module that ANY detection subsystem (LOLBAS, GTFOBins,
LOLDrivers, Sigma, OSINT, IOC intel) must adopt when returning
match evidence to the NivXRay pipeline.

Never claim a verdict from a single primitive.
Never label a legitimate binary "suspicious" or "malicious" solely
because it is a known LOLBIN.
"""
from __future__ import annotations

from typing import Literal

# ── Observation types ────────────────────────────────────────────
ObservationType = Literal[
    "LOLBIN",              # a known living-off-the-land binary was observed
    "LOLBIN_CAPABILITY",   # LOLBIN category, e.g. "download", "execute"
    "PARENT_CHILD",        # parent-child process relation
    "SEQUENCE",            # multi-hop named tradecraft chain
    "PATTERN",             # regex / cli-heuristic / sigma-like pattern
    "IOC",                 # IOC reputation match
    "ATTACK_TECHNIQUE",    # MITRE ATT&CK technique mapping
    "DETECTION",           # rule-driven detection observation
    "CORRELATION",         # correlation-engine emission
    "NEGATIVE_EVIDENCE",   # expected-but-missing signal
    "IDENTITY",
    "NETWORK",
    "FILE",
]

# ── Signal strengths ─────────────────────────────────────────────
# OBSERVED       — the thing exists.  Zero contribution to a verdict.
# INFORMATIONAL  — context only.
# WEAK           — small contribution, meaningful only in combination.
# MODERATE       — non-trivial signal (e.g. ABNORMAL parent-child).
# STRONG         — high-signal (e.g. named phishing chain), still not
#                                 a verdict by itself.
SignalStrength = Literal[
    "OBSERVED", "INFORMATIONAL", "WEAK", "MODERATE", "STRONG",
]

# Numeric weights for the deterministic aggregate score.  These are
# INTENTIONALLY conservative — a naked LOLBIN produces 0 weight; even
# a full Squiblydoo chain aggregates to only ~7.  A verdict requires
# the Correlation + Verdict engines to combine multi-source evidence.
STRENGTH_WEIGHT: dict[str, int] = {
    "OBSERVED":      0,
    "INFORMATIONAL": 0,
    "WEAK":          1,
    "MODERATE":      3,
    "STRONG":        5,
}

# ── Disposition ladder ───────────────────────────────────────────
# NivXRay's evidence layers use this ladder — but a Verdict never
# emerges from evidence alone; the Verdict Engine owns that.
Disposition = Literal[
    "OBSERVED",
    "OBSERVED_WITH_SIGNAL",
    "CONTEXTUALIZED",
    "CORRELATION_CANDIDATE",
]


def compute_disposition(aggregate_score: int) -> Disposition:
    if aggregate_score >= 12: return "CORRELATION_CANDIDATE"
    if aggregate_score >= 6:  return "CONTEXTUALIZED"
    if aggregate_score >= 2:  return "OBSERVED_WITH_SIGNAL"
    return "OBSERVED"


# ── Standard contract clause ─────────────────────────────────────
CONTRACT_PRINCIPLE = (
    "Living-off-the-land binary is a CAPABILITY, not a verdict.  "
    "IOC / MITRE / Sigma / parent-child / regex matches are EVIDENCE.  "
    "Only the Correlation + Verdict engines produce a verdict — "
    "NivXRay never escalates a single primitive to MALICIOUS."
)
CONTRACT_NOTE = (
    "Every hit is EVIDENCE.  The correlation engine combines evidence "
    "from multiple sources (IOC, network, file, identity, temporal, "
    "negative evidence) before the Verdict Engine determines the outcome."
)


def contract_block() -> dict:
    """Standard `contract` block to attach to any evidence response."""
    return {"principle": CONTRACT_PRINCIPLE, "note": CONTRACT_NOTE}
