"""
DKP · Decoder Knowledge Pack
────────────────────────────
Owner-locked 2026-02-16 · Phase B.2.

Every decoder output flows through DKP.  The knowledge pack turns a
raw AST envelope into an enriched semantic explanation without
changing the engine.  Purely deterministic — no LLM, no network.

Contract:
    match(envelope)     → List[MatchedPattern]
    load_patterns()     → List[Pattern]
    pattern_by_id(id)   → Optional[Pattern]

A ``MatchedPattern`` carries:
    { pattern, matched_signatures, confidence, evidence }

Consumers (Analyst Narrative Generator · CEM enricher ·
Investigation Engine) never care whether a match came from a regex,
a MITRE hit, or a LOLBAS lookup — only that the pattern fired.
"""
from .models import Pattern, Signature, MatchedPattern
from .engine import match, pattern_by_id, load_patterns, add_pattern
from .seed_patterns import SEED_PATTERNS

__all__ = [
    "Pattern",
    "Signature",
    "MatchedPattern",
    "match",
    "pattern_by_id",
    "load_patterns",
    "add_pattern",
    "SEED_PATTERNS",
]
