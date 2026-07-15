"""NivXRay Reasoning Engine — hypothesis-driven candidate analysis.

Public entry points:
    characterize(text)          → InputProfile
    linguistic_score(text)      → float ∈ [0.0, 1.0]
    text_candidates(text)       → list[Candidate]  (ROT-N, Atbash, XOR-1, Caesar)
    reason(text, mode)          → ReasoningResult   (4-phase orchestrator)
    compute_confidence(...)     → ConfidenceBreakdown (4-dim weighted verdict)
    explain_reasoning(trace)    → human-readable why-selected / why-rejected
    arbitrate(input, cands)     → TiebreakerVerdict (LLM tiebreaker for deep mode)

This package is additive. Existing magic_decoder + analysis_core continue
to work; the reasoning engine is invoked via explicit calls from
`analysis_core.deterministic_best_decode(..., mode=...)`.
"""
from .scorer import linguistic_score, score_breakdown  # noqa: F401
from .characterize import characterize, InputProfile  # noqa: F401
from .text_candidates import text_candidates, Candidate  # noqa: F401
from .engine import reason, ReasoningResult  # noqa: F401
from .confidence_engine import compute_confidence, ConfidenceBreakdown  # noqa: F401
from .explainer import explain_reasoning, explain_chain  # noqa: F401
from .llm_tiebreaker import arbitrate, arbitrate_async, tiebreak_available, TiebreakerVerdict  # noqa: F401
from .plugin_contract import DecoderPlugin, DecoderResult, PLUGIN_REGISTRY  # noqa: F401
