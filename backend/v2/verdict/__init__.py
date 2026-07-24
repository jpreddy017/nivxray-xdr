"""v2/verdict — deterministic scoring engine (v3).

Public API:
    from v2.verdict import score, Verdict
    v = score(frame_dict, ctx={"file_writes_60s": 47, "entropy_jump": 0.85})
    v.score   # 0..100
    v.band    # benign|informational|low|suspicious|malicious|critical
    v.breakdown  # audit trail

Multi-event correlation (v3.1):
    from v2.verdict.correlation import correlate
    report = correlate(irg_enriched_frames, case_id="case_xyz")
    report.processes / .chains / .device / .incident
"""
from .engine import score, Verdict, SignalHit
from .weights import WEIGHTS, DECAY_WEIGHTS, FAMILY_CAPS, BANDS, band_of
from .correlation import correlate, CorrelationReport, AggregateVerdict

__all__ = ["score", "Verdict", "SignalHit",
           "WEIGHTS", "DECAY_WEIGHTS", "FAMILY_CAPS", "BANDS", "band_of",
           "correlate", "CorrelationReport", "AggregateVerdict"]
