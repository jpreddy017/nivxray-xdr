"""T1.5 · Tie-breaking test.

When two sub-classifiers emit conflicting primary_type, the composer's
deterministic tie-breaker rule applies identically across replays.

Rule (see composer.py::_TIE_BREAK_ORDER):
    1. highest confidence wins
    2. on confidence tie: bytes_magic > text_structure > language_multi_artefact
"""
from canonical.iue import classify, RawInput
from canonical.iue.composer import _pick_primary, _TIE_BREAK_ORDER


def test_pick_primary_prefers_higher_confidence():
    """If bytes_magic conf=95 and text_structure conf=50, bytes wins."""
    candidates = [
        ("bytes_magic", "pe_binary", 95),
        ("text_structure", "plain_text", 50),
    ]
    assert _pick_primary(candidates) == "pe_binary"


def test_pick_primary_confidence_tie_uses_priority_order():
    """Equal confidence: bytes_magic beats text_structure beats lang."""
    candidates = [
        ("text_structure", "powershell_naked", 80),
        ("bytes_magic", "plain_text", 80),
        ("language_multi_artefact", "command_line", 80),
    ]
    # bytes_magic (priority 0) wins on tie
    assert _pick_primary(candidates) == "plain_text"


def test_pick_primary_ignores_nones():
    candidates = [
        ("bytes_magic", None, 95),
        ("text_structure", "powershell", 80),
    ]
    assert _pick_primary(candidates) == "powershell"


def test_pick_primary_empty_yields_unknown():
    assert _pick_primary([]) == "unknown"
    assert _pick_primary([("bytes_magic", None, 0)]) == "unknown"


def test_tie_break_order_covers_all_sub_classifier_sources():
    required_sources = {"bytes_magic", "text_structure",
                        "language_multi_artefact", "artefact_decomp",
                        "input_health", "intent"}
    assert required_sources.issubset(_TIE_BREAK_ORDER.keys())


def test_tie_break_priority_is_stable_across_replays():
    """Re-run the composer on a genuinely-ambiguous input; result stable."""
    ambiguous = "powershell -e SGVsbG8="  # both text_structure and lang detect this
    h0 = classify(ambiguous).determinism_hash
    for _ in range(50):
        assert classify(ambiguous).determinism_hash == h0
