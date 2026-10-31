"""v1.4.2 · literal-escape normalisation regression.

Analyst pastes and SIEM tickets frequently deliver payloads with
LITERAL ``\\n`` / ``\\t`` / ``\\r`` escape sequences instead of real
newlines. The intent rules must normalise these so word-boundary
regexes match the real tokens (``Enable-PSRemoting``) instead of the
glued ``nEnable-PSRemoting`` produced by leaving the backslash-n
in place.
"""
from __future__ import annotations

from v2.investigation.pipeline import investigate


# The exact SME sample from the 2026-07-28 screenshot — every newline
# is delivered as a literal ``\n`` two-character sequence.
_LITERAL_ESCAPE_SAMPLE = (
    r'E:\Installs\PSTools\PsExec.exe \\10.253.34.27 -u .\mativadmin '
    r'-p BlackCloud@53 -h powershell -Command '
    r'\nEnable-PSRemoting -Force -SkipNetworkProfileCheck'
    r'\n\nSet-Service WinRM -StartupType Automatic\nStart-Service WinRM'
    r'\n\nEnable-NetFirewallRule -DisplayGroup Windows Remote Management'
    r'\nEnable-NetFirewallRule -DisplayGroup File and Printer Sharing'
)


def test_literal_escape_sample_produces_full_verdict():
    r = investigate(_LITERAL_ESCAPE_SAMPLE)
    assert r.verdict.band.value == "malicious", (
        f"literal-\\n escape sample must produce MALICIOUS "
        f"(got {r.verdict.band.value})"
    )
    categories = {i.category.value for i in r.intent.intents}
    assert "lateral_movement" in categories, (
        "PSRemoting + WinRM enablement must fire lateral_movement even "
        "when newlines arrive as literal \\n sequences"
    )
    assert "defense_evasion" in categories, (
        "Enable-NetFirewallRule must fire defense_evasion even when "
        "newlines arrive as literal \\n sequences"
    )
    kinds = set(r.behavior.kinds())
    assert kinds == {"lateral_movement", "defense_evasion"}, (
        f"expected [lateral_movement, defense_evasion], got {sorted(kinds)}"
    )


def test_literal_escape_and_real_newlines_produce_identical_verdicts():
    """Determinism check — the same payload with real newlines vs
    literal ``\\n`` must produce byte-identical verdict + behaviour."""
    real_newlines = _LITERAL_ESCAPE_SAMPLE.replace("\\n", "\n")
    r1 = investigate(_LITERAL_ESCAPE_SAMPLE)
    r2 = investigate(real_newlines)
    assert r1.verdict.band == r2.verdict.band
    assert r1.verdict.confidence == r2.verdict.confidence
    assert set(r1.behavior.kinds()) == set(r2.behavior.kinds())
    assert {m.id for m in r1.report.mitre} == {m.id for m in r2.report.mitre}


def test_reasoning_surfaces_dual_use_ambiguity_on_literal_escape():
    """Even with literal ``\\n`` normalisation, the dual-use ambiguity
    caveat must still appear so analysts see the honesty statement."""
    r = investigate(_LITERAL_ESCAPE_SAMPLE)
    ambiguity = r.verdict.reasoning.get("ambiguity", "").lower()
    assert "dual-use" in ambiguity or "legitimate" in ambiguity, (
        "dual-use ambiguity caveat must survive literal-escape normalisation"
    )
