"""Targeted validation of Command Intelligence R-1/R-2/R-3 honesty via public API.
Non-destructive: only calls POST /api/analyze/command.
"""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ENDPOINT = f"{BASE_URL}/api/analyze/command"

_SESSION = None


def _session():
    global _SESSION
    if _SESSION is not None:
        return _SESSION
    s = requests.Session()
    r = s.post(f"{BASE_URL}/api/auth/login",
               json={"email": "admin@nivxray.com", "password": "uulVDp5cCSB3Hva99s7UUAwK"},
               timeout=30)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = (r.json() or {}).get("access_token") or (r.json() or {}).get("token")
    if tok:
        s.headers.update({"Authorization": f"Bearer {tok}"})
    _SESSION = s
    return s


def _post(cmd: str):
    r = _session().post(ENDPOINT, json={"input": cmd}, timeout=30)
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    return r.json()


# --- R-1: Windows-safe tokenization ------------------------------------------
def test_windows_ps_backslashes_preserved():
    cmd = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -Command Get-Process"
    data = _post(cmd)
    ps = data.get("parsed_structure") or {}
    exe = ps.get("executable")
    assert exe and "\\" in exe, f"backslashes lost: {exe!r}"
    assert exe == r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", exe
    assert ps.get("evidence_preserved") is True
    assert ps.get("tokenizer") == "windows-argv"
    assert "shell_token_count" in ps
    assert "token_count" in ps  # deprecated mirror
    assert ps["shell_token_count"] == ps["token_count"]


# --- R-1: POSIX unchanged -----------------------------------------------------
def test_posix_bash_tokenizer_unchanged():
    data = _post("bash -c 'echo hello world'")
    ps = data.get("parsed_structure") or {}
    assert ps.get("tokenizer") == "posix-shlex", ps.get("tokenizer")


# --- R-2: Obfuscated fixture → PARTIALLY_RECOVERED ---------------------------
OBF = (
    'powershell.exe -NoProfile -Command "'
    '$a = \'aQBw\' + 9 + \'AGMAbwBuAGYAaQBnACAALwBhAGwAbAA=\'; '
    '$b = [Convert]::FromBase64String($a); '
    '[ScriptBlock]::Create($b).Invoke()"'
)


def test_obfuscated_fixture_partially_recovered():
    data = _post(OBF)
    assert data.get("decode_status") == "PARTIALLY_RECOVERED", data.get("decode_status")
    unresolved = data.get("unresolved_expressions") or []
    assert isinstance(unresolved, list) and len(unresolved) > 0
    kinds = {u.get("kind") for u in unresolved}
    expected = {"non-string-concat-operand", "unbound-variable", "dynamic-base64", "dynamic-scriptblock"}
    missing = expected - kinds
    assert not missing, f"missing unresolved kinds: {missing}. got={kinds}"
    cda = data.get("canonical_decoded_artifact") or {}
    assert cda.get("promoted") is False
    assert cda.get("text") in (None, ""), cda.get("text")
    assert isinstance(cda.get("reason"), str) and len(cda.get("reason")) > 0


# --- R-2: Clean single-layer → RECOVERED + promoted --------------------------
def test_clean_base64_recovered_and_promoted():
    data = _post("powershell.exe -enc aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAA=")
    assert data.get("decode_status") == "RECOVERED", data.get("decode_status")
    assert (data.get("unresolved_expressions") or []) == []
    cda = data.get("canonical_decoded_artifact") or {}
    assert cda.get("promoted") is True
    assert cda.get("text") == "ipconfig /all", cda.get("text")


# --- R-2: Benign command → NOT_REQUIRED --------------------------------------
def test_benign_command_not_required():
    data = _post("ipconfig /all")
    assert data.get("decode_status") == "NOT_REQUIRED", data.get("decode_status")


# --- R-2: Cosmetic casing is not recovery ------------------------------------
def test_case_only_obfuscation_not_a_recovery():
    data = _post(r"InVOkE-eXpReSsION (Get-Content C:\x.txt)")
    ast = data.get("ast_deobfuscation") or {}
    assert ast.get("applied") is False, ast
    assert ast.get("semantic_transformations", 0) == 0, ast


# --- R-3: Fragment classification --------------------------------------------
def test_concat_operand_classified_as_fragment():
    data = _post(
        "powershell.exe -enc 'aQBwAGMAbwBuAGYAaQBnACAALwBhAGwAbAAAAAAAAAAA' + 'BBBBBBBBBBBBBBBB'"
    )
    artifacts = data.get("decoded_artifacts") or data.get("artifacts") or []
    # Fall back: search anywhere in payload for artifact_class=FRAGMENT
    def _walk(o):
        if isinstance(o, dict):
            yield o
            for v in o.values():
                yield from _walk(v)
        elif isinstance(o, list):
            for v in o:
                yield from _walk(v)
    frags = [d for d in _walk(data) if d.get("artifact_class") == "FRAGMENT"]
    assert frags, f"no FRAGMENT artifact found. keys={list(data.keys())}"
    for f in frags:
        assert f.get("auto_decoded") is False, f
        assert f.get("fragment_of"), f
