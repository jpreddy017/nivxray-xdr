"""P1-09 regression lock · AutoHotkey false-positive from base64 substring.

Before the fix, `classify_command` used a bare `"ahk" in h` substring
check. When the head string contained an entire wrapped command whose
base64 payload happened to include the letters 'ahk', every such
command was mis-classified as an "AutoHotkey stager".

The fix tightened the check to `\\b(?:autohotkey|ahk)(?:\\.exe|_l)?\\b`.
This suite locks that boundary so no substring inside a base64 blob
can trigger the AHK classifier.
"""
from __future__ import annotations

from services.ida.behaviors import classify_command


def _label(cmd: str, head: str | None = None):
    """Convenience — return the label string."""
    h = (head if head is not None
             else (cmd or "").split(None, 1)[0].lower())
    lbl, _tag = classify_command(cmd, h)
    return lbl


# ── True positives (must still flag as AutoHotkey stager) ─────────
def test_true_positive_autohotkey_exe():
    assert "AutoHotkey" in _label("autohotkey.exe C:\\loader.ahk", "autohotkey.exe")


def test_true_positive_ahk_exe():
    assert "AutoHotkey" in _label("ahk.exe stager.ahk", "ahk.exe")


def test_true_positive_ahk_l():
    assert "AutoHotkey" in _label("ahk_l C:\\loader.ahk", "ahk_l")


# ── False positives (must NOT flag as AutoHotkey stager) ──────────
def test_no_false_positive_from_base64_substring():
    # Real-world example — base64 payload contains 'ahk' substring.
    b64_with_ahk = "aWFrX2JhaGtldA=="   # decodes to "iak_bahket"
    cmd = f"powershell -EncodedCommand {b64_with_ahk}"
    assert "AutoHotkey" not in _label(cmd, "powershell")


def test_no_false_positive_ahk_inside_word():
    cmd = "sahk.exe /f"     # "sahk" contains "ahk" but isn't AutoHotkey
    lbl, _ = classify_command(cmd, "sahk.exe")
    assert lbl is None or "AutoHotkey" not in lbl


def test_no_false_positive_ahk_in_domain():
    cmd = "curl https://mahkdown.example.com/x"
    lbl, _ = classify_command(cmd, "curl")
    assert lbl is None or "AutoHotkey" not in lbl


def test_no_false_positive_ahk_in_path_word():
    cmd = "C:\\shakhkey\\file.exe /run"
    lbl, _ = classify_command(cmd, "file.exe")
    assert lbl is None or "AutoHotkey" not in lbl


def test_no_false_positive_ahk_in_random_b64():
    # Long random-looking b64 with 'ahk' embedded.
    cmd = "cmd /c echo dGVzdC1haGstc3RyaW5nLWluc2lkZQ== | base64 -d"
    lbl, _ = classify_command(cmd, "cmd")
    assert lbl is None or "AutoHotkey" not in lbl
