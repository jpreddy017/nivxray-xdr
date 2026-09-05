"""
Regression test — Preprocessor + IUE on the permanent Talos IR fixture.

This is the P0 architectural regression asserted by the user on
2026-02-28.  Any change that breaks these assertions must fail CI.

Contract:
    · The exact analyst-provided Talos IR blog paste is stored
      verbatim in ``tests/fixtures/mixed_investigation_input/``.
    · The Preprocessor must extract structured artifacts + stages
      from the prose without help from a decoder.
    · The IUE must classify it as ``vendor_report_text`` and route
      it via the Preprocessor.
    · The DIE ``analyze()`` must NOT return a single flat Stage-0
      blob — it must emit a chain envelope with ≥ 7 steps.
    · Key command families detected: reverse-ssh-tunnel,
      shadow-copy-deletion, ad-discovery, session-discovery,
      psexec-lateral, brute-ratel, rmm-remote-access.
    · At least one inferred process edge must be present.
"""
from __future__ import annotations
from pathlib import Path

import pytest

from services.die.preprocessor import preprocess
from services.die.api import analyze
from services.die.input_understanding import understand


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "mixed_investigation_input"
    / "talos_ir_ransomware_case_study.txt"
)


@pytest.fixture(scope="module")
def talos_text() -> str:
    return FIXTURE_PATH.read_text(encoding="utf-8")


# ── Preprocessor ─────────────────────────────────────────────────
def test_preprocessor_produces_at_least_seven_stages(talos_text: str):
    pre = preprocess(talos_text)
    assert pre.stage_count() >= 7, (
        f"expected ≥ 7 stages on the Talos fixture, got {pre.stage_count()}")


def test_preprocessor_extracts_key_families(talos_text: str):
    pre = preprocess(talos_text)
    families = {s.command_family for s in pre.stages if s.command_family}
    required = {
        "reverse-ssh-tunnel",
        "shadow-copy-deletion",
        "ad-discovery",
        "session-discovery",
        "psexec-lateral",
        "brute-ratel",
        "rmm-remote-access",
    }
    missing = required - families
    assert not missing, f"missing families: {missing} (got {families})"


def test_preprocessor_infers_process_edges(talos_text: str):
    pre = preprocess(talos_text)
    assert len(pre.process_edges) >= 1, (
        f"expected ≥ 1 inferred process edge, got {len(pre.process_edges)}")
    # Every edge MUST carry a `why` and confidence.
    for e in pre.process_edges:
        assert e.why, f"edge {e.id} missing `why`"
        assert 0.0 <= e.confidence <= 1.0
        assert e.inferred is True


def test_preprocessor_no_giant_stage_zero(talos_text: str):
    pre = preprocess(talos_text)
    # No single stage may contain more than 400 characters of raw
    # excerpt — that would indicate the "flat blob" regression.
    for s in pre.stages:
        assert len(s.raw_excerpt or "") <= 400, (
            f"stage {s.index} raw_excerpt too long "
            f"({len(s.raw_excerpt or '')} chars) — possible flat-blob regression")


def test_preprocessor_artifact_provenance(talos_text: str):
    pre = preprocess(talos_text)
    for a in pre.artifacts:
        assert a.line_number >= 1
        assert a.start_offset >= 0
        assert a.end_offset >= a.start_offset
        assert a.raw_text
        assert a.normalized_text
        assert a.type
        assert a.confidence >= 0.0


# ── DIE integration ───────────────────────────────────────────────
def test_die_analyze_produces_chain_envelope(talos_text: str):
    env = analyze(talos_text)
    assert env.get("chain"), (
        "DIE should route mixed input through the chain / preprocessor path")
    chain = env["chain"]
    assert chain.get("step_count", 0) >= 7, (
        f"DIE chain envelope should have ≥ 7 steps, got {chain.get('step_count')}")


def test_die_analyze_rmm_dkp_fires(talos_text: str):
    env = analyze(talos_text)
    dkp_ids = {m["id"] for m in env.get("dkp_matches") or []}
    assert "dkp.rmm_abuse" in dkp_ids, (
        f"expected DKP RMM Abuse to fire on the Talos fixture, got {dkp_ids}")
    assert "dkp.reverse_ssh_tunnel" in dkp_ids
    assert "dkp.ad_discovery_nltest" in dkp_ids


def test_die_analyze_bundles_preprocessor(talos_text: str):
    env = analyze(talos_text)
    pre_bundle = env.get("preprocessor") or {}
    assert pre_bundle.get("stages"), "preprocessor bundle missing from envelope"
    assert pre_bundle.get("stats", {}).get("stage_count", 0) >= 7


# ── Input Understanding Engine ────────────────────────────────────
def test_iue_classifies_talos_as_vendor_report(talos_text: str):
    u = understand(talos_text, execute=False)
    assert u.input_type == "vendor_report_text", (
        f"expected input_type=vendor_report_text, got {u.input_type!r}")
    assert u.confidence >= 0.85
    assert u.decode_required is False
    assert "Preprocessor" in u.next_engine


def test_iue_execution_trace_runs_every_step(talos_text: str):
    u = understand(talos_text, execute=True)
    assert u.execution_trace, "execution_trace must be populated"
    statuses = {s.status for s in u.execution_trace}
    assert "done" in statuses, f"no step completed successfully: {statuses}"
    assert "failed" not in statuses, (
        f"execution had failures: "
        f"{[(s.id, s.detail) for s in u.execution_trace if s.status=='failed']}")


def test_iue_encoded_ps_classification():
    encoded = (
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        "-EncodedCommand "
        "UwB0AGEAcgB0ACAAIgBoAHQAdABwADoALwAvADEAMgA3AC4AMAAuADAALgAxADoA"
        "NAAwADkANgAvACIA"
    )
    u = understand(encoded, execute=False)
    assert u.input_type == "powershell_encoded"
    assert u.decode_required is True
    assert len(u.decode_layers) >= 2
    assert u.decode_layers[0].name == "Base64"
    assert u.decode_layers[1].name == "UTF-16LE"


def test_iue_bare_base64_classification():
    b64 = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgYmxvYiB0aGF0IGlzIGxvbmcgZW5vdWdoLg=="
    u = understand(b64, execute=False)
    assert u.input_type == "base64_blob"
    assert u.decode_required is True


def test_iue_plain_text_classification():
    u = understand("this is just some notes about the incident", execute=False)
    # Short single line falls into single_command or plain_text buckets.
    assert u.input_type in ("plain_text", "single_command", "unknown")
    assert u.decode_required is False
