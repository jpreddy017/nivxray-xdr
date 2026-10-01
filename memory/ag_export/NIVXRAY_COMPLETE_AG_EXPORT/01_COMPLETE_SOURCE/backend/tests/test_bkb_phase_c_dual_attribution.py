"""
P0.16 · Phase C · Dual-Attribution & Feature-Flag tests

Verifies that:
    · `_build_behavior_clusters` emits both `canonical_mitre` and
      `observed_mitre` on every cluster.
    · When ``NVX_BKB_CANONICAL=0`` (default / production), every
      cluster's `mitre` field is byte-identical to the legacy
      observed set — Workspace behaviour is preserved.
    · When ``NVX_BKB_CANONICAL=1`` (preview), `mitre` is the
      canonical BKB projection — the contamination bug the user
      reported is eliminated.
    · Unknown labels (no BKB entry) fall back to the observed
      attribution regardless of flag state.
"""
from __future__ import annotations

import pytest

from services.ice.correlate import _build_behavior_clusters


def _cmd(purpose, text="x"):
    return {"purpose": purpose, "command": text}


def _inv(techs):
    return {"techniques": [{"id": t, "name": t} for t in techs]}


# ══════════════════════════════════════════════════════════════════
# Both attribution paths present on every cluster
# ══════════════════════════════════════════════════════════════════
def test_dual_attribution_fields_emitted_on_every_cluster(monkeypatch):
    monkeypatch.delenv("NVX_BKB_CANONICAL", raising=False)
    clusters = _build_behavior_clusters(
        commands       = [_cmd("Registry modification"),
                              _cmd("Scheduled Task create")],
        investigations = [_inv(["T1112", "T1053.005"]),
                              _inv(["T1053.005"])],
    )
    for c in clusters:
        assert "canonical_mitre"    in c
        assert "observed_mitre"     in c
        assert "attribution_source" in c


# ══════════════════════════════════════════════════════════════════
# Flag OFF → legacy behaviour preserved byte-identically
# ══════════════════════════════════════════════════════════════════
def test_flag_off_yields_legacy_observed_attribution(monkeypatch):
    monkeypatch.delenv("NVX_BKB_CANONICAL", raising=False)
    clusters = _build_behavior_clusters(
        commands       = [_cmd("Registry modification"),
                              _cmd("Scheduled Task create")],
        investigations = [_inv(["T1112", "T1053.005"]),
                              _inv(["T1053.005"])],
    )
    reg  = next(c for c in clusters if c["label"] == "Registry modification")
    sch  = next(c for c in clusters if c["label"] == "Scheduled Task create")
    # Legacy shape — Registry-mod cluster is CONTAMINATED by
    # T1053.005 (this is what production currently shows).  The
    # test locks the legacy behaviour so we can prove flag=OFF
    # regressed nothing.
    assert reg["attribution_source"] == "observed"
    reg_ids = {m["id"] for m in reg["mitre"]}
    assert "T1112"     in reg_ids
    assert "T1053.005" in reg_ids     # contamination · legacy behavior
    # Same for the scheduled task cluster.
    assert sch["mitre"][0]["id"] == "T1053.005"


# ══════════════════════════════════════════════════════════════════
# Flag ON → canonical BKB projection · contamination gone
# ══════════════════════════════════════════════════════════════════
def test_flag_on_yields_canonical_bkb_attribution(monkeypatch):
    monkeypatch.setenv("NVX_BKB_CANONICAL", "1")
    clusters = _build_behavior_clusters(
        commands       = [_cmd("Registry modification"),
                              _cmd("Scheduled Task create")],
        investigations = [_inv(["T1112", "T1053.005"]),
                              _inv(["T1053.005"])],
    )
    reg = next(c for c in clusters if c["label"] == "Registry modification")
    sch = next(c for c in clusters if c["label"] == "Scheduled Task create")

    assert reg["attribution_source"] == "bkb"
    assert {m["id"] for m in reg["mitre"]} == {"T1112"}          # clean
    assert {m["id"] for m in sch["mitre"]} == {"T1053.005"}      # clean

    # Diagnostic evidence is preserved — the observed set still
    # carries the DIE noise for analyst inspection.
    assert "T1053.005" in {m["id"] for m in reg["observed_mitre"]}


# ══════════════════════════════════════════════════════════════════
# Unknown labels fall back to observed regardless of flag
# ══════════════════════════════════════════════════════════════════
def test_unknown_label_falls_back_to_observed_under_bkb_flag(monkeypatch):
    monkeypatch.setenv("NVX_BKB_CANONICAL", "1")
    clusters = _build_behavior_clusters(
        commands       = [_cmd("Command execution")],
        investigations = [_inv(["T1059.003"])],
    )
    c = clusters[0]
    # BKB has no entry → attribution_source stays "observed".
    assert c["attribution_source"] == "observed"
    assert c["canonical_mitre"]    == []
    assert {m["id"] for m in c["mitre"]} == {"T1059.003"}


# ══════════════════════════════════════════════════════════════════
# Panels project from the SAME cluster.mitre when flag is on —
# a lightweight simulation of Attack-Chain / Summary agreement.
# ══════════════════════════════════════════════════════════════════
def test_all_projections_agree_when_reading_cluster_mitre(monkeypatch):
    monkeypatch.setenv("NVX_BKB_CANONICAL", "1")
    clusters = _build_behavior_clusters(
        commands       = [_cmd("PowerShell execution"),
                              _cmd("Current-user discovery"),
                              _cmd("Certutil download / decode")],
        investigations = [_inv([])] * 3,
    )
    chain   = set()
    summary = set()
    for c in clusters:
        for m in c["mitre"]:
            chain.add(m["id"])
            summary.add(m["id"])
    assert chain == summary
    assert "T1059.001" in chain
    assert "T1033"     in chain
    assert "T1105"     in chain
