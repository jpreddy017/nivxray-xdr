"""Regression tests for the P2 side-by-side GRAPH + CHAIN pair figure.

Guards `_pair_graph_chain_by_step` behaviour and confirms the paired
figure lands in the PDF flowables when both files exist.
"""
from __future__ import annotations

from pathlib import Path

import pytest


def test_pair_detection_returns_complete_pairs_only(tmp_path):
    from docs.pdf_generator import _pair_graph_chain_by_step

    # Simulate 2 payloads: one with graph+chain, one with only graph.
    files = [
        tmp_path / "step_1_a.png",
        tmp_path / "step_1_tab_graph.png",
        tmp_path / "step_1_tab_chain.png",
        tmp_path / "step_1_tab_mitre.png",
        tmp_path / "step_2_tab_graph.png",  # no chain sibling
    ]
    for p in files:
        p.write_bytes(b"\x89PNG\r\n\x1a\n")  # PNG magic, unreadable but harmless

    pairs = _pair_graph_chain_by_step(files)
    assert set(pairs.keys()) == {"1"}
    assert pairs["1"]["graph"].name == "step_1_tab_graph.png"
    assert pairs["1"]["chain"].name == "step_1_tab_chain.png"


def test_pair_detection_ignores_non_matching_names(tmp_path):
    from docs.pdf_generator import _pair_graph_chain_by_step
    files = [
        tmp_path / "step_1.png",              # bare step, no tab
        tmp_path / "cover.png",               # unrelated
        tmp_path / "step_1_tab_iocs.png",     # not graph/chain
    ]
    for p in files:
        p.write_bytes(b"\x89PNG\r\n\x1a\n")
    assert _pair_graph_chain_by_step(files) == {}


def test_pdf_generator_runs_when_pairs_exist():
    """A real payload with graph+chain shots should generate cleanly and
    produce a non-trivial PDF (the pair-figure code path is exercised).
    """
    from docs.pdf_generator import create_user_guide, _SCREENSHOTS_DIR

    have_pair = False
    for d in _SCREENSHOTS_DIR.iterdir():
        if not d.is_dir():
            continue
        names = {p.name for p in d.glob("step_*_tab_*.png")}
        if any("tab_graph.png" in n for n in names) and \
           any("tab_chain.png" in n for n in names):
            have_pair = True
            break
    if not have_pair:
        pytest.skip("no docs corpus with graph+chain pair — nothing to verify")

    data = create_user_guide("all")
    assert data[:4] == b"%PDF"
    # A doc with paired figures + all other assets should be well over
    # 200 KB (real corpus is multi-MB).
    assert len(data) > 200_000


def test_embed_screenshots_returns_pair_table(tmp_path, monkeypatch):
    """Directly call `_embed_screenshots` with a fake dir containing a
    graph+chain pair — the returned flowable list must include a Table
    (the side-by-side figure)."""
    from docs import pdf_generator
    from reportlab.platypus import Table

    fake_dir = tmp_path / "docs" / "screenshots" / "fake_payload"
    fake_dir.mkdir(parents=True)

    # Create tiny valid PNGs via PIL for RLImage to load.
    from PIL import Image
    for name in ("step_1_tab_graph.png", "step_1_tab_chain.png",
                 "step_1_a.png"):
        Image.new("RGB", (200, 100), (15, 118, 110)).save(fake_dir / name)

    monkeypatch.setattr(pdf_generator, "_SCREENSHOTS_DIR",
                        tmp_path / "docs" / "screenshots")
    from docs.pdf_generator import _embed_screenshots, _styles
    flowables = _embed_screenshots("fake_payload", _styles())
    tables = [f for f in flowables if isinstance(f, Table)]
    assert len(tables) == 1, "expected exactly one side-by-side pair Table"
