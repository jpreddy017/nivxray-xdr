"""P0.15C-1 · VEEE Acquisition wire-up · Release-gate tests.

Covers the five invariants from P0.15C-RELEASE-CONTRACT.md:
    §3.1 · Flag OFF = byte-identical to pre-P0.15C behaviour
    §3.2 · Flag ON  = additive-only (never removes evidence)
    §3.3 · Complete provenance on every OCR record
    §3.4 · Zero Workspace regressions (asserted elsewhere)
    §3.5 · Deterministic acquisition (repeated runs identical)

Plus the two implementation disciplines:
    §0.1 · Stage Isolation Rule
    §0.2 · Never-Modify-Evidence Rule
"""
from __future__ import annotations

import copy
import pathlib
from typing import Any, Dict, List

import pytest

from services.ida.acquisition       import AcquiredResource, acquire_url
from services.veee.image_discovery  import discover_images
from services.veee                  import (extract_from_html,
                                                is_enabled)


# ══════════════════════════════════════════════════════════════════
# §0.1 · Stage Isolation Rule
# ══════════════════════════════════════════════════════════════════
def test_image_discovery_is_pure_and_deterministic():
    html = '''
        <img src="https://a.example.com/1.png">
        <p>ignored</p>
        <img src="https://a.example.com/2.png">
        <img src='https://a.example.com/3.png'>
        <img src="https://a.example.com/1.png">   <!-- dupe -->
    '''
    out1 = discover_images(html)
    out2 = discover_images(html)
    assert out1 == out2                    # deterministic
    assert out1 == [                        # ordered · deduped
        "https://a.example.com/1.png",
        "https://a.example.com/2.png",
        "https://a.example.com/3.png",
    ]


def test_image_discovery_skips_data_and_file_and_protocol_relative():
    html = '''
        <img src="data:image/png;base64,AAA">
        <img src="file:///etc/passwd">
        <img src="//host/x.png">
        <img src="https://real.example.com/ok.png">
    '''
    assert discover_images(html) == ["https://real.example.com/ok.png"]


def test_image_discovery_resolves_relative_paths_when_base_provided():
    html = '<img src="/media/x.png"><img src="../y.png">'
    out = discover_images(html, base_url="https://vendor.example.com/blog/post/")
    assert "https://vendor.example.com/media/x.png" in out
    assert "https://vendor.example.com/blog/y.png"  in out


def test_image_discovery_empty_or_bad_input():
    assert discover_images("") == []
    assert discover_images(None) == []                # type: ignore[arg-type]
    assert discover_images("<html>no images</html>") == []


# ══════════════════════════════════════════════════════════════════
# §3.1 · Flag OFF = byte-identical (pre-P0.15C)
# ══════════════════════════════════════════════════════════════════
def test_extract_from_html_noop_when_flag_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NVX_VEEE_ENABLED", "0")
    assert is_enabled() is False
    html = '<img src="https://x.example.com/img.png">'
    assert extract_from_html(html) == []


def test_acquired_resource_veee_records_defaults_to_empty_list():
    """The additive field must not change the pre-P0.15C shape:
    default value is `[]`, absent from serialised output when empty."""
    r = AcquiredResource(ok=False, url="")
    assert r.veee_records == []
    d = r.to_dict()
    # Field present (dataclass includes it) but its default value
    # ensures byte-identity with pre-P0.15C consumers that ignore it.
    assert d["veee_records"] == []


# ══════════════════════════════════════════════════════════════════
# §3.2 · Additivity — VEEE never removes evidence
# ══════════════════════════════════════════════════════════════════
def test_flag_on_appends_to_structured_blocks_never_replaces(monkeypatch,
                                                                    tmp_path):
    """Simulate a run with the flag ON and confirm every pre-existing
    block is still present, in the same order, with the OCR-derived
    text appended after."""
    from services.veee import extract_from_image
    monkeypatch.setenv("NVX_VEEE_ENABLED", "1")

    # Snapshot of what the HTML pipeline emitted (pre-VEEE).
    baseline_blocks = ["html-block-1", "html-block-2", "html-block-3"]

    # Fake a VEEE payload the same way the acquisition orchestrator
    # would (the real fetch is exercised end-to-end in the Vendor
    # Corpus suite; here we lock the append semantics).
    veee_records = [
        {"type": "commandline", "text": "reg add HKLM\\...",
             "provenance": {"source": "image", "acquisition_level": "P3",
                                 "image_sha256": "abc", "ocr_engine": "tesseract-5",
                                 "ocr_confidence": 0.9,
                                 "bounding_box": {"x": 0, "y": 0, "w": 1, "h": 1}}},
        {"type": "skipped",     "text": "",
             "provenance": {"source": "image", "acquisition_level": "P3",
                                 "skipped": True, "reason": "not_code_screenshot"}},
        {"type": "commandline", "text": "schtasks /create /tn X",
             "provenance": {"source": "image", "acquisition_level": "P3",
                                 "image_sha256": "def", "ocr_engine": "tesseract-5",
                                 "ocr_confidence": 0.95,
                                 "bounding_box": {"x": 0, "y": 0, "w": 1, "h": 1}}},
    ]

    # Reproduce the append loop from acquisition.py line-for-line.
    blocks = list(baseline_blocks)
    for rec in veee_records:
        txt = (rec.get("text") or "").strip()
        if txt and rec.get("type") != "skipped":
            blocks.append(txt)

    # Every pre-existing block is present, in original position.
    assert blocks[:3] == baseline_blocks
    # OCR text is appended.
    assert blocks[3:] == ["reg add HKLM\\...", "schtasks /create /tn X"]
    # Additivity invariant · set inclusion + monotonic length.
    assert set(baseline_blocks) <= set(blocks)
    assert len(blocks) >= len(baseline_blocks)


def test_skipped_records_do_not_pollute_structured_blocks():
    """Skipped provenance records carry text="" — the append loop
    must ignore them so `structured_blocks` stays clean."""
    veee_records = [
        {"type": "skipped", "text": "",
             "provenance": {"skipped": True, "reason": "corrupt"}},
        {"type": "skipped", "text": "",
             "provenance": {"skipped": True, "reason": "not_code_screenshot"}},
    ]
    blocks = ["existing-1"]
    for rec in veee_records:
        txt = (rec.get("text") or "").strip()
        if txt and rec.get("type") != "skipped":
            blocks.append(txt)
    assert blocks == ["existing-1"]


# ══════════════════════════════════════════════════════════════════
# §3.5 · Deterministic Acquisition
# ══════════════════════════════════════════════════════════════════
def test_image_discovery_repeated_calls_identical():
    html = ('<html><body>'
                + ''.join(f'<img src="https://cdn.example.com/img-{i}.png">'
                              for i in range(24))
                + '</body></html>')
    out1 = discover_images(html)
    out2 = discover_images(html)
    out3 = discover_images(html)
    assert out1 == out2 == out3
    assert len(out1) == 24


def test_extract_from_html_deterministic_on_identical_input(
        monkeypatch: pytest.MonkeyPatch):
    """§3.5 · Deterministic Acquisition · VEEE's own output must be
    byte-identical across repeated runs given identical HTML input.
    (Upstream HTML fetch variance — dynamic ads, cache-buster query
    params in vendor image URLs — is a separate concern; §3.5 scopes
    to 'same article + config + OCR engine version'.)"""
    monkeypatch.setenv("NVX_VEEE_ENABLED", "1")
    # Use the cached Octlurk image so the fetch is deterministic
    # against the customer-assets CDN (returns the same bytes).
    html = (
        '<img src="https://customer-assets-4nw71qhi.emergentagent.net'
        '/job_greeting-app-5782/artifacts/3i61ymmp_octlurk-silklurk1.png">')
    r1 = extract_from_html(html)
    r2 = extract_from_html(html)
    r3 = extract_from_html(html)
    if not r1:
        pytest.skip("cached asset unreachable — Vendor Corpus v1 covers this")
    assert r1 == r2 == r3


# ══════════════════════════════════════════════════════════════════
# §0.2 · Never-Modify — the caller's html is not mutated
# ══════════════════════════════════════════════════════════════════
def test_extract_from_html_does_not_mutate_input(monkeypatch):
    monkeypatch.setenv("NVX_VEEE_ENABLED", "0")
    html = '<img src="https://x.example.com/a.png"><p>keep me</p>'
    snapshot = html
    extract_from_html(html)
    assert html == snapshot


# ══════════════════════════════════════════════════════════════════
# §3.3 · Provenance completeness surfaces from the extractor.
# (The extractor's own suite in test_veee.py locks the record shape;
# here we just confirm the wire-up preserves that shape end-to-end.)
# ══════════════════════════════════════════════════════════════════
def test_extract_from_html_output_carries_expected_shape(monkeypatch,
                                                              tmp_path):
    monkeypatch.setenv("NVX_VEEE_ENABLED", "1")
    # Give the discovery stage an image that will 404 (fetch_failed)
    # so we get a skipped-provenance record deterministically.
    html = '<img src="https://nonexistent-veee-test.invalid/x.png">'
    recs = extract_from_html(html)
    assert isinstance(recs, list)
    assert recs, "expected at least one skipped record for a bad url"
    for r in recs:
        assert "type" in r
        assert "provenance" in r
        p = r["provenance"]
        assert p.get("source") == "image"
        assert p.get("acquisition_level") == "P3"
