"""Auto-Archetype Learner engine tests — Feb 2026.

Deterministic unit tests around feature extraction, similarity, clustering,
proposal generation, confidence breakdown, and staging file writer.
"""
from __future__ import annotations
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import learner_engine as eng


# ─── Feature extraction ─────────────────────────────────────────────────

def test_extract_features_empty():
    f = eng.extract_features("")
    assert f["length"] == 0 and f["charset"] == "empty"


def test_extract_features_base64_like():
    payload = "aGVsbG8gd29ybGQhIHRoaXMgaXMgYSB0ZXN0IHBheWxvYWQ="
    f = eng.extract_features(payload)
    assert f["length"] == len(payload)
    assert f["charset"] == "base64"
    assert f["b64_ratio"] > 0.9
    assert 3.0 < f["entropy"] < 7.0
    assert f["length_band"] in ("small", "medium")


def test_extract_features_hex_and_lolbas():
    payload = "powershell -Command '4142434445464748494A4B4C'"
    f = eng.extract_features(payload)
    assert f["has_lolbas"] is True
    assert "powershell" in f["lolbas_tokens"]


def test_extract_features_escapes():
    payload = "http://x/y?a=%20b\\x41\\x42\\u0041&#65;"
    f = eng.extract_features(payload)
    assert f["has_percent_esc"] is True
    assert f["has_backslash_x"] is True
    assert f["has_unicode_esc"] is True
    assert f["has_html_entity"] is True


# ─── Similarity + cluster key ───────────────────────────────────────────

def test_similarity_identical_features_scores_high():
    p = "aGVsbG8gd29ybGQhIHRoaXMgaXMgYSB0ZXN0IHBheWxvYWQ="
    f1 = eng.extract_features(p)
    f2 = eng.extract_features(p)
    assert eng.similarity(f1, f2) >= 80


def test_similarity_different_charsets_scores_low():
    f1 = eng.extract_features("powershell -EncodedCommand VABlAHMAdAA=")
    f2 = eng.extract_features("4142434445464748")
    assert eng.similarity(f1, f2) < 60


def test_cluster_key_groups_similar():
    p1 = "aGVsbG8gd29ybGQhIHRoaXMgaXMgYSB0ZXN0IHBheWxvYWQ="
    p2 = "cGVsbG8gd29ybGQhIHRoaXMgaXMgYSB0ZXN0IHBheWxvYWQ="
    k1 = eng.cluster_key(eng.extract_features(p1))
    k2 = eng.cluster_key(eng.extract_features(p2))
    assert k1 == k2


# ─── Proposal generation ────────────────────────────────────────────────

def test_propose_archetype_returns_expected_shape():
    prop = eng.propose_archetype(
        "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAaGVsbG8n",
        "Write-Host 'hello'"
    )
    assert set(prop.keys()) >= {
        "archetype_id", "features", "cluster_key", "wrapper_regex",
        "decode_chain", "confidence", "confidence_breakdown",
        "why", "why_not", "code",
    }
    assert prop["confidence"] == prop["confidence_breakdown"]["total"]
    # LOLBAS + base64 → decode chain should include base64 & lolbas-annotate
    assert "base64-decode" in prop["decode_chain"]
    assert "lolbas-annotate" in prop["decode_chain"]
    assert prop["confidence"] >= 40
    # code block should reference the archetype id
    assert prop["archetype_id"] in prop["code"]


def test_propose_low_confidence_explains_why_not():
    prop = eng.propose_archetype("hello world", "hello world")
    assert prop["confidence"] < 80
    assert isinstance(prop["why_not"]["missing"], list)


def test_confidence_breakdown_sums_to_total():
    prop = eng.propose_archetype(
        "%68%65%6c%6c%6f%20%77%6f%72%6c%64", "hello world"
    )
    b = prop["confidence_breakdown"]
    assert b["total"] == b["regex"] + b["entropy"] + b["charsets"] \
                        + b["decode_path"] + b["corpus_match"]
    assert 0 <= b["total"] <= 100


# ─── Staging writer & rollback ──────────────────────────────────────────

def test_append_and_remove_from_staging(monkeypatch, tmp_path):
    fake = tmp_path / "wrapper_archetypes_learned.py"
    fake.write_text("from typing import Any, Dict, List\n"
                    "LEARNED_ARCHETYPES: List[Dict[str, Any]] = []\n")
    monkeypatch.setattr(eng, "_STAGING", str(fake))

    code = "# ─── LEARNED · LEARNED_FOO ─────────────────────────────────\nprint('foo')"
    r = eng.append_to_staging(code)
    assert r["ok"] and not r.get("skipped")
    # idempotent
    r2 = eng.append_to_staging(code)
    assert r2.get("skipped")
    # rollback
    r3 = eng.remove_from_staging("LEARNED_FOO")
    assert r3["ok"]
    assert "LEARNED_FOO" not in fake.read_text()


# ─── Regression harness smoke ───────────────────────────────────────────

def test_run_regression_returns_dict():
    # This is a smoke test — we don't assert ok==True because on some CI
    # environments the NXGEC fixture may be skipped. We just verify the
    # returned shape is correct.
    r = eng.run_regression(timeout_sec=180)
    assert isinstance(r, dict)
    assert "ok" in r and "passed" in r and "failed" in r and "log_tail" in r
