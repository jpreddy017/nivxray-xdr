"""User-reported payload regression harness.

Runs every JSON fixture under ``backend/tests/user_reported_corpus/``
through the shared Canonical Evidence Recovery service and asserts:

1. ``terminal_state`` matches the fixture's ``expected_terminal_state``.
2. ``confidence`` ≥ ``min_confidence``.
3. ``decoded_output`` matches ``expected_decoded_output`` when
   specified (exact match).
4. Every id in ``expected_chain_contains`` appears in the
   canonical chain.

CI runs this file on every commit. Adding a new user-reported
payload = adding ONE JSON file to the corpus directory. No code.

See Governance Rule 21 · Two-Track Investment.
"""
from __future__ import annotations
import glob
import json
import os
from pathlib import Path

import pytest

from services.canonical_evidence_recovery import recover_canonical_evidence


CORPUS_DIR = Path(__file__).parent / "user_reported_corpus"


def _load_corpus():
    paths = sorted(glob.glob(str(CORPUS_DIR / "*.json")))
    corpus = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            fx = json.load(f)
        fx["_path"] = p
        corpus.append(fx)
    return corpus


CORPUS = _load_corpus()


def _ids(param):
    return f"{param['id']}·{param['label'][:40]}"


@pytest.mark.parametrize("fx", CORPUS, ids=_ids)
def test_user_reported_payload_recovers_as_expected(fx):
    """Every reported payload MUST continue to decode correctly.

    Any regression fails CI. Fixture format:
      { "id": "PNN",
        "label": "…",
        "input": "…",
        "expected_terminal_state": "recovered",
        "expected_decoded_output": "…",          (optional)
        "min_confidence": 50,
        "expected_chain_contains": ["op-name", …] }
    """
    art = recover_canonical_evidence(fx["input"])
    # 1) terminal_state
    exp_term = fx.get("expected_terminal_state")
    if exp_term:
        assert art.terminal_state == exp_term, (
            f"[{fx['id']}] terminal_state expected {exp_term!r}, got "
            f"{art.terminal_state!r}. decoded={art.decoded_output!r}"
        )
    # 2) min_confidence (only when the artifact reports one)
    min_conf = fx.get("min_confidence")
    if min_conf is not None and art.confidence is not None:
        assert art.confidence >= min_conf, (
            f"[{fx['id']}] confidence {art.confidence} < min {min_conf}"
        )
    # 3) exact decoded_output when specified
    exp_dec = fx.get("expected_decoded_output")
    if exp_dec is not None:
        assert art.decoded_output == exp_dec, (
            f"[{fx['id']}] decoded_output mismatch\n"
            f"  expected: {exp_dec!r}\n"
            f"  got     : {art.decoded_output!r}"
        )
    # 4) chain-ids substring contract
    exp_chain = fx.get("expected_chain_contains") or []
    for op in exp_chain:
        assert op in (art.chain_ids or []), (
            f"[{fx['id']}] expected op {op!r} in chain_ids, got "
            f"{art.chain_ids!r}"
        )


def test_user_reported_corpus_is_non_empty():
    """Guard against the corpus directory being accidentally emptied."""
    assert len(CORPUS) >= 4, (
        f"user_reported_corpus should have at least 4 fixtures; "
        f"found {len(CORPUS)}"
    )
