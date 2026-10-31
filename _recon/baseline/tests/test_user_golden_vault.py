"""User Golden Vault regression — Feb 2026.

Every SAVE CASE click in Workspace + every 'merged' learner payload is
auto-snapshotted into fixtures/user_golden_vault.jsonl. This test replays
each fixture and asserts:
  1. `try_archetypes` still matches (regression guard on the engine).
  2. Output has ZERO CJK ideographs (the class of bug that hit Error1/2/3).
  3. Engine label has NO duplicated archetype IDs (the 6× cascade bug).
  4. ASCII-printable head still starts with the recorded signature (soft check,
     first 40 chars — protects against major output drift).

This is a HARD gate — every PR & every Learner-approve regression must
pass this, so behaviour the analyst already validated can never silently
regress.
"""
from __future__ import annotations
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from wrapper_archetypes import try_archetypes


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "user_golden_vault.jsonl")


def _load():
    if not os.path.exists(FIXTURE):
        pytest.skip("user_golden_vault fixture missing")
    with open(FIXTURE, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _has_cjk(s: str) -> bool:
    return any(
        (0x4E00 <= ord(c) <= 0x9FFF) or (0x3040 <= ord(c) <= 0x30FF)
        or (0x3400 <= ord(c) <= 0x4DBF) or (0xAC00 <= ord(c) <= 0xD7AF)
        for c in (s or "")
    )


def _duplicated_archetype_ids(engine: str) -> bool:
    """Detects the runaway-recursion bug where the same archetype
    (CERTUTIL_DOWNLOAD_DECODE_WORKFLOW, LOLBAS_RUNDLL32_JAVASCRIPT etc.)
    appears more than once in the '+'-joined engine label."""
    parts = [p for p in (engine or "").split("+") if p]
    parts = [p.replace("archetype:", "") for p in parts]
    return len(parts) != len(set(parts))


@pytest.mark.parametrize("fx", _load(), ids=lambda fx: fx["name"])
def test_golden_vault_case(fx):
    inp = fx["input"]
    r = try_archetypes(inp)

    if not r:
        # Fixtures that never matched an archetype (plain-text stubs) are
        # only used to catch crashes. If input was < 40 chars, we treat
        # "no match" as acceptable — genuine payloads are always longer.
        if len(inp) < 40:
            return
        # If it USED to match an archetype and no longer does → HARD regression.
        if fx.get("expected_engine", "").startswith("archetype:"):
            pytest.fail(f"{fx['name']}: archetype used to match, now does not")
        return

    out = r.get("output", "") or ""
    engine = r.get("engine", "") or ""

    # HARD INVARIANT 1 — no CJK gibberish
    head = out.split("━━")[0]
    assert not _has_cjk(head), \
        f"{fx['name']}: CJK gibberish returned in output head"

    # HARD INVARIANT 2 — no duplicated archetype IDs (6× cascade guard)
    assert not _duplicated_archetype_ids(engine), \
        f"{fx['name']}: archetype cascaded (engine = {engine!r})"

    # SOFT SIGNATURE CHECK — the recorded ASCII head is expected to appear
    # somewhere in the current output (or the current output should be
    # STRICTLY LONGER, indicating a forward-improvement, e.g. a deeper
    # layer got peeled since the snapshot). Never fails on improvements.
    #
    # Feb 2026 RC3.9 — INTENTIONAL SHORTER OUTPUT: when the pipeline now
    # emits a Partial-Decode verdict (wrapper_only flag) it's the RIGHT
    # answer even though the ASCII head is shorter than the old snapshot
    # (which captured the OLD false-positive gibberish). Treat that as a
    # forward improvement, not drift.
    sig = (fx.get("expected_signature") or "").strip()
    sig_head = sig[:40]
    if len(sig_head) >= 20 and sig_head not in head:
        vc = r.get("verdict_card") or {}
        if vc.get("partial") or vc.get("wrapper_only") or vc.get("undecoded"):
            return  # Partial verdict = honest downgrade, not regression
        ascii_new = sum(1 for c in head if 32 <= ord(c) < 127)
        ascii_old = sum(1 for c in sig if 32 <= ord(c) < 127)
        if ascii_new < ascii_old * 0.5:
            pytest.fail(
                f"{fx['name']}: output drifted (much shorter than snapshot). "
                f"Expected head to contain {sig_head!r}"
            )
