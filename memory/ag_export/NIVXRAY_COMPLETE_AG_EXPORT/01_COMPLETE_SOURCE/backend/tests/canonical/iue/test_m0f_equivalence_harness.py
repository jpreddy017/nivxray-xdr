"""Equivalence Harness runner (ADR-0014e).

Runs the read-only harness across all 4 M0a corpus inputs and writes a
structured report to `/app/memory/equivalence_report_m0a.json`.

This test does NOT assert equivalence — that is a decision for owner
review.  It only asserts that:
  1. The harness executed successfully across all 4 inputs.
  2. The report was written to disk.
  3. The M0a IUE envelope hashes remain byte-identical (guardrail).
  4. SystemWeakness projection still contains no `url.acquire.v1`.
  5. Legacy path itself is stable (byte-identical across 2 replays).

Owner reviews `equivalence_report_m0a.json` to make the M0f decision.
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.iue.harness.equivalence_harness import (   # noqa: E402
    EXTENDED_CORPUS,
    M0A_CORPUS,
    run_equivalence_harness,
    run_legacy,
)
from services.die.input_understanding import understand           # noqa: E402
from services.registry.iue_projection import plan_to_execution_steps  # noqa: E402


_REPORT_PATH = Path("/app/memory/equivalence_report_m0a.json")
_EXTENDED_REPORT_PATH = Path("/app/memory/equivalence_report_extended.json")


def test_harness_runs_and_writes_report():
    result = run_equivalence_harness()
    assert "records" in result and len(result["records"]) == 4
    assert "overall_verdict" in result
    assert result["overall_verdict"] in ("GO", "NO-GO", "GAPS-REQUIRE-MIGRATION")
    _REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _REPORT_PATH.write_text(json.dumps(result, indent=2, default=str,
                                        sort_keys=True) + "\n")
    assert _REPORT_PATH.exists()
    assert _REPORT_PATH.stat().st_size > 0


def test_harness_runs_extended_corpus():
    """Owner note (2026-02-15): 'You can take different payloads and test
    not only sample1.'  Extended-corpus run does NOT re-lock hashes —
    it is exploratory equivalence evidence written to a separate file
    for owner review."""
    result = run_equivalence_harness(EXTENDED_CORPUS)
    assert len(result["records"]) == len(EXTENDED_CORPUS)
    assert result["overall_verdict"] in ("GO", "NO-GO", "GAPS-REQUIRE-MIGRATION")
    _EXTENDED_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _EXTENDED_REPORT_PATH.write_text(
        json.dumps(result, indent=2, default=str, sort_keys=True) + "\n")
    # Additional per-input sanity: for every record, if BOTH legacy and
    # router produced a die.command.v1 envelope, they MUST be byte-identical.
    # This is the core equivalence claim, and it should hold for every
    # sync payload — not just the M0a fixtures.
    for r in result["records"]:
        legacy_hash = r["legacy"]["envelope_hash"]
        # Find the router's die.command.v1 result hash if present.
        router_die_hash = None
        for o in r["router"]["outcomes"]:
            if o["entry_id"] == "die.command.v1" and o["status"] == "success":
                router_die_hash = o["result_hash"]
                break
        if router_die_hash is not None:
            assert legacy_hash == router_die_hash, (
                f"[{r['input']['name']}] router-dispatched die.command.v1 "
                f"envelope DIFFERS from inline invocation.\n"
                f"  legacy: {legacy_hash}\n"
                f"  router: {router_die_hash}\n"
                "This would be a novel equivalence failure — investigate.")


def test_m0a_iue_envelope_hashes_unchanged_by_harness():
    """The harness must NOT mutate IUE state.  Locked by hash re-check
    against the M0a baseline."""
    expected = {
        "bare_url_medium_style": "febd68f13aab444b8018ee91dd0d97e0bd04b407d565aedffd9fef6038f93a00",
        "powershell_naked":      "92b9c1cf9c6ac52c6600fa6b3d12660a2a6641d89f3cc765d2cd350e6d1af56b",
        "plain_english_short":   "35aa379db9d4b99e5587825657092843d4ae775553ad5b0ebdbd528a29dd329b",
        "hex_ratio_long":        "7061f38454cd08a06cb092d6827779f30500d87abd57114caf31ebd4e1b97aad",
    }
    for name, text in M0A_CORPUS.items():
        u = understand(text, execute=False)
        h = hashlib.sha256(
            json.dumps(asdict(u), default=str, sort_keys=True).encode()).hexdigest()
        assert h == expected[name]


def test_systemweakness_projection_still_lacks_url_acquire_v1():
    """The harness must NOT slip in a URL Acquisition step for
    SystemWeakness.  That fix is IUE-side migration, still LOCKED."""
    u = understand("https://systemweakness.com/some-report", execute=False)
    proj = plan_to_execution_steps(u)
    entry_ids = [s.entry_id for s in proj.steps]
    assert "url.acquire.v1" not in entry_ids, (
        f"SystemWeakness scope-creep — url.acquire.v1 appeared in "
        f"projection: {entry_ids}. Fix is M0h/M1/M4, LOCKED.")


def test_legacy_path_is_deterministic():
    """Precondition for equivalence: legacy path must itself be
    byte-identical across two replays for the same input.
    (If legacy is non-deterministic, no cutover comparison is meaningful.)"""
    for name, text in M0A_CORPUS.items():
        r1 = run_legacy(text)
        r2 = run_legacy(text)
        assert r1["envelope_hash"] == r2["envelope_hash"], (
            f"Legacy envelope non-deterministic for {name!r}")
        assert r1["report_hash"] == r2["report_hash"], (
            f"Legacy report non-deterministic for {name!r}")


def test_harness_never_modifies_production_files():
    """Grep-lock: the harness module has no disk-write calls against any
    production path.  Only /app/memory/ report writes are done from
    THIS test file, never from the harness module itself."""
    src = (Path(__file__).parent / "harness" / "equivalence_harness.py").read_text()
    # The check targets Python-level disk writes.  We deliberately do NOT
    # search for the substring `.write(` because the extended-corpus
    # payload strings contain literal `document.write()` fragments.
    assert ".write_text(" not in src
    assert "Path(" not in src
    # Python `open()` calls with mode `w` / `a` / `x` are the only real
    # write vectors — guard those explicitly.
    import re as _re
    write_open = _re.search(r"open\s*\([^)]*['\"][wax]", src)
    assert write_open is None, f"harness contains a write-mode open: {write_open.group()!r}"
