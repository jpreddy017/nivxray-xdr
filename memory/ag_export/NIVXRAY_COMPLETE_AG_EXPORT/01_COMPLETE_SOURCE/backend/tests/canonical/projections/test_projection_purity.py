"""Phase 4 · T4.3 — Purity (P4-FW1).

Projections MUST be pure functions of AuthoritativeSSOT:
    - no I/O
    - no clock
    - no random
    - no network
    - identical input ⇒ identical output
"""
from __future__ import annotations

import inspect
import io
from pathlib import Path

import pytest

from canonical.projections import (
    project_activity,
    project_analyst_summary,
    project_attck,
    project_attack_chain,
    project_attack_story,
    project_canonical,
    project_evidence_bundle,
    project_evidence_graph_view,
    project_executive_summary,
    project_iocs,
    project_lolbas,
    project_recommendations,
    project_reports,
    project_timeline,
    project_verdict,
)

ALL_PROJECTIONS = [
    project_activity, project_analyst_summary, project_attck,
    project_attack_chain, project_attack_story, project_canonical,
    project_evidence_bundle, project_evidence_graph_view,
    project_executive_summary, project_iocs, project_lolbas,
    project_recommendations, project_reports, project_timeline,
    project_verdict,
]


PROHIBITED_TOKENS = (
    "datetime.now",
    "datetime.utcnow",
    "time.time",
    "random",
    "uuid.uuid",
    "requests.",
    "httpx.",
    "urllib.request",
    "pymongo",
    "MongoClient",
    "open(",
)


def _projections_dir() -> Path:
    return Path("/app/backend/canonical/projections")


def test_t4_3_no_forbidden_calls_in_projection_source():
    """Static check: no forbidden IO/clock/random call in projection code."""
    for py in _projections_dir().glob("*.py"):
        if py.name.startswith("_") or py.name == "__init__.py":
            continue
        text = py.read_text()
        for token in PROHIBITED_TOKENS:
            assert token not in text, (
                f"prohibited token {token!r} in {py.name} — projections "
                f"must be pure (P4-FW1)"
            )


def test_t4_3_projection_signatures_are_pure_single_arg():
    """Every projection accepts exactly one arg: an AuthoritativeSSOT."""
    for fn in ALL_PROJECTIONS:
        sig = inspect.signature(fn)
        params = list(sig.parameters.values())
        assert len(params) == 1, \
            f"{fn.__name__} must be a single-arg function; got {params}"


def test_t4_3_projection_is_pure_by_repeated_call(ssot_rich):
    """Calling twice with the same input returns the same output."""
    from dataclasses import asdict, is_dataclass

    def _norm(v):
        if is_dataclass(v):
            return asdict(v)
        return v

    for fn in ALL_PROJECTIONS:
        a = _norm(fn(ssot_rich))
        b = _norm(fn(ssot_rich))
        assert a == b, f"{fn.__name__} not pure"


def test_t4_3_no_projection_writes_to_stdout(ssot_rich, capsys):
    """No projection prints to stdout/stderr."""
    for fn in ALL_PROJECTIONS:
        fn(ssot_rich)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
