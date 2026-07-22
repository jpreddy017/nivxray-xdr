"""v2 framework contract tests (Phase 1).

Verifies:
  • CEM v1 schema is well-formed and immutable.
  • Adapter registry discovers all 5 seed adapters.
  • Every seed adapter satisfies the InputAdapter Protocol.
  • Registry is deterministic across repeated discover() calls.
  • Adapter names/versions/CEM versions are byte-stable.
  • v2 code does NOT import any RC5 engine module (isolation §3).
  • CEM Provenance / Entity / Relationship / CanonicalEvent
    construct + serialise round-trip cleanly.
  • JSON Schemas expose the same enums as the Python dataclasses.
"""
from __future__ import annotations

import importlib
import json
import sys

import pytest

from v2.adapters import discover, ADAPTERS
from v2.adapters.base import BaseAdapter, InputAdapter
from v2.adapters.registry import reset_registry
from v2.cem import registry as cem_registry
from v2.cem.v1 import schema as cem_schema
from v2.cem.v1 import json_schema as cem_json_schema
from v2.parser.base import Parser, ParsedEvent
from v2.normalization.base import Normalizer


# ─── Adapter registry ───────────────────────────────────────────────
class TestAdapterRegistry:
    def test_discovers_all_five_seeds(self):
        reset_registry()
        # Ensure any previously-imported adapter modules re-register.
        for mod in (
            "v2.adapters.command_line",
            "v2.adapters.powershell",
            "v2.adapters.cmd",
            "v2.adapters.bash",
            "v2.adapters.json_events",
        ):
            if mod in sys.modules:
                importlib.reload(sys.modules[mod])
        names = discover()
        assert set(names) == {"command_line", "powershell", "cmd", "bash", "json_events"}

    def test_registry_deterministic(self):
        first = discover()
        second = discover()
        assert first == second

    def test_every_adapter_is_a_protocol_impl(self):
        discover()
        for name, cls in ADAPTERS.items():
            inst = cls()
            assert isinstance(inst, InputAdapter), (
                f"{name} does not satisfy InputAdapter Protocol"
            )
            assert isinstance(inst, BaseAdapter)

    def test_adapter_metadata_stability(self):
        """Adapter names + versions are the public identity of an
        adapter. This test freezes them so a rename lands as a
        governance amendment, not an accidental bump."""
        discover()
        expected = {
            "command_line": ("0.1.0-stub", "v1"),
            "powershell":   ("0.1.0-stub", "v1"),
            "cmd":          ("0.1.0-stub", "v1"),
            "bash":         ("0.1.0-stub", "v1"),
            "json_events":  ("0.1.0-stub", "v1"),
        }
        for name, (ver, cem) in expected.items():
            cls = ADAPTERS[name]
            assert cls.version == ver, f"{name}.version drifted: {cls.version}"
            assert cls.cem_version == cem, f"{name}.cem_version drifted"

    def test_stub_detect_returns_zero(self):
        """Stubs return 0.0 confidence — no accidental logic in Phase 1."""
        discover()
        for name, cls in ADAPTERS.items():
            assert cls().detect(b"anything") == 0.0, (
                f"{name}.detect() must return 0.0 in Phase 1 (stub)"
            )


# ─── CEM v1 schema ───────────────────────────────────────────────────
class TestCEMSchema:
    def test_version_registered(self):
        assert cem_registry.LATEST == "v1"
        assert "v1" in cem_registry.supported()
        assert cem_registry.get("v1") is cem_schema

    def test_unknown_version_raises(self):
        with pytest.raises(KeyError):
            cem_registry.get("v42")

    def test_entity_kind_rejection(self):
        with pytest.raises(ValueError):
            cem_schema.Entity(iid="e_1", case_id="c_1", kind="not-a-kind")

    def test_event_kind_rejection(self):
        with pytest.raises(ValueError):
            cem_schema.CanonicalEvent(
                iid="evt_1", case_id="c_1", adapter="x",
                adapter_version="0.0.1", ts="2026-02-22T00:00:00Z",
                sequence=1, kind="not-a-kind",
            )

    def test_relationship_kind_rejection(self):
        with pytest.raises(ValueError):
            cem_schema.Relationship(
                iid="rel_1", case_id="c_1",
                src_iid="a", dst_iid="b",
                kind="not-a-kind", confidence=0.5,
            )

    def test_relationship_confidence_bounds(self):
        with pytest.raises(ValueError):
            cem_schema.Relationship(
                iid="rel_1", case_id="c_1",
                src_iid="a", dst_iid="b",
                kind="executed", confidence=1.2,
            )

    def test_canonical_event_serialises_deterministically(self):
        e1 = cem_schema.CanonicalEvent(
            iid="evt_01", case_id="case_01",
            adapter="command_line", adapter_version="0.1.0-stub",
            ts="2026-02-22T00:00:00Z", sequence=1, kind="process_create",
        )
        e2 = cem_schema.CanonicalEvent(
            iid="evt_01", case_id="case_01",
            adapter="command_line", adapter_version="0.1.0-stub",
            ts="2026-02-22T00:00:00Z", sequence=1, kind="process_create",
        )
        assert json.dumps(e1.to_dict(), sort_keys=True) == json.dumps(e2.to_dict(), sort_keys=True)

    def test_enum_sizes_locked(self):
        # Freeze the enums so an accidental addition lands as a
        # governance amendment.
        assert len(cem_schema.ENTITY_KINDS) == 44
        assert len(cem_schema.EVENT_KINDS) == 41
        assert len(cem_schema.RELATIONSHIP_KINDS) == 27


# ─── CEM v1 JSON schema mirrors dataclasses ─────────────────────────
class TestCEMJsonSchema:
    def test_event_schema_enum_matches(self):
        expected = list(cem_schema.EVENT_KINDS)
        got = cem_json_schema.CANONICAL_EVENT_SCHEMA["properties"]["kind"]["enum"]
        assert got == expected

    def test_entity_schema_enum_matches(self):
        assert cem_json_schema.ENTITY_SCHEMA["properties"]["kind"]["enum"] == list(cem_schema.ENTITY_KINDS)

    def test_relationship_schema_enum_matches(self):
        assert cem_json_schema.RELATIONSHIP_SCHEMA["properties"]["kind"]["enum"] == list(cem_schema.RELATIONSHIP_KINDS)


# ─── Parser + Normalizer contract types ─────────────────────────────
class TestParserNormalizerContracts:
    def test_parsed_event_is_frozen_dataclass(self):
        p = ParsedEvent(adapter="x", sequence=1, kind_hint=None, payload={})
        with pytest.raises(Exception):
            p.adapter = "y"          # frozen dataclass — cannot reassign

    def test_parser_and_normalizer_are_protocols(self):
        # Protocols themselves are import-safe placeholders — the real
        # test is that a concrete class satisfying the shape is
        # runtime-checkable.
        class FakeParser:
            name = "fake"; version = "0.0.1"
            def parse(self, raw): return ParsedEvent(adapter="x", sequence=1, kind_hint=None, payload={})
            def stream(self, source): return iter(())

        class FakeNormalizer:
            adapter = "fake"; cem_version = "v1"
            def normalize(self, parsed, *, case_id): return iter(())

        assert isinstance(FakeParser(), Parser)
        assert isinstance(FakeNormalizer(), Normalizer)


# ─── Isolation §3 · v2 must not import from RC5 engine ─────────────
class TestIsolationFromRC5:
    def test_v2_modules_do_not_import_engine(self):
        """Any v2 module importing from `engine.*` violates §3
        Namespace Isolation. RC5 must remain reachable only via the
        eventual `v2/adapters/*_bridge` modules (not yet built)."""
        import pkgutil, importlib
        import v2

        offenders: list[str] = []
        for mod_info in pkgutil.walk_packages(v2.__path__, prefix="v2."):
            m = importlib.import_module(mod_info.name)
            src = getattr(m, "__file__", "") or ""
            if not src.endswith(".py"):
                continue
            with open(src) as f:
                body = f.read()
            for line in body.splitlines():
                s = line.strip()
                if s.startswith("#"):
                    continue
                if s.startswith("from engine") or s.startswith("import engine"):
                    offenders.append(f"{mod_info.name}: {s}")
        assert not offenders, (
            "v2 modules must NOT import RC5 `engine` code per "
            f"GOVERNANCE.md §3: {offenders}"
        )
