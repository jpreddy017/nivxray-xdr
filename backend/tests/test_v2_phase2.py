"""Phase 2 · Storage schema + shadow adapter + RC5-isolation tests.

Focus:
  • v2/case_engine schema is well-formed and never auto-writes.
  • v2/case_engine imports have zero side effects.
  • command_line shadow adapter respects the ADAPTERS feature flag.
  • command_line normalizer produces valid, deterministic CEM events.
  • RC5 endpoints are unaffected by enabling `NIVX_FLAG_ADAPTERS=shadow`.
"""
from __future__ import annotations

import hashlib
import importlib
import json
import os
from unittest import mock

import pytest

from v2.adapters.base import Source
from v2.adapters.command_line import CommandLineAdapter
from v2.case_engine import COLLECTIONS, INDEX_SPECS, ensure_indexes
from v2.case_engine.schema import summary as schema_summary
from v2.case_engine.store import coll_name
from v2.cem.v1.schema import CanonicalEvent
from v2.normalization.command_line_normalizer import CommandLineNormalizer
from v2 import flags


# ═══════════════════════════════════════════════════════════════════
# Phase 2a — CEM Storage Schema
# ═══════════════════════════════════════════════════════════════════
class TestCaseEngineSchema:
    def test_collections_locked(self):
        expected_keys = {
            "cases", "events", "entities", "relationships",
            "behaviors", "reports", "enrichment_cache",
            "audit_log", "artifacts", "shadow_observations",
        }
        assert set(COLLECTIONS.keys()) == expected_keys

    def test_every_collection_has_indexes(self):
        for coll in COLLECTIONS.values():
            assert coll in INDEX_SPECS, f"No indexes defined for {coll}"
            assert INDEX_SPECS[coll], f"Empty index list for {coll}"

    def test_no_v2_collection_name_collides_with_rc5(self):
        rc5_names = {
            "workspace_cases", "investigation_events", "settings",
            "shadow_snapshots", "training_inbox",
            "rc5_golden_runs", "playbooks",
        }
        collisions = rc5_names.intersection(COLLECTIONS.values())
        assert not collisions, f"v2 collection name collision with RC5: {collisions}"

    def test_summary_shape(self):
        s = schema_summary()
        assert "collections" in s and "index_count" in s

    def test_coll_name_resolves(self):
        assert coll_name("events") == "v2_case_events"

    def test_coll_name_unknown_raises(self):
        with pytest.raises(KeyError):
            coll_name("nope")


class TestEnsureIndexesFlagGated:
    @pytest.mark.asyncio
    async def test_disabled_flag_skips_index_creation(self):
        # With CASE_ENGINE disabled, ensure_indexes must be a no-op.
        # We assert it returns an empty dict WITHOUT touching db.
        db_mock = mock.MagicMock()
        with mock.patch.dict(os.environ, {"NIVX_FLAG_CASE_ENGINE": "disabled"}):
            importlib.reload(flags)
            # Re-import store to pick up reloaded flags module.
            from v2.case_engine import store as _store
            importlib.reload(_store)
            result = await _store.ensure_indexes(db_mock)
        assert result == {}
        db_mock.__getitem__.assert_not_called()
        # restore
        importlib.reload(flags)


# ═══════════════════════════════════════════════════════════════════
# Phase 2b — Shadow Command-Line Adapter
# ═══════════════════════════════════════════════════════════════════
class TestCommandLineAdapterDisabled:
    def test_detect_returns_zero_when_flag_disabled(self):
        with mock.patch.dict(os.environ, {"NIVX_FLAG_ADAPTERS": "disabled"}):
            importlib.reload(flags)
            a = CommandLineAdapter()
            assert a.detect("powershell -c Get-Process") == 0.0

    def test_stream_is_empty_when_flag_disabled(self):
        with mock.patch.dict(os.environ, {"NIVX_FLAG_ADAPTERS": "disabled"}):
            importlib.reload(flags)
            a = CommandLineAdapter()
            src = Source(kind="bytes", ref=b"powershell -c Get-Process")
            assert list(a.stream(src)) == []

    def teardown_method(self, method):
        importlib.reload(flags)


class TestCommandLineAdapterShadow:
    def setup_method(self, method):
        os.environ["NIVX_FLAG_ADAPTERS"] = "shadow"
        importlib.reload(flags)
        # Reload adapter module so it re-reads the flag helper.
        import v2.adapters.command_line as _cl
        importlib.reload(_cl)

    def teardown_method(self, method):
        os.environ.pop("NIVX_FLAG_ADAPTERS", None)
        importlib.reload(flags)

    def test_detect_text_input(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        a = CL()
        assert a.detect("powershell -c Get-Process") == 0.75

    def test_detect_rejects_binary(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        a = CL()
        # Random bytes that fail utf-8 decode → 0.0.
        assert a.detect(b"\xff\xfe\xfd\x00\x01\x02\x03\x04") == 0.0

    def test_detect_rejects_oversize(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        a = CL()
        assert a.detect("A" * 40_000) == 0.0

    def test_stream_emits_single_raw_event(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        a = CL()
        src = Source(kind="bytes", ref="powershell -c Get-Process")
        events = list(a.stream(src))
        assert len(events) == 1
        ev = events[0]
        assert ev.adapter == "command_line"
        assert ev.payload["text"] == "powershell -c Get-Process"
        assert ev.payload["length"] == 25
        assert ev.payload["sha256"] == hashlib.sha256(
            b"powershell -c Get-Process"
        ).hexdigest()


class TestCommandLineNormalizer:
    def setup_method(self, method):
        os.environ["NIVX_FLAG_ADAPTERS"] = "shadow"
        importlib.reload(flags)
        import v2.adapters.command_line as _cl
        import v2.normalization.command_line_normalizer as _norm
        importlib.reload(_cl)
        importlib.reload(_norm)

    def teardown_method(self, method):
        os.environ.pop("NIVX_FLAG_ADAPTERS", None)
        importlib.reload(flags)

    def test_produces_valid_cem_event(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        from v2.normalization.command_line_normalizer import CommandLineNormalizer as N
        a = CL()
        src = Source(kind="bytes", ref="powershell -c Get-Process")
        raw = next(iter(a.stream(src)))
        n = N()
        events = list(n.normalize(raw, case_id="case_test"))
        assert len(events) == 1
        assert isinstance(events[0], CanonicalEvent)
        assert events[0].kind == "process_create"
        assert events[0].adapter == "command_line"
        assert events[0].case_id == "case_test"
        assert events[0].artefacts_iids == (events[0].artefacts_iids[0],)
        assert events[0].artefacts_iids[0].startswith("cmd_")

    def test_deterministic_iids_for_identical_input(self):
        from v2.adapters.command_line import CommandLineAdapter as CL
        from v2.normalization.command_line_normalizer import CommandLineNormalizer as N
        a = CL()
        n = N()
        src = Source(kind="bytes", ref="cmd /c whoami")
        raw1 = next(iter(a.stream(src)))
        raw2 = next(iter(a.stream(src)))
        e1 = next(iter(n.normalize(raw1, case_id="case_x")))
        e2 = next(iter(n.normalize(raw2, case_id="case_x")))
        assert e1.iid == e2.iid
        assert e1.process_iid == e2.process_iid
        assert e1.artefacts_iids == e2.artefacts_iids

    def test_disabled_flag_yields_nothing(self):
        os.environ["NIVX_FLAG_ADAPTERS"] = "disabled"
        importlib.reload(flags)
        import v2.normalization.command_line_normalizer as _norm
        importlib.reload(_norm)
        from v2.normalization.command_line_normalizer import CommandLineNormalizer as N
        from v2.adapters.base import RawEvent
        # Even a valid raw event should yield nothing when disabled.
        raw = RawEvent(adapter="command_line", sequence=0,
                       payload={"text": "hi", "length": 2,
                                "sha256": "0"*64, "hint_language": None})
        assert list(N().normalize(raw, case_id="c")) == []


# ═══════════════════════════════════════════════════════════════════
# RC5 isolation invariant: enabling shadow flag MUST NOT change RC5
# ═══════════════════════════════════════════════════════════════════
class TestRC5UnaffectedByShadowFlag:
    def test_rc5_engine_source_has_no_conditional_on_adapter_flag(self):
        """The RC5 engine must not read ANY v2 feature flag. Any
        conditional branch there would violate Governance §3."""
        import pathlib
        offenders: list[str] = []
        engine_dir = pathlib.Path(__file__).resolve().parents[1] / "engine"
        for py in engine_dir.rglob("*.py"):
            body = py.read_text(errors="ignore")
            if "NIVX_FLAG_" in body or "v2.flags" in body or "from v2" in body:
                offenders.append(str(py.relative_to(engine_dir.parent)))
        assert not offenders, (
            "RC5 engine references v2 feature flags — this violates "
            f"Governance §3 (RC5 immutability): {offenders}"
        )

    def test_rc5_parse_endpoint_output_stable_across_flag_states(self):
        """Call the deterministic golden-corpus runner (RC5 core)
        twice — once with the shadow flag OFF and once ON. Per-sample
        fingerprints must be byte-identical."""
        from engine.golden_corpus import run_corpus
        os.environ.pop("NIVX_FLAG_ADAPTERS", None)
        r1 = run_corpus()
        os.environ["NIVX_FLAG_ADAPTERS"] = "shadow"
        r2 = run_corpus()
        os.environ.pop("NIVX_FLAG_ADAPTERS", None)

        def fp(r):
            per = {s.sample_id: (s.got_verdict, tuple(s.mitre_technique_ids), s.passed) for s in r.samples}
            return hashlib.sha256(json.dumps(per, sort_keys=True, default=list).encode()).hexdigest()

        assert fp(r1) == fp(r2), (
            "RC5 output changed between flag OFF and flag=shadow. "
            "This VIOLATES the shadow-adapter isolation constraint."
        )
