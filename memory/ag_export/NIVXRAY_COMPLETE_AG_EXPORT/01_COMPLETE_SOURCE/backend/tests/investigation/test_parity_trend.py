"""Tests for the parity trend ledger."""
from __future__ import annotations

import json
import pathlib
import tempfile

from nivxforge.investigation.pipeline.cem_parity import (
    FieldDelta, ParityReport,
)
from nivxforge.investigation.pipeline.parity_trend import (
    append_entry, build_trend_entry, read_entries, render_trend_markdown,
)


def _report(fixture: str, parity: float, cat_counts: dict) -> ParityReport:
    deltas = tuple(
        FieldDelta(f"f{i}", "lost_mapping", "v", None,
                    reason="synthetic", gap_category=cat)
        for cat, cnt in cat_counts.items() for i in range(cnt)
    )
    return ParityReport(
        fixture=fixture,
        vendor_route="synthetic",
        vendor_field_count=5,
        semantic_field_count=3,
        matches=2,
        new_mappings=1,
        lost_mappings=sum(cat_counts.values()),
        value_mismatches=0,
        ambiguous=0,
        confidence_drift=-0.05,
        parity_rate=parity,
        field_deltas=deltas,
        semantic_confidence=0.9,
        schema_family="generic_json",
    )


class TestTrendLedger:

    def test_build_entry_aggregates_metrics(self):
        reports = [
            _report("a", 0.60, {"parser_gap": 1, "schema_gap": 2}),
            _report("b", 0.80, {"parser_gap": 1}),
        ]
        entry = build_trend_entry(reports, note="unit-test")
        assert entry.fixtures_count == 2
        assert abs(entry.overall_parity - 0.70) < 1e-6
        assert entry.per_category == {"parser_gap": 2, "schema_gap": 2}
        assert entry.note == "unit-test"
        # Timestamp is UTC ISO-8601.
        assert "T" in entry.timestamp and entry.timestamp.endswith(("Z", "+00:00"))

    def test_append_and_read_round_trip(self):
        reports = [_report("x", 0.5, {"parser_gap": 1})]
        entry = build_trend_entry(reports)
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "trend.jsonl"
            append_entry(entry, ledger_path=p)
            append_entry(entry, ledger_path=p)
            rows = read_entries(ledger_path=p)
        assert len(rows) == 2
        for r in rows:
            assert r["fixtures_count"] == 1
            assert r["overall_parity"] == 0.5

    def test_render_markdown_shows_recent_rows(self):
        rows = [{
            "timestamp": "2026-02-02T10:00:00+00:00",
            "git_sha": "abcdef1",
            "fixtures_count": 13,
            "overall_parity": 0.371,
            "mean_confidence_drift": -0.1,
            "matches": 20,
            "lost_mappings": 4,
            "per_category": {"parser_gap": 1, "schema_gap": 1},
            "note": "identity parser landed",
        }]
        md = render_trend_markdown(rows)
        assert "37.1%" in md
        assert "abcdef1" in md
        assert "parser_gap:1" in md

    def test_render_markdown_empty(self):
        md = render_trend_markdown([])
        assert "No parity runs" in md

    def test_ledger_read_handles_missing_file(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "does-not-exist.jsonl"
            assert read_entries(ledger_path=p) == []

    def test_ledger_read_skips_malformed_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "trend.jsonl"
            p.write_text(
                '{"overall_parity":0.5}\n'
                'not-json\n'
                '{"overall_parity":0.7}\n',
                encoding="utf-8",
            )
            rows = read_entries(ledger_path=p)
        assert len(rows) == 2
