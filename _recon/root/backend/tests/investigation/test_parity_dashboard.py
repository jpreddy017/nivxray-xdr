"""Tests for the Parity Dashboard header + sparkline.

Contracts:
  · Migration readiness is the primary indicator, not raw parity %
  · Dashboard clearly signals cut-over ineligibility when far below gate
  · Sparkline renders when ≥ 2 runs are recorded
  · Report never raises on missing / malformed ledger
"""
from __future__ import annotations

from nivxforge.investigation.pipeline.cem_parity import (
    FieldDelta, GapCategory, ParityReport,
    _render_sparkline, render_parity_markdown,
)


def _report(fixture: str, parity: float, gap_cat: str = None,
             gap_count: int = 0) -> ParityReport:
    deltas = tuple(
        FieldDelta(f"f{i}", "lost_mapping", "v", None,
                    reason="synthetic", gap_category=gap_cat)
        for i in range(gap_count)
    )
    return ParityReport(
        fixture=fixture,
        vendor_route="synthetic",
        vendor_field_count=5,
        semantic_field_count=3,
        matches=2,
        new_mappings=1,
        lost_mappings=gap_count,
        value_mismatches=0,
        ambiguous=0,
        confidence_drift=-0.05,
        parity_rate=parity,
        field_deltas=deltas,
        semantic_confidence=0.9,
        schema_family="generic_json",
    )


class TestDashboardHeader:

    def test_readiness_table_leads_the_report(self):
        md = render_parity_markdown([_report("a", 0.384)])
        # Migration Readiness must appear BEFORE Engineering detail.
        pos_dash = md.find("## Migration Readiness")
        pos_detail = md.find("## Engineering detail")
        assert 0 <= pos_dash < pos_detail

    def test_cutover_eligibility_no_when_far_below_gate(self):
        md = render_parity_markdown([_report("a", 0.384)])
        assert "Cut-over Eligible | ❌ No" in md
        assert "Parallel validation only" in md

    def test_cutover_eligibility_yes_when_perfect_parity_no_gaps(self):
        r = _report("a", 1.0, gap_count=0)
        md = render_parity_markdown([r])
        assert "Cut-over Eligible | ✅ Yes" in md

    def test_expected_divergence_does_not_block_cutover(self):
        # 100% parity + only expected_divergence gaps → still eligible.
        r = _report("a", 1.0,
                     gap_cat=GapCategory.EXPECTED_DIVERGENCE,
                     gap_count=5)
        md = render_parity_markdown([r])
        assert "Cut-over Eligible | ✅ Yes" in md

    def test_remaining_blockers_excludes_expected_divergence(self):
        r1 = _report("a", 0.5,
                      gap_cat=GapCategory.EXPECTED_DIVERGENCE,
                      gap_count=10)
        r2 = _report("b", 0.5,
                      gap_cat=GapCategory.PARSER_GAP,
                      gap_count=1)
        md = render_parity_markdown([r1, r2])
        # 1 parser_gap → 1 blocker (10 expected_divergence excluded)
        assert "Remaining Blockers | 1" in md

    def test_current_parity_and_target_are_shown(self):
        md = render_parity_markdown([_report("a", 0.384)])
        assert "38.4%" in md
        assert "99.5%" in md


class TestSparkline:

    def test_empty_ledger(self):
        line, summary = _render_sparkline([])
        assert line == ""
        assert "no parity runs" in summary.lower()

    def test_single_run_no_sparkline(self):
        line, summary = _render_sparkline([{"overall_parity": 0.5}])
        assert line == ""
        assert "needs ≥ 2 runs" in summary

    def test_multi_run_renders_blocks(self):
        entries = [{"overall_parity": p} for p in
                    (0.351, 0.371, 0.384, 0.410, 0.480)]
        line, summary = _render_sparkline(entries)
        assert len(line) == 5
        # Ascending series → non-descending sparkline heights
        indexes = ["▁▂▃▄▅▆▇█".index(ch) for ch in line]
        for i in range(1, len(indexes)):
            assert indexes[i] >= indexes[i - 1]
        assert "latest **48.0%**" in summary

    def test_flat_series_produces_uniform_bar(self):
        entries = [{"overall_parity": 0.5}] * 4
        line, _ = _render_sparkline(entries)
        assert len(line) == 4
        assert all(ch == line[0] for ch in line)
