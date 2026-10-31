"""Alien Telemetry Corpus — permanent regression asset.

Purpose (owner mandate): measure the release metric
    "Can NivXRay understand telemetry it has never seen before?"

Every JSON file under ``corpus/alien/`` is a sanitised, previously-
unseen telemetry shape. The pipeline must be able to:

  1. Parse the file (parser stage succeeds),
  2. Emit a well-formed SchemaFingerprint (Stage 2b),
  3. Emit a well-formed SemanticMappingResult (Stage 3),
  4. Reach the Investigation Graph via ``run_phase1``,

without raising, and without depending on vendor identity.

The corpus grows over time. This test iterates every file present.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from nivxforge.investigation.pipeline.input_classification import (
    classify_input,
)
from nivxforge.investigation.pipeline.orchestrator import run_phase1
from nivxforge.investigation.pipeline.parser import parse_input
from nivxforge.investigation.pipeline.schema_understanding import (
    SchemaFingerprint,
    understand_schema,
)
from nivxforge.investigation.pipeline.semantic_field_mapper import (
    SemanticMappingResult,
    map_semantic_fields,
)


CORPUS_DIR = pathlib.Path(__file__).parent / "corpus" / "alien"


def _corpus_files():
    return sorted(CORPUS_DIR.glob("*.json"))


class TestCorpusInvariants:

    def test_corpus_directory_exists(self):
        assert CORPUS_DIR.exists(), (
            f"alien corpus directory missing: {CORPUS_DIR}"
        )

    def test_corpus_seed_size_meets_minimum(self):
        # Owner requested minimum of 5 diverse alien shapes at seed.
        assert len(_corpus_files()) >= 5


@pytest.mark.parametrize("path", _corpus_files(), ids=lambda p: p.stem)
class TestAlienTelemetry:
    """One test class run per alien telemetry file.

    Every file must clear every stage.
    """

    def test_file_is_valid_json(self, path):
        raw = path.read_text(encoding="utf-8")
        json.loads(raw)  # will raise if malformed

    def test_parser_succeeds(self, path):
        raw = path.read_text(encoding="utf-8")
        classification = classify_input(raw)
        parsed = parse_input(raw, classification)
        assert parsed.records, f"parser produced no records for {path.name}"

    def test_schema_understanding_returns_fingerprint(self, path):
        raw = path.read_text(encoding="utf-8")
        classification = classify_input(raw)
        parsed = parse_input(raw, classification)
        fp = understand_schema(parsed)
        assert isinstance(fp, SchemaFingerprint)
        # Every alien file must yield a supported success family.
        # generic_json is the expected honest classification.
        assert fp.schema_family in ("generic_json", "unknown_structured")

    def test_semantic_field_mapper_returns_result(self, path):
        raw = path.read_text(encoding="utf-8")
        classification = classify_input(raw)
        parsed = parse_input(raw, classification)
        fp = understand_schema(parsed)
        r = map_semantic_fields(fp, parsed)
        assert isinstance(r, SemanticMappingResult)
        # No field is silently discarded.
        seen = (
            {m.surface_field for m in r.mappings}
            | set(r.unmapped_fields)
            | {a.surface_field for a in r.ambiguous_fields}
        )
        assert seen == set(fp.candidate_fields), (
            f"{path.name}: fields not fully accounted for. "
            f"missing = {set(fp.candidate_fields) - seen}"
        )

    def test_pipeline_reaches_investigation_graph(self, path):
        raw = path.read_text(encoding="utf-8")
        state = run_phase1(raw)
        assert state.graph is not None, (
            f"{path.name}: pipeline failed to build a graph"
        )


class TestReleaseMetric:
    """The release metric: previously-unseen telemetry produces
    at least *some* canonical mappings across the whole corpus.

    This is a coarse guardrail — not a per-file assertion. It
    prevents silent regressions where every alien shape becomes
    100% unmapped.
    """

    def test_corpus_wide_mapping_rate(self):
        total_candidates = 0
        total_mapped = 0
        for p in _corpus_files():
            raw = p.read_text(encoding="utf-8")
            classification = classify_input(raw)
            parsed = parse_input(raw, classification)
            fp = understand_schema(parsed)
            r = map_semantic_fields(fp, parsed)
            total_candidates += len(fp.candidate_fields)
            total_mapped += len(r.mappings)
        # At seed corpus, expect ≥ 1 mapping in aggregate — a corpus
        # of 5 truly-alien files with zero mappings would indicate
        # a Stage 3 regression.
        assert total_candidates > 0
        assert total_mapped >= 1, (
            f"release metric regression: {total_mapped}/"
            f"{total_candidates} alien fields mapped"
        )
