"""
Transformation registry & Coverage Dashboard tests.

Governance guarantees enforced by this suite
--------------------------------------------

1. Every transformation registered in the engine passes
   (``TRANSFORMATIONS`` tuple in ``decoder.py`` + the ``_FOLDS``
   pipeline in ``structural.py`` + registered descriptors elsewhere)
   has a corresponding entry in
   :mod:`workspace.convergence.registry`.

2. Every registry descriptor has:
   * unique ``name``
   * a supported ``language``
   * a supported ``category``
   * non-empty ``description`` / ``consumes`` / ``produces``
   * a ``version`` string in the shape ``X.Y``

3. The Coverage Dashboard builds without error and reports at least
   one covered transformation per family currently in the corpus.
"""
from __future__ import annotations

from workspace.convergence import decoder as decoder_pass
from workspace.convergence.registry import (
    REGISTRY,
    languages,
    categories,
    registry_by_name,
)
from workspace_recovery.phase_r.coverage_dashboard import build_dashboard


ENGINE_PASS_TRANSFORMATION_NAMES: set[str] = (
    # decoder pass declares its transformations via a public tuple
    {xf.name for xf in decoder_pass.TRANSFORMATIONS}
    # structural pass folds are named strings in _FOLDS (private)
    | {
        "structural-static-join-fold",
        "structural-join-operator-fold",
        "structural-string-concat-fold",
        "structural-cmd-caret-strip",
        "structural-js-split-reverse-join",
        "structural-js-split-join",
    }
    # content pass folds
    | {
        "content-ps-operator-case-normalize",
        "content-env-var-case-normalize",
        "content-env-var-substitute",
        "content-string-index-single-fold",
        "content-string-index-range-fold",
        "content-string-index-list-fold",
        "content-backtick-escape-strip",
        "content-numeric-constant-fold",
    }
    # semantic pass reductions
    | {
        "semantic-bash-pipeline-reduce",
        "semantic-ps-alias-expand",
        "semantic-ps-variable-propagate",
    }
)


def test_registry_covers_every_engine_transformation():
    """Every transformation implemented in a pass MUST have a
    registry descriptor."""
    registered = {xf.name for xf in REGISTRY}
    missing = ENGINE_PASS_TRANSFORMATION_NAMES - registered
    assert not missing, (
        f"Registry is missing descriptors for: {sorted(missing)}"
    )


def test_registry_has_no_stale_entries():
    """Every registry descriptor MUST correspond to an implemented
    transformation \u2014 no stale entries."""
    registered = {xf.name for xf in REGISTRY}
    stale = registered - ENGINE_PASS_TRANSFORMATION_NAMES
    assert not stale, (
        f"Registry has stale entries not implemented in any pass: {sorted(stale)}"
    )


def test_registry_names_are_unique():
    seen: set[str] = set()
    for xf in REGISTRY:
        assert xf.name not in seen, f"duplicate registry name: {xf.name}"
        seen.add(xf.name)


def test_registry_descriptors_are_well_formed():
    valid_langs = set(languages())
    valid_cats = set(categories())
    for xf in REGISTRY:
        assert xf.language in valid_langs, f"{xf.name}: bad language {xf.language}"
        assert xf.category in valid_cats, f"{xf.name}: bad category {xf.category}"
        assert xf.description, f"{xf.name}: empty description"
        assert xf.consumes, f"{xf.name}: empty consumes"
        assert xf.produces, f"{xf.name}: empty produces"
        # version format X.Y
        parts = xf.version.split(".")
        assert len(parts) >= 2, f"{xf.name}: bad version {xf.version}"
        for p in parts:
            assert p.isdigit(), f"{xf.name}: bad version segment {p}"


def test_registry_by_name_returns_all_descriptors():
    m = registry_by_name()
    assert len(m) == len(REGISTRY)
    assert all(m[name].name == name for name in m)


def test_coverage_dashboard_reports_100_percent_family_coverage():
    dash = build_dashboard()
    fo = dash["family_overall"]
    assert fo["sample_dcs_pct"] == 100.0
    assert fo["technique_coverage_pct"] == 100.0
    # Every family in the current corpus must have at least one passing sample.
    for f in dash["families"]:
        assert f["samples_passed"] >= 1, f"family {f['family_id']} has zero passing samples"
        assert f["technique_coverage_pct"] > 0, (
            f"family {f['family_id']} has zero technique coverage"
        )


def test_coverage_dashboard_transformation_coverage_matches_universe():
    dash = build_dashboard()
    xo = dash["transformation_overall"]
    assert xo["total_transformations"] == len(REGISTRY)
    # Every language dimension present in the registry must appear in
    # the dashboard aggregation.
    dash_langs = {row["language"] for row in xo["by_language"]}
    assert dash_langs == set(languages())


def test_coverage_dashboard_lists_uncovered_transformations():
    """The dashboard MUST explicitly enumerate uncovered transformations
    so engineering can target them next. If everything is covered,
    the list is empty (that's also a valid state)."""
    dash = build_dashboard()
    xf_rows = dash["transformations"]
    uncovered = [r for r in xf_rows if not r["covered"]]
    # No assertion about the exact count \u2014 just that the list is
    # a valid list of dicts with the expected shape.
    for r in uncovered:
        assert "name" in r and "language" in r and "category" in r
