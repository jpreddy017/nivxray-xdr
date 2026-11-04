"""NVKC pytest harness — CI gate for the Validation & Knowledge Corpus.

Discovers every `*.nvkc.yaml` under `backend/nvkc/corpus/`, replays
each sample through the frozen v1.1 pipeline, asserts every expected
field matches, and enforces per-sample determinism (same input →
same output across two runs).

CLI:
    pytest backend/nvkc/harness/                     # normal CI run
    pytest backend/nvkc/harness/ --nvkc-update-baseline   # owner-only

The --nvkc-update-baseline flag rewrites the descriptor YAMLs with
the current actual outputs. Owner review of the diff is required
before commit — same governance as the Golden Corpus.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nvkc.schema import discover_samples
from nvkc.harness.runner import (
    replay,
    _actual_outputs,
    diff_expected,
    update_baseline_yaml,
)

CORPUS_ROOT = Path(__file__).resolve().parent.parent / "corpus"


def _samples():
    if not CORPUS_ROOT.exists():
        return []
    return discover_samples(CORPUS_ROOT)


@pytest.mark.parametrize("sample", _samples(),
                         ids=lambda s: s.slug if hasattr(s, "slug") else str(s))
def test_nvkc_sample(sample, request):
    """One test per NVKC sample."""
    r1 = replay(sample)
    r2 = replay(sample)

    a1 = _actual_outputs(r1)
    a2 = _actual_outputs(r2)
    assert a1 == a2, (
        f"[{sample.slug}] NON-DETERMINISTIC replay — P0 architectural regression.\n"
        f"run1 = {a1}\nrun2 = {a2}")

    if request.config.getoption("--nvkc-update-baseline"):
        update_baseline_yaml(sample, a1)
        return

    diffs = diff_expected(sample, a1)
    assert not diffs, (
        f"[{sample.slug}] NVKC baseline drift ({sample.descriptor_path}):\n"
        + "\n".join(f"  • {d}" for d in diffs)
        + f"\n\nIf this drift is intentional, rerun with "
          f"--nvkc-update-baseline after owner review."
    )
