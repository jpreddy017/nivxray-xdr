"""Corpus loader — reads YAML sample specs from disk."""
from __future__ import annotations

import glob
import os
from typing import Iterable

import yaml

from .models import SampleSpec, VerdictExpected


def load_corpus(path: str) -> list[SampleSpec]:
    """Load every ``*.yaml`` sample under ``path`` (deterministic order)."""
    if os.path.isfile(path):
        files = [path]
    else:
        files = sorted(glob.glob(os.path.join(path, "*.yaml")))
    samples: list[SampleSpec] = []
    for f in files:
        with open(f, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        samples.append(_from_dict(data, source=f))
    return samples


def _from_dict(d: dict, *, source: str) -> SampleSpec:
    return SampleSpec(
        id=d["id"],
        title=d["title"],
        source=d.get("provenance") or source,
        input=d["input"],
        expected_verdict=VerdictExpected(d["expected_verdict"]),
        must_fire_intents=list(d.get("must_fire_intents", [])),
        must_not_fire=list(d.get("must_not_fire", [])),
        forbidden_words_in_verdict=list(d.get("forbidden_words_in_verdict", [])),
        must_admit_unknown=bool(d.get("must_admit_unknown", False)),
        notes=d.get("notes", ""),
    )


__all__ = ["load_corpus"]
