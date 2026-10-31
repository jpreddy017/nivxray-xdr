"""
Phase R1 loader — reads family JSON packs under ``phase_r/families/``.

Schema
------
Family JSON follows the *technique-first* schema (v2.0.0):

    {
      "family_id": "...",
      "family_display_name": "...",
      "family_version": "r1-2.0.0",
      "schema_version": "technique-first-1.0.0",
      "known_technique_universe": ["tech_id_1", "tech_id_2", ...],
      "techniques": [
        {
          "id": "tech_id_1",
          "display_name": "...",
          "description": "...",
          "mitre_attack": [...],
          "samples": [ {id, variant, input, expected}, ... ]
        }
      ]
    }

The loader exposes both:

* :func:`load_samples` \u2192 flat list (backwards compatible), where each
  sample is enriched with ``family_id`` **and** ``technique_id``.
* :func:`load_techniques` \u2192 hierarchical view (family \u2192 technique \u2192 samples)
  used by the Coverage Matrix reporter.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

FAMILIES_DIR = Path(__file__).resolve().parent / "families"


@dataclass(frozen=True)
class FamilyMeta:
    family_id: str
    display_name: str
    version: str
    technique_count: int
    sample_count: int
    known_technique_universe: tuple[str, ...] = field(default_factory=tuple)


def _families_on_disk() -> list[Path]:
    return sorted(FAMILIES_DIR.glob("*.json"))


def load_family(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_all_families() -> list[dict[str, Any]]:
    return [load_family(p) for p in _families_on_disk()]


def load_samples(families: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Return every R1 sample as a flat list, tagged with ``family_id`` and
    ``technique_id``.
    """
    wanted = set(families) if families is not None else None
    out: list[dict[str, Any]] = []
    for fam in load_all_families():
        fid = fam.get("family_id", "unknown")
        if wanted is not None and fid not in wanted:
            continue
        for tech in fam.get("techniques", []) or []:
            tid = tech.get("id", "unknown")
            for sample in tech.get("samples", []) or []:
                enriched = dict(sample)
                enriched["family_id"] = fid
                enriched["technique_id"] = tid
                out.append(enriched)
    return out


def load_techniques(
    families: Iterable[str] | None = None,
) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
    """Return ``(family, technique_records)`` pairs, where each technique record
    is the raw dict from the JSON file including its samples list. Used by the
    Coverage Matrix and family-level reporters.
    """
    wanted = set(families) if families is not None else None
    out: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
    for fam in load_all_families():
        fid = fam.get("family_id", "unknown")
        if wanted is not None and fid not in wanted:
            continue
        out.append((fam, list(fam.get("techniques", []) or [])))
    return out


def family_meta_list() -> list[FamilyMeta]:
    metas: list[FamilyMeta] = []
    for fam in load_all_families():
        techs = fam.get("techniques", []) or []
        sample_count = sum(len(t.get("samples", []) or []) for t in techs)
        metas.append(
            FamilyMeta(
                family_id=fam.get("family_id", "unknown"),
                display_name=fam.get("family_display_name", ""),
                version=fam.get("family_version", ""),
                technique_count=len(techs),
                sample_count=sample_count,
                known_technique_universe=tuple(
                    fam.get("known_technique_universe") or []
                ),
            )
        )
    return metas


__all__ = [
    "FAMILIES_DIR",
    "FamilyMeta",
    "family_meta_list",
    "load_all_families",
    "load_family",
    "load_samples",
    "load_techniques",
]
