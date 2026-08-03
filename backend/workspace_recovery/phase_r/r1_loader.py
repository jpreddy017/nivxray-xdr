"""
Phase R1 loader — reads family JSON packs under ``phase_r/families/``.

Design contract
---------------
* Every family lives in a single ``families/<family_id>.json`` file.
* Every sample carries a stable ``id`` unique across the entire R1
  corpus (family_id is embedded via the enclosing file).
* Loader returns a flat list; each sample is enriched with ``family_id``.
* Fingerprint fields live in ``expected.fingerprint`` and are populated
  by :mod:`workspace_recovery.phase_r.r1_fingerprint_generator`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

FAMILIES_DIR = Path(__file__).resolve().parent / "families"


@dataclass(frozen=True)
class FamilyMeta:
    family_id: str
    display_name: str
    version: str
    sample_count: int


def _families_on_disk() -> list[Path]:
    return sorted(FAMILIES_DIR.glob("*.json"))


def load_family(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def load_all_families() -> list[dict[str, Any]]:
    return [load_family(p) for p in _families_on_disk()]


def load_samples(families: Iterable[str] | None = None) -> list[dict[str, Any]]:
    """Return every R1 sample as a flat list, tagged with ``family_id``.

    Parameters
    ----------
    families:
        Optional iterable of family_ids to include. ``None`` means "all".
    """
    wanted = set(families) if families is not None else None
    out: list[dict[str, Any]] = []
    for fam in load_all_families():
        fid = fam.get("family_id", "unknown")
        if wanted is not None and fid not in wanted:
            continue
        for sample in fam.get("samples", []) or []:
            enriched = dict(sample)
            enriched["family_id"] = fid
            out.append(enriched)
    return out


def family_meta_list() -> list[FamilyMeta]:
    metas: list[FamilyMeta] = []
    for fam in load_all_families():
        metas.append(
            FamilyMeta(
                family_id=fam.get("family_id", "unknown"),
                display_name=fam.get("family_display_name", ""),
                version=fam.get("family_version", ""),
                sample_count=len(fam.get("samples", []) or []),
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
]
