"""
NivXRay MITRE ATT&CK Enterprise Catalogue service.

Owner rules — strictly enforced:

  1. **Catalogue is the projection of a versioned ATT&CK STIX
     bundle.**  The compact catalogue file
     `/app/backend/mitre_catalogue/enterprise_v16_1.compact.json`
     is generated from the official MITRE STIX bundle at tag
     ATT&CK-v16.1 (see `build_catalogue.py`).  No hand-authored
     technique lists live in code any more.

  2. **Catalogue presence ≠ detection coverage.**  Every
     technique / sub-technique starts life at coverage state
     `NO_EVIDENCE`.  Only a real observation in
     `AttackTechniqueEvidence` — i.e. a NivXRay
     detection-backed row — can move it to `OBSERVED`.

  3. **Aggregate parent counts NEVER fabricate child
     observations.**  A parent technique's `observed_count` is
     the sum of the parent's own direct observations and the
     union of its observed sub-techniques' `observed_count`s.
     The parent's coverage state is `OBSERVED` iff any of
     (parent, sub) has ≥1 observation.  Sub-techniques with no
     evidence remain `NO_EVIDENCE` regardless of the parent.

  4. **No confidence, no risk score.**  This service surfaces
     counts + coverage state only.  Confidence and risk live in
     `AttackTechniqueEvidence`; this layer does not remix them.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Iterable


CATALOGUE_PATH = (
    pathlib.Path(__file__).parents[2]
    / "mitre_catalogue" / "enterprise_v16_1.compact.json"
)
NAME_INDEX_PATH = (
    pathlib.Path(__file__).parents[2]
    / "mitre_catalogue" / "name_index.json"
)


class CoverageState(str, Enum):
    NO_EVIDENCE = "NO_EVIDENCE"
    OBSERVED    = "OBSERVED"


@dataclass(frozen=True)
class MitreCatalogue:
    version: str
    source: str
    generated_at: str
    tactics: list[dict[str, Any]]
    techniques: list[dict[str, Any]]
    stats: dict[str, int]

    # Derived, populated in `_index`.
    _by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    _children_of: dict[str, list[str]] = field(default_factory=dict)
    _name_to_id: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: pathlib.Path = CATALOGUE_PATH) -> "MitreCatalogue":
        raw = json.loads(path.read_text())
        techniques = list(raw.get("techniques") or [])
        by_id = {t["external_id"]: t for t in techniques}
        children: dict[str, list[str]] = {}
        for t in techniques:
            parent = t.get("parent_id")
            if parent:
                children.setdefault(parent, []).append(t["external_id"])
        for kids in children.values():
            kids.sort()
        # Load the generated name index if present.  If not, the
        # coverage projection still works — callers just lose the
        # name-fallback resolution.
        name_to_id: dict[str, str] = {}
        if NAME_INDEX_PATH.exists():
            n_raw = json.loads(NAME_INDEX_PATH.read_text())
            name_to_id = dict(n_raw.get("name_to_external_id") or {})
        return cls(
            version=raw["version"],
            source=raw["source"],
            generated_at=raw["generated_at"],
            tactics=list(raw.get("tactics") or []),
            techniques=techniques,
            stats=dict(raw.get("stats") or {}),
            _by_id=by_id,
            _children_of=children,
            _name_to_id=name_to_id,
        )

    # ------- read helpers ---------------------------------------

    def technique(self, ext_id: str) -> dict[str, Any] | None:
        return self._by_id.get(ext_id)

    def children(self, parent_id: str) -> list[dict[str, Any]]:
        return [self._by_id[c] for c in self._children_of.get(parent_id, [])]

    def parents(self) -> list[dict[str, Any]]:
        return [t for t in self.techniques if not t.get("is_sub")]

    def sub_techniques(self) -> list[dict[str, Any]]:
        return [t for t in self.techniques if t.get("is_sub")]

    def resolve_name(self, name: str) -> str | None:
        """Map a technique NAME to its canonical external id, or
        None when the name is not published in the catalogue.
        Case-insensitive; whitespace-collapsed."""
        if not name:
            return None
        key = " ".join(str(name).split()).upper()
        if key in self._name_to_id:
            return self._name_to_id[key]
        # Try stripping a leading "Parent: " prefix.
        if ":" in key:
            tail = key.split(":", 1)[1].strip()
            if tail in self._name_to_id:
                return self._name_to_id[tail]
        return None


@lru_cache(maxsize=1)
def get_catalogue() -> MitreCatalogue:
    """Cached singleton — the catalogue is versioned and immutable."""
    return MitreCatalogue.load()


# --------------------------------------------------------------------
# Coverage resolver.
#
# `observations` is a mapping `external_id -> observed_count`, derived
# by the caller from AttackTechniqueEvidence (the SSOT).  The resolver
# joins those honest counts onto the catalogue hierarchy and returns
# a heatmap-ready projection: tactic → parents → sub-techniques with
# `observed_count`, `aggregate_count` and `coverage_state`.
# --------------------------------------------------------------------
def resolve_coverage(
    observations: dict[str, int],
    catalogue: MitreCatalogue | None = None,
) -> dict[str, Any]:
    """Return a full ATT&CK Enterprise coverage projection.

    `observations` may include either `T####` or `T####.###` keys.
    Missing keys are treated as zero — never as a fabricated count.
    """
    cat = catalogue or get_catalogue()

    def _state(count: int) -> CoverageState:
        return CoverageState.OBSERVED if count > 0 else CoverageState.NO_EVIDENCE

    # Project every technique.
    parents_out: dict[str, dict[str, Any]] = {}
    for parent in cat.parents():
        pid   = parent["external_id"]
        direct_count = int(observations.get(pid, 0) or 0)
        sub_rows: list[dict[str, Any]] = []
        agg = direct_count
        observed_sub_count = 0
        for child in cat.children(pid):
            cid = child["external_id"]
            child_count = int(observations.get(cid, 0) or 0)
            if child_count > 0:
                observed_sub_count += 1
            agg += child_count
            sub_rows.append({
                "external_id":    cid,
                "name":           child["name"],
                "url":            child.get("url"),
                "tactics":        list(child.get("tactics") or []),
                "platforms":      list(child.get("platforms") or []),
                "observed_count": child_count,
                "coverage_state": _state(child_count).value,
                "is_sub":         True,
                "parent_id":      pid,
            })
        parents_out[pid] = {
            "external_id":        pid,
            "name":               parent["name"],
            "url":                parent.get("url"),
            "tactics":            list(parent.get("tactics") or []),
            "platforms":          list(parent.get("platforms") or []),
            "observed_count":     direct_count,   # parent's own evidence rows
            "aggregate_count":    agg,            # parent + all subs
            "observed_sub_count": observed_sub_count,
            "sub_total":          len(sub_rows),
            "coverage_state":     _state(agg).value,
            "is_sub":             False,
            "parent_id":          None,
            "subs":               sub_rows,
        }

    # Group by tactic.
    tactic_rows: list[dict[str, Any]] = []
    for tac in cat.tactics:
        tid = tac["shortname"]
        techniques_in_tactic = [
            p for p in parents_out.values()
            if tid in (p["tactics"] or [])
        ]
        techniques_in_tactic.sort(key=lambda r: r["external_id"])

        parent_total          = len(techniques_in_tactic)
        parent_observed       = sum(1 for p in techniques_in_tactic
                                     if p["coverage_state"] == CoverageState.OBSERVED.value)
        sub_total             = sum(p["sub_total"] for p in techniques_in_tactic)
        sub_observed          = sum(p["observed_sub_count"] for p in techniques_in_tactic)
        aggregate_detections  = sum(p["aggregate_count"] for p in techniques_in_tactic)

        tactic_rows.append({
            "shortname":            tid,
            "name":                 tac.get("name"),
            "url":                  tac.get("url"),
            "parent_total":         parent_total,
            "parent_observed":      parent_observed,
            "sub_total":            sub_total,
            "sub_observed":         sub_observed,
            "aggregate_detections": aggregate_detections,
            "techniques":           techniques_in_tactic,
        })

    # Enterprise-wide totals.
    all_parents          = list(parents_out.values())
    total_parents        = len(all_parents)
    observed_parents     = sum(1 for p in all_parents
                                 if p["coverage_state"] == CoverageState.OBSERVED.value)
    total_subs           = sum(p["sub_total"] for p in all_parents)
    observed_subs        = sum(p["observed_sub_count"] for p in all_parents)
    aggregate_detections = sum(p["aggregate_count"] for p in all_parents)

    return {
        "catalogue_version": cat.version,
        "catalogue_source":  cat.source,
        "generated_at":      cat.generated_at,
        "totals": {
            # Catalogue coverage — how many rows exist.
            "tactics":                len(cat.tactics),
            "techniques":             total_parents,
            "sub_techniques":         total_subs,
            # Detection coverage — how many rows have real evidence.
            "techniques_observed":    observed_parents,
            "sub_techniques_observed": observed_subs,
            "aggregate_detections":   aggregate_detections,
        },
        "tactics": tactic_rows,
    }


def coalesce_observations(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Helper for callers that hand us AttackTechniqueEvidence rows.

    Accepts any iterable of dicts with an `external_id` / `attack_id`
    / `technique_id` / `id` field.  Non-canonical values are IGNORED
    (we do not name-map here — the resolver deals only in canonical
    ATT&CK ids).  Rows with a `count` field contribute that count;
    otherwise each row counts as one observation.
    """
    import re
    ATTACK_RE = re.compile(r"\b(T\d{4})(?:\.(\d{3}))?\b")
    out: dict[str, int] = {}
    for r in rows or []:
        cand = (
            r.get("external_id") or r.get("attack_id")
            or r.get("technique_id") or r.get("id") or ""
        )
        m = ATTACK_RE.search(str(cand))
        if not m:
            continue
        ext = m.group(1)
        if m.group(2):
            ext = f"{ext}.{m.group(2)}"
        inc = int(r.get("count") or 1)
        out[ext] = out.get(ext, 0) + inc
    return out
