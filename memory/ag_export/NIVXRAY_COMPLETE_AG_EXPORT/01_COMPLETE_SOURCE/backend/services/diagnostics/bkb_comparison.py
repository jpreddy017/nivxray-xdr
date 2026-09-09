"""
NivXRay · BKB Comparison Harness (P0.16 · Phase B)
────────────────────────────────────────────────────

Compares cluster MITRE attribution BEFORE (current production path
— DIE per-command techniques folded into cluster.mitre) vs AFTER
(canonical BKB projection — cluster.mitre = BKB.lookup(label)
canonical techniques) on the Vendor Corpus v1 fixtures.

This is intentionally READ-ONLY.  It does NOT switch the Workspace
projection.  It produces a report analysts can review to decide
whether the canonical projection is safe to enable in production.

Report shape (JSON):
    {
      "sprint":      "sprint-YYYYMMDD",
      "fixtures":    { fixture_id → { label → { old, new, removed, added, unchanged } } },
      "aggregate":   { removed_total, added_total, unchanged_total,
                          labels_affected, unknown_labels },
    }

Guarantees:
    · Deterministic.
    · Never mutates the case payload.
    · Runs the same acquisition + classification pipeline as
      production — only the cluster attribution step is swapped.
    · Reports are written to:
          corpus/vendor/v1/reports/bkb_projection_diff.json
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ══════════════════════════════════════════════════════════════════
# Attribution paths
# ══════════════════════════════════════════════════════════════════
def _old_cluster_mitre(commands, investigations) -> Dict[str, Set[str]]:
    """Reproduce the CURRENT production `_build_behavior_clusters`
    attribution logic — cluster techniques come from DIE
    per-command investigations, with a legacy purpose-bridge
    fallback."""
    from services.ice.correlate import (
        _mitre_from_purpose, _PURPOSE_TO_MITRE,   # noqa: F401 (bridge kept in sync via BKB)
    )
    groups: Dict[str, Set[str]] = {}
    for i, cmd in enumerate(commands):
        label = cmd.get("purpose") or "Uncategorised"
        s = groups.setdefault(label, set())
        ci = investigations[i] if i < len(investigations) else {}
        for t in (ci.get("techniques") or []):
            tid = (t.get("id") or "").upper()
            if tid:
                s.add(tid)
    # Legacy bridge fallback for empty clusters.
    for label, s in list(groups.items()):
        if not s:
            for m in _mitre_from_purpose(label):
                s.add(m["id"])
    return groups


def _new_cluster_mitre(commands, investigations) -> Tuple[Dict[str, Set[str]], Set[str]]:
    """Canonical BKB projection: cluster techniques come EXCLUSIVELY
    from ``BKB.lookup(label).canonical_techniques``.  Returns the
    per-label technique set + the set of labels that had no BKB
    entry (so callers can decide whether to warn / expand the BKB)."""
    from services.knowledge.behavior_registry import lookup
    groups: Dict[str, Set[str]] = {}
    unknown_labels: Set[str] = set()
    for cmd in commands:
        label = cmd.get("purpose") or "Uncategorised"
        s = groups.setdefault(label, set())
        spec = lookup(label)
        if spec:
            for t in spec.canonical_techniques:
                s.add(t["id"])
        else:
            unknown_labels.add(label)
    return groups, unknown_labels


# ══════════════════════════════════════════════════════════════════
# Corpus driver
# ══════════════════════════════════════════════════════════════════
def _pipeline_for_fixture(fixture) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Run acquisition (VEEE on) + IDA extraction on a corpus
    fixture and return (commands, investigations) exactly like
    production would."""
    from services.diagnostics.vendor_benchmark import (
        _render_screenshot, _fixture_html,
    )
    from services.veee import extract_from_image
    from services.ida.report_extractors import extract_all
    os.environ["NVX_VEEE_ENABLED"] = "1"
    html = _fixture_html(fixture.article_title, fixture.vendor, fixture.fixture_id)
    structured_blocks: List[str] = []
    for rec in extract_from_image(_render_screenshot(fixture.commands),
                                          image_url=f"https://vendor.example/{fixture.fixture_id}.png"):
        if rec.get("type") != "skipped" and rec.get("text"):
            structured_blocks.append(rec["text"])
    ext = extract_all("\n".join([html] + structured_blocks),
                            structured_blocks=structured_blocks)
    return (ext.get("commands") or []), (ext.get("command_investigations") or [])


def build_comparison(*, sprint: Optional[str] = None) -> Dict[str, Any]:
    """Run the comparison across every fixture and return the report."""
    from tests.test_p015c5_vendor_corpus_v1 import VENDOR_CORPUS_V1

    fixtures_report: Dict[str, Any] = {}
    total_removed:   int  = 0
    total_added:     int  = 0
    total_unchanged: int  = 0
    labels_affected: Set[str] = set()
    unknown_labels:  Set[str] = set()

    for fixture in VENDOR_CORPUS_V1:
        commands, investigations = _pipeline_for_fixture(fixture)
        old = _old_cluster_mitre(commands, investigations)
        new, unknown = _new_cluster_mitre(commands, investigations)
        unknown_labels |= unknown

        per_label: Dict[str, Any] = {}
        # Union of labels seen in either projection.
        for label in sorted(set(old.keys()) | set(new.keys())):
            old_set = old.get(label, set())
            new_set = new.get(label, set())
            removed = sorted(old_set - new_set)
            added   = sorted(new_set - old_set)
            unchanged = sorted(old_set & new_set)
            per_label[label] = {
                "old":       sorted(old_set),
                "new":       sorted(new_set),
                "removed":   removed,
                "added":     added,
                "unchanged": unchanged,
            }
            total_removed   += len(removed)
            total_added     += len(added)
            total_unchanged += len(unchanged)
            if removed or added:
                labels_affected.add(label)

        fixtures_report[fixture.fixture_id] = per_label

    sprint = sprint or ("sprint-" +
                              datetime.now(timezone.utc).strftime("%Y%m%d"))
    return {
        "schema_version": "1.0",
        "sprint":         sprint,
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "aggregate": {
            "removed_total":   total_removed,
            "added_total":     total_added,
            "unchanged_total": total_unchanged,
            "labels_affected": sorted(labels_affected),
            "unknown_labels":  sorted(unknown_labels),
        },
        "fixtures":       fixtures_report,
    }


def persist_comparison(report: Dict[str, Any]) -> Path:
    root = (Path(__file__).resolve().parent.parent.parent
                / "corpus" / "vendor" / "v1" / "reports")
    root.mkdir(parents=True, exist_ok=True)
    path = root / "bkb_projection_diff.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True))
    return path


__all__ = ["build_comparison", "persist_comparison",
                "_old_cluster_mitre", "_new_cluster_mitre"]
