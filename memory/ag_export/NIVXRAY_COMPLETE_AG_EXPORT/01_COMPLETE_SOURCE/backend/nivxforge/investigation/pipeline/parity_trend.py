"""Parity Trend Ledger — append-only structured history.

Owner directive (2026-02-XX): parity should be tracked over time with
more than a single percentage. Each run emits one JSONL row capturing:

  · timestamp (ISO 8601 UTC)
  · git_sha (short) — best-effort; empty when unavailable
  · fixtures_count
  · matches / new_mappings / lost_mappings / value_mismatches / ambiguous
  · overall_parity (mean parity rate across fixtures)
  · mean_confidence_drift
  · per_category (counts by GapCategory)
  · note (optional architectural change label passed by caller)

Persisted to ``tests/investigation/parity_trend.jsonl``. Append-only —
never rewritten, never rotated. Old runs stay for trend analysis.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .cem_parity import ParityReport


LEDGER_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tests" / "investigation" / "parity_trend.jsonl"
)


@dataclass(frozen=True)
class TrendEntry:
    timestamp: str
    git_sha: str
    fixtures_count: int
    matches: int
    new_mappings: int
    lost_mappings: int
    value_mismatches: int
    ambiguous: int
    overall_parity: float
    mean_confidence_drift: float
    per_category: Dict[str, int]
    note: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps({
            "timestamp": self.timestamp,
            "git_sha": self.git_sha,
            "fixtures_count": self.fixtures_count,
            "matches": self.matches,
            "new_mappings": self.new_mappings,
            "lost_mappings": self.lost_mappings,
            "value_mismatches": self.value_mismatches,
            "ambiguous": self.ambiguous,
            "overall_parity": round(self.overall_parity, 4),
            "mean_confidence_drift": round(self.mean_confidence_drift, 4),
            "per_category": self.per_category,
            "note": self.note,
        }, separators=(",", ":"))


def build_trend_entry(reports: List[ParityReport],
                       *,
                       note: Optional[str] = None,
                       ) -> TrendEntry:
    """Aggregate a ParityReport list into a TrendEntry."""
    matches = sum(r.matches for r in reports)
    new_mappings = sum(r.new_mappings for r in reports)
    lost_mappings = sum(r.lost_mappings for r in reports)
    value_mismatches = sum(r.value_mismatches for r in reports)
    ambiguous = sum(r.ambiguous for r in reports)
    overall_parity = (sum(r.parity_rate for r in reports) / len(reports)
                      if reports else 0.0)
    drift = (sum(r.confidence_drift for r in reports) / len(reports)
             if reports else 0.0)

    per_category: Dict[str, int] = {}
    for r in reports:
        for d in r.field_deltas:
            if d.kind == "match" or d.gap_category is None:
                continue
            per_category[d.gap_category] = (
                per_category.get(d.gap_category, 0) + 1
            )

    return TrendEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        git_sha=_git_sha(),
        fixtures_count=len(reports),
        matches=matches,
        new_mappings=new_mappings,
        lost_mappings=lost_mappings,
        value_mismatches=value_mismatches,
        ambiguous=ambiguous,
        overall_parity=overall_parity,
        mean_confidence_drift=drift,
        per_category=per_category,
        note=note,
    )


def append_entry(entry: TrendEntry,
                  ledger_path: pathlib.Path = LEDGER_PATH) -> None:
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    with ledger_path.open("a", encoding="utf-8") as f:
        f.write(entry.to_json() + "\n")


def read_entries(ledger_path: pathlib.Path = LEDGER_PATH
                 ) -> List[Dict]:
    if not ledger_path.exists():
        return []
    out: List[Dict] = []
    for line in ledger_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # Skip malformed rows silently — the ledger is a
            # convenience artifact, not a schema-strict store.
            continue
    return out


def render_trend_markdown(entries: List[Dict], *, tail: int = 8) -> str:
    """Render the last ``tail`` runs as a compact Markdown table."""
    if not entries:
        return "_No parity runs recorded yet._"
    rows = entries[-tail:]
    lines: List[str] = []
    lines.append("| Time (UTC) | git | Fixtures | Parity | Drift | Matches | Lost | Categories | Note |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        cats = ", ".join(f"{k}:{v}" for k, v in
                          sorted(r.get("per_category", {}).items()))
        lines.append(
            f"| {r['timestamp'][:19].replace('T', ' ')} "
            f"| `{(r.get('git_sha') or '—')[:7]}` "
            f"| {r['fixtures_count']} "
            f"| **{r['overall_parity']:.1%}** "
            f"| {r['mean_confidence_drift']:+.3f} "
            f"| {r['matches']} "
            f"| {r['lost_mappings']} "
            f"| {cats or '—'} "
            f"| {(r.get('note') or '').strip() or '—'} |"
        )
    return "\n".join(lines)


def _git_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=2,
            cwd=str(pathlib.Path(__file__).resolve().parents[3]),
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired,
            subprocess.SubprocessError):
        pass
    return ""


__all__ = [
    "LEDGER_PATH",
    "TrendEntry",
    "build_trend_entry",
    "append_entry",
    "read_entries",
    "render_trend_markdown",
]
