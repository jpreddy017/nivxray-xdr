"""RC5 · Phase 9.5c · Golden Corpus PR Delta Reporter.

CI helper that compares the current Golden Corpus + regression metrics
against a **base** run (typically the base branch's saved JSON) and
prints a Markdown delta report. Deterministic. No I/O other than
reading two local JSON files.

Usage:
    python scripts/golden_delta.py \
        --base   base_run.json \
        --head   head_run.json \
        --out    delta.md

If ``--base`` is omitted or the file doesn't exist, the report is
emitted as "first run — no baseline" and exits 0.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


# --------------------------------------------------------------------------
# Data extraction — schema-tolerant so old base runs don't break the report.
# --------------------------------------------------------------------------
def _load(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _sample_map(run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {s.get("sample_id", f"?_{i}"): s
            for i, s in enumerate(run.get("samples", []))}


def _techniques(run: Dict[str, Any]) -> set:
    """Union of all MITRE techniques asserted across samples in a run."""
    out: set = set()
    for s in run.get("samples", []):
        # Corpus doesn't store per-sample techniques in the report itself;
        # rely on ``expected_mitre`` if a future schema adds it. For now,
        # coverage is derived from accuracy.mitre percentage.
        pass
    return out


# --------------------------------------------------------------------------
# Delta computation
# --------------------------------------------------------------------------
def _delta(base_val, head_val, fmt: str = "%.2f") -> str:
    if base_val is None:
        return f"{fmt % head_val} (baseline)" if head_val is not None else "n/a"
    if head_val is None:
        return "n/a"
    try:
        diff = float(head_val) - float(base_val)
        sign = "+" if diff > 0 else ""
        arrow = "🔺" if diff > 0 else ("🔻" if diff < 0 else "▪")
        return f"{fmt % head_val} ({sign}{fmt % diff}) {arrow}"
    except (TypeError, ValueError):
        return str(head_val)


def _int_delta(base_val, head_val) -> str:
    if base_val is None:
        return f"{head_val} (baseline)"
    diff = int(head_val or 0) - int(base_val or 0)
    if diff > 0:
        return f"{head_val} (+{diff}) 🔺"
    if diff < 0:
        return f"{head_val} ({diff}) 🔻"
    return f"{head_val} (=)"


def build_report(head: Dict[str, Any],
                 base: Optional[Dict[str, Any]] = None) -> str:
    lines: List[str] = []
    lines.append("## RC5 Golden Corpus · PR Delta Report\n")
    if base is None:
        lines.append("_No base run supplied — treating this as the initial baseline._\n")

    head_pass = head.get("pass_rate", 0.0)
    head_total = head.get("total", 0)
    head_ok = head.get("passed", 0)
    head_regr = head.get("regression_count", 0)
    head_cov = head.get("coverage", {}) or {}
    head_acc = head.get("accuracy", {}) or {}

    base_pass = base.get("pass_rate", 0.0) if base else None
    base_regr = base.get("regression_count", 0) if base else None
    base_cov = base.get("coverage", {}) if base else {}
    base_acc = base.get("accuracy", {}) if base else {}

    # Headline gate.
    lines.append("### Gate summary\n")
    lines.append(f"- **Pass rate:** {_delta(base_pass, head_pass)} ({head_ok}/{head_total})")
    lines.append(f"- **Regression count:** {_int_delta(base_regr, head_regr)}")
    lines.append("")

    # Coverage table.
    lines.append("### Stage coverage (% of samples with confidence ≥ 70)\n")
    lines.append("| Stage | Base | Head |")
    lines.append("|---|---|---|")
    for stage in ("decode", "semantic", "behavior", "mitre", "verdict"):
        lines.append(f"| {stage} | {base_cov.get(stage, 'n/a')} | "
                     f"{_delta(base_cov.get(stage), head_cov.get(stage))} |")
    lines.append("")

    # Accuracy table.
    lines.append("### Detector accuracy\n")
    lines.append("| Detector | Base | Head |")
    lines.append("|---|---|---|")
    for k in ("verdict", "mitre", "lolbin", "behavior", "overall_pass_rate"):
        lines.append(f"| {k} | {base_acc.get(k, 'n/a')} | "
                     f"{_delta(base_acc.get(k), head_acc.get(k))} |")
    lines.append("")

    # Latency table (Phase 9.5c+).
    head_lat = head.get("latency", {}) or {}
    base_lat = base.get("latency", {}) if base else {}
    if head_lat:
        lines.append("### Pipeline latency (ms per sample)\n")
        lines.append("| Metric | Base | Head |")
        lines.append("|---|---|---|")
        for k in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "max_ms", "total_ms"):
            lines.append(f"| {k} | {base_lat.get(k, 'n/a')} | "
                         f"{_delta(base_lat.get(k), head_lat.get(k), fmt='%.3f')} |")
        lines.append("")

    # Per-category coverage (Phase 9.5d+).
    head_cat = head.get("category_coverage", {}) or {}
    base_cat = (base.get("category_coverage", {}) if base else {}) or {}
    if head_cat:
        lines.append("### Per-category coverage (pass rate by taxonomy)\n")
        lines.append("| Category | Base | Head | Samples |")
        lines.append("|---|---|---|---|")
        for cat in sorted(head_cat.keys()):
            hd = head_cat[cat] or {}
            bd = base_cat.get(cat) or {}
            samples = f"{hd.get('passed', 0)}/{hd.get('total', 0)}"
            lines.append(
                f"| {cat} | {bd.get('pass_rate', 'n/a')} | "
                f"{_delta(bd.get('pass_rate'), hd.get('pass_rate'))} | {samples} |"
            )
        lines.append("")

    # Newly failing / newly supported.
    newly_failing = head.get("newly_failing") or []
    newly_supported = head.get("newly_supported") or []
    if newly_failing:
        lines.append("### ❌ Newly failing samples")
        for s in newly_failing:
            lines.append(f"- `{s}`")
        lines.append("")
    if newly_supported:
        lines.append("### ✅ Newly supported samples")
        for s in newly_supported:
            lines.append(f"- `{s}`")
        lines.append("")

    # Sample-level deltas (per-sample verdict / accuracy flip).
    if base is not None:
        base_samples = _sample_map(base)
        head_samples = _sample_map(head)
        flipped: List[str] = []
        for sid, hs in head_samples.items():
            bs = base_samples.get(sid)
            if not bs:
                flipped.append(f"➕ `{sid}` — **new sample** · verdict={hs.get('got_verdict')} · pass={hs.get('passed')}")
                continue
            if bool(bs.get("passed")) != bool(hs.get("passed")):
                arrow = "PASS→FAIL 🔴" if bs.get("passed") else "FAIL→PASS 🟢"
                flipped.append(f"- `{sid}` · {arrow} · verdict {bs.get('got_verdict')} → {hs.get('got_verdict')}")
            elif bs.get("got_verdict") != hs.get("got_verdict"):
                flipped.append(f"- `{sid}` · verdict shift {bs.get('got_verdict')} → {hs.get('got_verdict')}")
        removed = sorted(set(base_samples) - set(head_samples))
        for sid in removed:
            flipped.append(f"➖ `{sid}` — removed from corpus")
        if flipped:
            lines.append("### Per-sample deltas")
            lines.extend(flipped)
            lines.append("")

    # Fail-fast bullet.
    lines.append("### Enforcement")
    if head_pass < 95.0:
        lines.append(f"- ❌ **BLOCK** — head pass_rate {head_pass}% < 95% floor.")
    elif head_regr > 0:
        lines.append(f"- ❌ **BLOCK** — {head_regr} regression(s) introduced.")
    else:
        lines.append("- ✅ **PASS** — pass_rate ≥ 95% and zero regressions.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _emit_run_json() -> Dict[str, Any]:
    """Run the corpus in-process and return its JSON-safe dict."""
    os.environ.setdefault("SEMANTIC_ENGINE_V2", "true")
    # Ensure the backend package is importable when this script is run
    # directly from /app/backend (CI does this).
    _backend_dir = Path(__file__).resolve().parent.parent
    if str(_backend_dir) not in sys.path:
        sys.path.insert(0, str(_backend_dir))
    from engine.golden_corpus import run_corpus
    r = run_corpus()
    return json.loads(r.model_dump_json())


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="RC5 Golden Corpus PR delta reporter (deterministic, no I/O)."
    )
    ap.add_argument("--base", type=Path, default=None,
                    help="Base-branch run JSON (optional).")
    ap.add_argument("--head", type=Path, default=None,
                    help="Head run JSON. If omitted, runs the corpus in-process.")
    ap.add_argument("--out",  type=Path, required=True,
                    help="Path to write Markdown delta report.")
    ap.add_argument("--emit-head-json", type=Path, default=None,
                    help="If set, write the freshly-run head JSON here (only "
                         "used when --head is omitted).")
    args = ap.parse_args(argv)

    if args.head is None:
        head = _emit_run_json()
        if args.emit_head_json:
            args.emit_head_json.write_text(json.dumps(head, default=str),
                                           encoding="utf-8")
    else:
        head = _load(args.head)
        if head is None:
            print(f"::error::--head file not readable: {args.head}", file=sys.stderr)
            return 2

    base = _load(args.base) if args.base else None
    report = build_report(head, base)
    args.out.write_text(report, encoding="utf-8")
    print(report)

    # Exit code drives the gate.
    if head.get("pass_rate", 0.0) < 95.0:
        return 1
    if int(head.get("regression_count") or 0) > 0:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
