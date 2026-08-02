"""
Phase 3 · Deterministic A/B runner between the Certified Workspace Baseline
(v1.5.6 · fff5897) and the current HEAD.

For every sample in corpus.json:
  1. Invoke /api/decode/smart on BOTH trees via isolated subprocess workers.
  2. Compare the full response.
  3. Emit a first-divergence stage trace where they differ.
  4. Write:
        artifacts/baseline_raw.json  — full responses from v1.5.6
        artifacts/current_raw.json   — full responses from HEAD
        artifacts/phase3_ab_matrix.json — normalized per-sample diff
        phase3_ab_report.md          — human-readable comparison table
                                       + per-sample stage trace

The runner performs ZERO writes to /app/backend/routers/ops.py, engine/, v2/,
timeline/, or nivxforge/. It only reads. This is Phase 3 evidence.
"""
import json
import subprocess
import sys
from pathlib import Path

from workspace_recovery.corpus_loader import (
    category_stats,
    format_category_stats,
    load_meta,
    load_samples,
)

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True)

BASELINE = Path("/tmp/workspace-v1.5.6/backend")
CURRENT = Path("/app/backend")
CORPUS = ROOT / "corpus.json"

# Stages of the Decode Pipeline in canonical order (from PRD.md §Two-Layer
# Model). We use these labels to structure the first-divergence report.
CANONICAL_STAGES = [
    "input",
    "interpreter",
    "decoder_chain",
    "stage_order",
    "transformation_trace",
    "intermediate_payloads",
    "final_output",
    "runtime_reconstruction",
    "iocs",
    "verdict_inputs",
]


def _run_tree(backend_dir: Path, tag: str) -> dict:
    """Invoke the worker in a subprocess so each tree lives in its own sys.path."""
    env = {
        # PYTHONPATH points at the target tree so `from server import app`
        # resolves inside that tree, not /app/backend.
        "PYTHONPATH": str(backend_dir),
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cmd = [
        sys.executable, "-m", "workspace_recovery.tree_worker",
        str(backend_dir), str(CORPUS),
    ]
    # We must run from /app/backend so `-m workspace_recovery.tree_worker`
    # resolves. The worker itself then chdirs into `backend_dir`.
    proc = subprocess.run(
        cmd, capture_output=True, text=True, cwd="/app/backend",
        env={**env, "PYTHONPATH": "/app/backend"}, timeout=180,
    )
    if proc.returncode != 0:
        return {
            "tree": tag,
            "fatal": True,
            "stderr": proc.stderr[-4000:],
            "stdout": proc.stdout[-2000:],
            "returncode": proc.returncode,
        }
    # Worker prints the JSON as the last line.
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    for line in reversed(lines):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"tree": tag, "fatal": True, "reason": "no_json", "stdout": proc.stdout[-2000:], "stderr": proc.stderr[-2000:]}


def _extract_stages(resp: dict) -> dict:
    """Normalize a decode/smart response into canonical stage buckets."""
    if not isinstance(resp, dict):
        return {"input": None, "final_output": None}
    # trace is a list of {op, in, out, reason}
    trace = resp.get("trace") or resp.get("steps_output") or []
    ops = [t.get("op") for t in trace if isinstance(t, dict)]
    # interpreter: derive from the first op that mentions ps / cmd / bash,
    # else from atomic guard / detected_type
    interpreter = None
    for op in ops:
        if not op:
            continue
        low = op.lower()
        if "powershell" in low or low.startswith("ps-"):
            interpreter = "powershell"
            break
        if "cmd-" in low or low.startswith("cmd-"):
            interpreter = "cmd"
            break
        if "bash" in low:
            interpreter = "bash"
            break
    detected = resp.get("detected_type") or {}
    if not interpreter and isinstance(detected, dict):
        interpreter = detected.get("kind") or detected.get("interpreter")
    return {
        "input": resp.get("input"),
        "interpreter": interpreter,
        "decoder_chain": ops,
        "stage_order": ops,  # ops = ordered = de-facto stage order
        "transformation_trace": trace,
        "intermediate_payloads": [t.get("out") for t in trace if isinstance(t, dict)],
        "final_output": resp.get("output"),
        "runtime_reconstruction": resp.get("runtime_reconstruction") or resp.get("runtime"),
        "iocs": resp.get("iocs") or (resp.get("investigation") or {}).get("iocs") if isinstance(resp.get("investigation"), dict) else resp.get("iocs"),
        "verdict_inputs": resp.get("verdict") or resp.get("confidence") or resp.get("verdict_card"),
        "atomic_ioc": resp.get("atomic_ioc"),
    }


def _first_divergence(baseline: dict, current: dict) -> dict:
    """Walk canonical stages in order, return the first that differs."""
    b = _extract_stages(baseline)
    c = _extract_stages(current)
    for stage in CANONICAL_STAGES:
        if b.get(stage) != c.get(stage):
            return {
                "stage": stage,
                "baseline": b.get(stage),
                "current": c.get(stage),
                "all_baseline_stages": b,
                "all_current_stages": c,
            }
    return {"stage": None, "identical": True, "all_baseline_stages": b, "all_current_stages": c}


def _summarise(divergence: dict) -> str:
    """Short human string describing where the two trees first differed."""
    if divergence.get("identical"):
        return "identical"
    stage = divergence["stage"]
    b = divergence["baseline"]
    c = divergence["current"]
    if stage in ("decoder_chain", "stage_order"):
        # Show the first index where the op-list diverges.
        b_list = b or []
        c_list = c or []
        i = 0
        while i < min(len(b_list), len(c_list)) and b_list[i] == c_list[i]:
            i += 1
        if i >= len(b_list):
            return f"{stage}: CURRENT has extra op '{c_list[i] if i < len(c_list) else '?'}' at index {i}"
        if i >= len(c_list):
            return f"{stage}: CURRENT missing op '{b_list[i]}' at index {i}"
        return f"{stage}: at index {i} baseline='{b_list[i]}' current='{c_list[i]}'"
    if stage == "final_output":
        return f"final_output differs (baseline len={len(str(b or ''))}, current len={len(str(c or ''))})"
    return f"{stage} differs"


def main() -> int:
    print("[phase3] running baseline (v1.5.6) worker...")
    baseline_raw = _run_tree(BASELINE, "baseline_v1.5.6")
    (ART / "baseline_raw.json").write_text(json.dumps(baseline_raw, indent=2, default=str))
    if baseline_raw.get("fatal"):
        print("[phase3] baseline boot FAILED — see artifacts/baseline_raw.json")

    print("[phase3] running current (HEAD) worker...")
    current_raw = _run_tree(CURRENT, "current_head")
    (ART / "current_raw.json").write_text(json.dumps(current_raw, indent=2, default=str))
    if current_raw.get("fatal"):
        print("[phase3] current boot FAILED — see artifacts/current_raw.json")

    if baseline_raw.get("fatal") or current_raw.get("fatal"):
        return 2

    corpus_meta = load_meta(CORPUS)
    samples = load_samples(CORPUS)
    baseline_by_id = {r["id"]: r for r in baseline_raw["results"]}
    current_by_id = {r["id"]: r for r in current_raw["results"]}

    matrix = []
    for s in samples:
        sid = s["id"]
        b = baseline_by_id.get(sid, {})
        c = current_by_id.get(sid, {})
        b_resp = b.get("response") or {}
        c_resp = c.get("response") or {}
        div = _first_divergence(b_resp, c_resp)
        matrix.append({
            "id": sid,
            "family": s["family"],
            "category": s.get("category", "uncategorized"),
            "baseline_status": b.get("status"),
            "current_status": c.get("status"),
            "baseline_http": b.get("http_status"),
            "current_http": c.get("http_status"),
            "identical": bool(div.get("identical")),
            "first_divergence_stage": div.get("stage"),
            "first_divergence_summary": _summarise(div),
            "baseline_ops": (div.get("all_baseline_stages") or {}).get("decoder_chain"),
            "current_ops": (div.get("all_current_stages") or {}).get("decoder_chain"),
            "baseline_interpreter": (div.get("all_baseline_stages") or {}).get("interpreter"),
            "current_interpreter": (div.get("all_current_stages") or {}).get("interpreter"),
            "baseline_final": (div.get("all_baseline_stages") or {}).get("final_output"),
            "current_final": (div.get("all_current_stages") or {}).get("final_output"),
            "expected": s.get("expected"),
        })

    (ART / "phase3_ab_matrix.json").write_text(json.dumps(matrix, indent=2, default=str))
    _emit_report(matrix, corpus_meta.version)
    return 0


def _emit_report(matrix: list, corpus_version: str) -> None:
    # Per-category stats — publishes what the owner asked for:
    # PowerShell N/N · CMD N/N · Bash N/N · Mixed N/N · Overall N/N.
    # We treat "current" pass as (status==ok, http==200, identical to baseline).
    current_pass_by_id = {
        m["id"]: (m["current_status"] == "ok" and m["current_http"] == 200 and m["identical"])
        for m in matrix
    }
    baseline_pass_by_id = {
        m["id"]: (m["baseline_status"] == "ok" and m["baseline_http"] == 200)
        for m in matrix
    }
    stats_current = category_stats(current_pass_by_id)
    stats_baseline = category_stats(baseline_pass_by_id)

    lines = []
    lines.append("# Phase 3 · Behavioral A/B Report")
    lines.append("")
    lines.append(f"Corpus version: **{corpus_version}**")
    lines.append("Baseline tree : `/tmp/workspace-v1.5.6/backend/` (git `fff5897`, Jul 28 16:10 UTC)")
    lines.append("Current tree  : `/app/backend/` (HEAD)")
    lines.append("")
    lines.append("**No files were restored, forked, or wired during this phase.** This report")
    lines.append("is pure runtime evidence produced by invoking `/api/decode/smart` on both trees.")
    lines.append("")
    lines.append("## Per-Category Certification Metrics")
    lines.append("")
    lines.append("```")
    lines.append("Baseline (v1.5.6):")
    lines.append(format_category_stats(stats_baseline))
    lines.append("")
    lines.append("Current  (HEAD):")
    lines.append(format_category_stats(stats_current))
    lines.append("```")
    lines.append("")
    lines.append("## Comparison Table")
    lines.append("")
    lines.append("| # | Sample | Category | v1.5.6 | Current | Same? | First Divergence |")
    lines.append("|---|--------|----------|:------:|:-------:|:-----:|------------------|")
    for i, m in enumerate(matrix, 1):
        b_mark = "PASS" if m["baseline_status"] == "ok" and m["baseline_http"] == 200 else f"{m['baseline_status']}/{m['baseline_http']}"
        c_mark = "PASS" if m["current_status"] == "ok" and m["current_http"] == 200 else f"{m['current_status']}/{m['current_http']}"
        same = "PASS" if m["identical"] else "FAIL"
        first = m["first_divergence_summary"]
        lines.append(f"| {i} | `{m['id']}` — {m['family']} | {m.get('category','?')} | {b_mark} | {c_mark} | {same} | {first} |")
    lines.append("")
    lines.append("## Per-Sample Stage Trace (❌ rows only)")
    lines.append("")
    for m in matrix:
        if m["identical"]:
            continue
        lines.append(f"### `{m['id']}` — {m['family']}")
        lines.append("")
        lines.append(f"- **First divergent stage:** `{m['first_divergence_stage']}`")
        lines.append(f"- **Baseline interpreter:** `{m['baseline_interpreter']}`  ·  **Current interpreter:** `{m['current_interpreter']}`")
        lines.append("")
        lines.append("**Baseline decoder chain**")
        lines.append("```")
        lines.append(json.dumps(m["baseline_ops"], indent=2, default=str)[:4000])
        lines.append("```")
        lines.append("")
        lines.append("**Current decoder chain**")
        lines.append("```")
        lines.append(json.dumps(m["current_ops"], indent=2, default=str)[:4000])
        lines.append("```")
        lines.append("")
        lines.append("**Baseline final output**")
        lines.append("```")
        lines.append((str(m["baseline_final"]) or "")[:2000])
        lines.append("```")
        lines.append("")
        lines.append("**Current final output**")
        lines.append("```")
        lines.append((str(m["current_final"]) or "")[:2000])
        lines.append("```")
        lines.append("")
    (ROOT / "phase3_ab_report.md").write_text("\n".join(lines))
    print(f"[phase3] wrote {ROOT / 'phase3_ab_report.md'}")


if __name__ == "__main__":
    sys.exit(main())
