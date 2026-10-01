"""
Phase 4 · Precision Bisect

Binary-search a git range `good..bad` for the exact commit that flips a
predicate. The predicate is evaluated by executing the full corpus in the
target tree via the same isolated tree_worker used by Phase 3.

Usage:
    python -m workspace_recovery.narrow_bisect \\
        --good 5cab99e2b8 --bad 51666219ed \\
        --predicate s001_writehost --label window_a

    python -m workspace_recovery.narrow_bisect \\
        --good 09a556701a --bad 42d7dffd1d \\
        --predicate corpus_10_of_10 --label window_b

Writes:
    artifacts/narrow_<label>.json     (full per-anchor sample statuses)
    narrow_<label>_report.md          (bisect log + verdict)
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True)
REPO = Path("/app")
BISECT_TREE = Path("/tmp/wsp-bisect")
CORPUS = ROOT / "corpus.json"


def _commits_between(good: str, bad: str) -> list[dict]:
    """Return commits in oldest-first order: (good, ..., bad]."""
    cmd = ["git", "log", "--format=%H %ai", f"{good}..{bad}"]
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=30)
    rows = []
    for ln in r.stdout.strip().splitlines():
        parts = ln.split(maxsplit=1)
        if len(parts) == 2:
            rows.append({"sha": parts[0], "date": parts[1]})
    rows.reverse()  # oldest → newest
    # Prepend the "good" anchor itself for sanity-check.
    good_full = subprocess.run(["git", "rev-parse", good], cwd=REPO,
                               capture_output=True, text=True, timeout=10).stdout.strip()
    good_date = subprocess.run(["git", "log", "-1", "--format=%ai", good_full], cwd=REPO,
                               capture_output=True, text=True, timeout=10).stdout.strip()
    return [{"sha": good_full, "date": good_date, "role": "good_anchor"}] + rows


def _checkout(sha: str) -> tuple[bool, str]:
    try:
        subprocess.run(["git", "-C", str(BISECT_TREE), "checkout", "-f", sha],
                       capture_output=True, text=True, timeout=30, check=True)
    except subprocess.CalledProcessError as e:
        return False, e.stderr[-500:]
    be = BISECT_TREE / "backend"
    if not (be / "server.py").exists() or not (be / "routers" / "ops.py").exists():
        return False, "no backend/ in this revision"
    shutil.copy2("/app/backend/.env", be / ".env")
    return True, ""


def _run_worker(tree: Path) -> dict:
    env = {"PYTHONPATH": "/app/backend",
           "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "workspace_recovery.tree_worker",
             str(tree / "backend"), str(CORPUS)],
            capture_output=True, text=True, timeout=180, cwd="/app/backend", env=env)
    except subprocess.TimeoutExpired:
        return {"fatal": True, "reason": "timeout"}
    for line in reversed([ln for ln in proc.stdout.splitlines() if ln.strip()]):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"fatal": True, "stderr_tail": proc.stderr[-1000:]}


# ── Predicates ─────────────────────────────────────────────────────────
def _pred_s001_writehost(run: dict) -> tuple[bool, str]:
    for r in run.get("results", []):
        if r["id"] != "S001_ps_writehost_tweet":
            continue
        resp = r.get("response") or {}
        out = str(resp.get("output") or "")
        return ('tweet, tweet' in out.lower()), f"final_snippet={out[:120]!r}"
    return False, "S001 absent"


def _pred_corpus_10_of_10(run: dict) -> tuple[bool, str]:
    """Load baseline fingerprint and count how many of S01..S10 match."""
    baseline = json.loads((ART / "baseline_raw.json").read_text())
    fp = {r["id"]: {"ops": [t.get("op") for t in (r.get("response") or {}).get("trace") or []
                            if isinstance(t, dict)],
                    "final": str((r.get("response") or {}).get("output") or "").strip()}
          for r in baseline.get("results", [])}
    passes = 0
    total = 0
    for r in run.get("results", []):
        sid = r["id"]
        if sid == "S001_ps_writehost_tweet":
            continue
        total += 1
        resp = r.get("response") or {}
        ops = [t.get("op") for t in (resp.get("trace") or []) if isinstance(t, dict)]
        final = str(resp.get("output") or "").strip()
        if ops == fp[sid]["ops"] and final == fp[sid]["final"]:
            passes += 1
    return (passes == total), f"{passes}/{total} match v1.5.6 fingerprint"


PREDICATES = {
    "s001_writehost": _pred_s001_writehost,
    "corpus_10_of_10": _pred_corpus_10_of_10,
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--good", required=True)
    ap.add_argument("--bad", required=True)
    ap.add_argument("--predicate", required=True, choices=list(PREDICATES.keys()))
    ap.add_argument("--label", required=True)
    args = ap.parse_args()

    predicate = PREDICATES[args.predicate]
    commits = _commits_between(args.good, args.bad)
    print(f"[narrow-{args.label}] {len(commits)} commits between {args.good[:10]}..{args.bad[:10]}")
    # commits[0] = good, commits[-1] = bad.
    # Sanity: verify good passes and bad fails BEFORE bisecting.
    tested = {}

    def _run(sha: str) -> tuple[str, dict, str]:
        """Return one of 'PASS' / 'FAIL' / 'SKIP' plus detail."""
        if sha in tested:
            return tested[sha]
        ok, err = _checkout(sha)
        if not ok:
            tested[sha] = ("SKIP", {"skip": True, "reason": err}, f"checkout_fail: {err[:80]}")
            return tested[sha]
        # Two attempts — worker boot can be flaky under load.
        for attempt in (1, 2):
            run = _run_worker(BISECT_TREE)
            if not run.get("fatal"):
                break
        if run.get("fatal"):
            tested[sha] = ("SKIP", {"fatal": run}, "worker_fatal (2 attempts)")
            return tested[sha]
        passes, detail = predicate(run)
        tested[sha] = (("PASS" if passes else "FAIL"), run, detail)
        return tested[sha]

    print(f"[narrow-{args.label}] verifying good anchor {commits[0]['sha'][:10]}")
    good_res, _, gdet = _run(commits[0]["sha"])
    print(f"  → {good_res} · {gdet}")
    print(f"[narrow-{args.label}] verifying bad  anchor {commits[-1]['sha'][:10]}")
    bad_res, _, bdet = _run(commits[-1]["sha"])
    print(f"  → {bad_res} · {bdet}")

    if good_res != "PASS" or bad_res != "FAIL":
        report = {
            "label": args.label, "good": commits[0], "bad": commits[-1],
            "good_res": good_res, "bad_res": bad_res,
            "reason": "anchors do not straddle a PASS→FAIL transition",
            "tested": {k: v[2] for k, v in tested.items()},
        }
        (ART / f"narrow_{args.label}.json").write_text(json.dumps(report, indent=2, default=str))
        print(f"[narrow-{args.label}] ABORT — anchors do not straddle a transition")
        return 2

    # Binary search: invariant lo = last known PASS, hi = first known FAIL.
    lo = 0
    hi = len(commits) - 1
    trace = [(commits[lo]["sha"][:10], "PASS"), (commits[hi]["sha"][:10], "FAIL")]
    while hi - lo > 1:
        mid = (lo + hi) // 2
        # If mid is SKIP, walk outward until we find a testable commit
        # (still inside (lo, hi)). Prefer moving toward the untested side.
        original_mid = mid
        res_at_mid = None
        while lo < mid < hi:
            sha = commits[mid]["sha"]
            print(f"[narrow-{args.label}] bisect mid {sha[:10]} ({mid=}, {lo=}, {hi=})")
            res_at_mid, _, det = _run(sha)
            trace.append((sha[:10], res_at_mid))
            print(f"  → {res_at_mid} · {det}")
            if res_at_mid in ("PASS", "FAIL"):
                break
            # SKIP → try mid-1
            mid -= 1
            if mid <= lo:
                mid = original_mid + 1
                if mid >= hi:
                    break
        if res_at_mid == "PASS":
            lo = mid
        elif res_at_mid == "FAIL":
            hi = mid
        else:
            # All neighbours SKIP — cannot narrow further.
            print(f"[narrow-{args.label}] cannot narrow further — all mid candidates SKIP")
            break

    last_good = commits[lo]
    first_bad = commits[hi]
    diff_stat = subprocess.run(
        ["git", "show", "--stat", "--format=%h %ai %s", first_bad["sha"]],
        cwd=REPO, capture_output=True, text=True, timeout=30).stdout
    diff_files = subprocess.run(
        ["git", "show", "--name-only", "--format=", first_bad["sha"]],
        cwd=REPO, capture_output=True, text=True, timeout=30).stdout.strip().splitlines()

    result = {
        "label": args.label,
        "predicate": args.predicate,
        "good_anchor": commits[0],
        "bad_anchor": commits[-1],
        "last_good": last_good,
        "first_bad": first_bad,
        "commits_in_window": len(commits) - 1,
        "iterations": len(trace) - 2,
        "trace": trace,
        "first_bad_diff_stat": diff_stat,
        "first_bad_files_changed": diff_files,
    }
    (ART / f"narrow_{args.label}.json").write_text(json.dumps(result, indent=2, default=str))

    lines = []
    lines.append(f"# Phase 4 · Narrow Bisect · `{args.label}`")
    lines.append("")
    lines.append(f"- Predicate       : `{args.predicate}`")
    lines.append(f"- Original window : `{args.good}` .. `{args.bad}` ({len(commits)-1} commits)")
    lines.append(f"- Bisect steps    : {len(trace)-2}")
    lines.append("")
    lines.append(f"## Verdict")
    lines.append(f"- **Last Known Good** : `{last_good['sha'][:10]}` · {last_good['date']}")
    lines.append(f"- **First Bad**       : `{first_bad['sha'][:10]}` · {first_bad['date']}")
    lines.append("")
    lines.append("## Files changed in the First Bad commit")
    lines.append("```")
    for f in diff_files:
        lines.append(f"  {f}")
    lines.append("```")
    lines.append("")
    lines.append("## Diff stat")
    lines.append("```")
    lines.append(diff_stat)
    lines.append("```")
    lines.append("")
    lines.append("## Bisect trace")
    lines.append("| SHA | Result |")
    lines.append("|---|:-:|")
    for sha, res in trace:
        lines.append(f"| `{sha}` | {'✅' if res == 'PASS' else '❌'} |")
    (ROOT / f"narrow_{args.label}_report.md").write_text("\n".join(lines))
    print(f"[narrow-{args.label}] wrote {ROOT / f'narrow_{args.label}_report.md'}")
    print(f"[narrow-{args.label}] LAST GOOD = {last_good['sha'][:10]}  FIRST BAD = {first_bad['sha'][:10]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
