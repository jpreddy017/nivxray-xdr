"""
Phase 4.5 · Runtime Causality Validation & Root Cause Analysis.

For every candidate file across the two regression windows, we:

  1. Snapshot the current-HEAD state of the file in `/tmp/wsp-bisect`.
  2. Surgically revert *only that file's hunks* from the first-bad SHA
     (`git show <first_bad_sha> -- <file> | git apply -R`). This gives us
     the pre-regression state of that ONE file with every OTHER file
     still at HEAD.
  3. Run the full 11-sample corpus.
  4. Diff the per-sample PASS/FAIL against the HEAD baseline recorded in
     `artifacts/current_raw.json`.
  5. Restore the snapshot.

Files that demonstrably fix samples become **Phase 5 restore candidates**.
Files whose surgical revert produces no delta are declared innocent and
excluded from Phase 5.
Files whose surgical revert introduces NEW regressions get flagged so the
Phase 5 plan can restore them together as a group (not independently).

Outputs:
    artifacts/phase4_5_causality.json    (full matrix)
    phase4_5_causality_report.md         (human-readable RCA + prevention)
"""
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

WINDOW_A_FIRST_BAD = "26099be990"
WINDOW_A_LAST_GOOD = "8baa7aa467"
WINDOW_B_FIRST_BAD = "069bd23f77"
WINDOW_B_LAST_GOOD = "194d6ca8e9"

# Files we test individually. Layer classification (as owner requested):
#   workspace = Workspace-owned decoder file
#   shared    = Shared normalizer / decoder used by Workspace
#   engine    = engine/* orchestrator or model
#   xlab      = v2/* or nivxforge/* (Intelligence side, per Contract must
#               NOT influence the decoder — surprises here are red flags)
#   registration = server.py-style route registration only
CANDIDATES = [
    # Window B (Jul 29 04:20 · mass regression of S01..S10)
    {"file": "backend/engine/orchestrator.py",         "window": "B", "layer": "engine",       "first_bad": WINDOW_B_FIRST_BAD},
    {"file": "backend/engine/models.py",               "window": "B", "layer": "engine",       "first_bad": WINDOW_B_FIRST_BAD},
    {"file": "backend/rc22_adapter.py",                "window": "B", "layer": "shared",       "first_bad": WINDOW_B_FIRST_BAD},
    {"file": "backend/v2/semantic/ps_semantic.py",     "window": "B", "layer": "shared",       "first_bad": WINDOW_B_FIRST_BAD},
    {"file": "backend/v2/investigation/analyst_report/builder.py", "window": "B", "layer": "xlab", "first_bad": WINDOW_B_FIRST_BAD},
    {"file": "backend/v2/investigation/verdict/__init__.py",       "window": "B", "layer": "xlab", "first_bad": WINDOW_B_FIRST_BAD},
    # Window A (Jul 20 17:42 · S001 regression)
    {"file": "backend/decoders/ps_alias_normalizer.py",   "window": "A", "layer": "shared", "first_bad": WINDOW_A_FIRST_BAD},
    {"file": "backend/decoders/ps_backtick_normalizer.py","window": "A", "layer": "shared", "first_bad": WINDOW_A_FIRST_BAD},
    {"file": "backend/magic_decoder.py",                  "window": "A", "layer": "workspace", "first_bad": WINDOW_A_FIRST_BAD},
    {"file": "backend/routers/ops.py",                    "window": "A", "layer": "workspace", "first_bad": WINDOW_A_FIRST_BAD},
    {"file": "backend/server.py",                         "window": "A", "layer": "registration", "first_bad": WINDOW_A_FIRST_BAD},
]


def _git(*args, cwd=None, check=False, timeout=30):
    r = subprocess.run(["git", *args], cwd=cwd or REPO, capture_output=True,
                       text=True, timeout=timeout)
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr[-400:]}")
    return r


def _ensure_head_worktree():
    _git("-C", str(BISECT_TREE), "reset", "--hard", "HEAD", check=True)
    _git("-C", str(BISECT_TREE), "clean", "-fdx", check=True)
    _git("-C", str(BISECT_TREE), "checkout", "-f", "1a07de3", check=True)
    shutil.copy2("/app/backend/.env", BISECT_TREE / "backend" / ".env")


def _surgical_revert(first_bad_sha: str, file_path: str) -> tuple[bool, str]:
    """Reverse-apply the hunks that `first_bad_sha` made to `file_path` on the
    current HEAD file. Returns (ok, detail).

    If the file did not exist before `first_bad_sha` (i.e. the commit created
    it), surgical revert means DELETE the file. `git apply -R` handles that.
    If patch fails (later commits touched adjacent lines), fall back to full
    `git checkout <first_bad_sha>^ -- <file>` which restores the parent state.
    """
    patch = _git("show", "--format=", first_bad_sha, "--", file_path).stdout
    if not patch.strip():
        return False, "empty patch (file untouched in commit?)"
    # Try surgical reverse-apply.
    apply = subprocess.run(
        ["git", "-C", str(BISECT_TREE), "apply", "-R", "--3way", "-"],
        input=patch, text=True, capture_output=True, timeout=30,
    )
    if apply.returncode == 0:
        return True, "surgical_revert_ok"
    # Fallback: parent-checkout.
    parent = _git("rev-parse", f"{first_bad_sha}^").stdout.strip()
    checkout = _git("-C", str(BISECT_TREE), "checkout", parent, "--", file_path)
    if checkout.returncode == 0:
        return True, f"parent_checkout_fallback (parent={parent[:10]})"
    return False, f"BOTH_FAILED: apply={apply.stderr[-200:]} checkout={checkout.stderr[-200:]}"


def _run_worker() -> dict:
    env = {"PYTHONPATH": "/app/backend",
           "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
           "PYTHONDONTWRITEBYTECODE": "1"}
    for _ in (1, 2):
        proc = subprocess.run(
            [sys.executable, "-m", "workspace_recovery.tree_worker",
             str(BISECT_TREE / "backend"), str(CORPUS)],
            capture_output=True, text=True, timeout=180, cwd="/app/backend", env=env,
        )
        for line in reversed([ln for ln in proc.stdout.splitlines() if ln.strip()]):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"fatal": True, "stderr_tail": proc.stderr[-800:]}


def _fingerprint(resp: dict) -> tuple[list[str], str]:
    ops = [t.get("op") for t in (resp.get("trace") or []) if isinstance(t, dict)]
    final = str(resp.get("output") or "").strip()
    return ops, final


def _per_sample_delta(baseline: dict, before: dict, after: dict) -> dict:
    """Compare `after` (with the file reverted) to the HEAD baseline.

    Categories per sample:
      - fixed         : baseline vs v1.5.6 = FAIL, after = PASS
      - regressed_new : baseline = PASS, after = FAIL
      - unchanged     : same as baseline
    """
    baseline_by = {r["id"]: r for r in baseline.get("results", [])}
    before_by = {r["id"]: r for r in before.get("results", [])}
    after_by = {r["id"]: r for r in after.get("results", [])}
    out = {}
    for sid, base in baseline_by.items():
        b_resp = (base.get("response") or {})
        h_resp = (before_by.get(sid, {}).get("response") or {})  # HEAD state
        a_resp = (after_by.get(sid, {}).get("response") or {})  # after revert
        b_ops, b_final = _fingerprint(b_resp)
        h_ops, h_final = _fingerprint(h_resp)
        a_ops, a_final = _fingerprint(a_resp)
        # For S001 we grade against owner expected.
        if sid == "S001_ps_writehost_tweet":
            head_pass = 'tweet, tweet' in h_final.lower()
            after_pass = 'tweet, tweet' in a_final.lower()
        else:
            head_pass = (h_ops == b_ops and h_final == b_final)
            after_pass = (a_ops == b_ops and a_final == b_final)
        if not head_pass and after_pass:
            cat = "fixed"
        elif head_pass and not after_pass:
            cat = "regressed_new"
        elif head_pass and after_pass:
            cat = "unchanged_pass"
        else:
            cat = "unchanged_fail"
        out[sid] = {
            "category": cat,
            "head_ops": h_ops, "after_ops": a_ops,
            "head_final": h_final[:200], "after_final": a_final[:200],
        }
    return out


def main() -> int:
    # Baseline HEAD data was recorded in Phase 3 already.
    baseline = json.loads((ART / "baseline_raw.json").read_text())
    head_state = json.loads((ART / "current_raw.json").read_text())

    print("[phase4.5] preparing worktree at HEAD (1a07de3)")
    _ensure_head_worktree()

    results = []
    for i, cand in enumerate(CANDIDATES, 1):
        f = cand["file"]
        print(f"[phase4.5] {i}/{len(CANDIDATES)} · {f}")
        # Snapshot current bytes so we can restore precisely.
        snap = None
        target = BISECT_TREE / f
        if target.exists():
            snap = target.read_bytes()
        # Attempt surgical revert.
        ok, det = _surgical_revert(cand["first_bad"], f)
        row = {**cand, "revert_status": det}
        if not ok:
            row["skipped"] = True
            results.append(row)
            # Snapshot restore not needed (nothing changed).
            continue
        run = _run_worker()
        if run.get("fatal"):
            row["worker_fatal"] = run
            row["skipped"] = True
        else:
            row["per_sample"] = _per_sample_delta(baseline, head_state, run)
            row["counts"] = {
                "fixed": sum(1 for v in row["per_sample"].values() if v["category"] == "fixed"),
                "regressed_new": sum(1 for v in row["per_sample"].values() if v["category"] == "regressed_new"),
                "unchanged_pass": sum(1 for v in row["per_sample"].values() if v["category"] == "unchanged_pass"),
                "unchanged_fail": sum(1 for v in row["per_sample"].values() if v["category"] == "unchanged_fail"),
            }
        results.append(row)
        # Restore snapshot so next iteration starts from HEAD state.
        if snap is not None:
            target.write_bytes(snap)
        else:
            # File was created by revert (i.e. commit deleted a file); remove it.
            if target.exists():
                target.unlink()

    (ART / "phase4_5_causality.json").write_text(json.dumps(results, indent=2, default=str))
    _emit_report(results)
    return 0


def _emit_report(results: list) -> None:
    lines = []
    lines.append("# Phase 4.5 · Runtime Causality Validation & RCA")
    lines.append("")
    lines.append("Every row below reflects a **surgical per-file revert** on top of HEAD")
    lines.append("(`/tmp/wsp-bisect` worktree). We invert exactly the hunks that the first-bad")
    lines.append("commit applied to that ONE file, run the 11-sample corpus, and classify each")
    lines.append("sample as `fixed` / `regressed_new` / `unchanged_pass` / `unchanged_fail`.")
    lines.append("")
    lines.append("## Aggregate Causality Matrix")
    lines.append("")
    lines.append("| File | Win | Layer | Revert | Fixed | Regressed | Unchanged✅ | Unchanged❌ |")
    lines.append("|------|:-:|------|--------|:-----:|:---------:|:-----------:|:-----------:|")
    for r in results:
        if r.get("skipped"):
            lines.append(f"| `{r['file']}` | {r['window']} | {r['layer']} | SKIP · {r['revert_status'][:60]} | — | — | — | — |")
            continue
        c = r.get("counts") or {}
        lines.append(f"| `{r['file']}` | {r['window']} | {r['layer']} | ok · {r['revert_status']} | {c.get('fixed',0)} | {c.get('regressed_new',0)} | {c.get('unchanged_pass',0)} | {c.get('unchanged_fail',0)} |")
    lines.append("")
    lines.append("## Per-File Root-Cause Analysis (files that fixed ≥1 sample)")
    lines.append("")
    for r in results:
        c = r.get("counts") or {}
        if c.get("fixed", 0) == 0:
            continue
        lines.append(f"### `{r['file']}` — {c['fixed']} sample(s) fixed by surgical revert")
        lines.append("")
        lines.append(f"- Layer: **{r['layer']}**")
        lines.append(f"- Window: **{r['window']}**")
        lines.append(f"- Revert method: `{r['revert_status']}`")
        lines.append("")
        lines.append("**Samples restored:**")
        for sid, info in r["per_sample"].items():
            if info["category"] == "fixed":
                lines.append(f"  - `{sid}`")
                lines.append(f"      HEAD ops : `{info['head_ops']}`")
                lines.append(f"      Reverted : `{info['after_ops']}`")
                lines.append(f"      HEAD out : `{info['head_final'][:120]}`")
                lines.append(f"      After out: `{info['after_final'][:120]}`")
        if c.get("regressed_new"):
            lines.append("")
            lines.append("**⚠ New regressions introduced by this revert (block Phase 5 solo-restore):**")
            for sid, info in r["per_sample"].items():
                if info["category"] == "regressed_new":
                    lines.append(f"  - `{sid}` — was PASS, becomes FAIL")
        lines.append("")
    lines.append("## Files Proven Innocent (no samples fixed, no samples regressed)")
    lines.append("")
    for r in results:
        c = r.get("counts") or {}
        if not c or r.get("skipped"):
            continue
        if c.get("fixed", 0) == 0 and c.get("regressed_new", 0) == 0:
            lines.append(f"- `{r['file']}` ({r['layer']}) — revert had no runtime effect; **exclude from Phase 5**.")
    lines.append("")
    lines.append("## Files with Ambiguous Revert (SKIP — patch could not be applied)")
    lines.append("")
    for r in results:
        if r.get("skipped") and "revert_status" in r:
            lines.append(f"- `{r['file']}` ({r['layer']}) — {r['revert_status']}")
    lines.append("")
    lines.append("## Prevention Recommendations (populated by hand in the final RCA)")
    lines.append("")
    lines.append("_Populated once the machine-generated matrix is reviewed against the code diffs._")
    (ROOT / "phase4_5_causality_report.md").write_text("\n".join(lines))
    print(f"[phase4.5] wrote {ROOT / 'phase4_5_causality_report.md'}")


if __name__ == "__main__":
    sys.exit(main())
