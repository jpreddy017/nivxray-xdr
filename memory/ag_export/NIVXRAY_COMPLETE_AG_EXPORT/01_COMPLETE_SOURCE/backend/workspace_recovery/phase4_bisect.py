"""
Phase 4 · Historical Bisect

For every sampled git anchor between the earliest visible commit and HEAD:
  1. Check out that SHA into /tmp/wsp-bisect (a dedicated worktree).
  2. Copy /app/backend/.env into it.
  3. Invoke the worker to run the full corpus against that tree.
  4. For every sample, record PASS/FAIL against the KNOWN-GOOD FINGERPRINT.

The known-good fingerprint for each sample is the baseline v1.5.6 output
recorded during Phase 3, EXCEPT for S001 which is fingerprinted against
the owner's specified expected output `Write-Host "tweet, tweet!"`.
For S001 we search the entire history for ANY revision that produces
`Write-Host "tweet, tweet!"` — if none exists, S001 is a
build-not-restore case (flagged explicitly).

Outputs:
    artifacts/phase4_bisect_matrix.json
    phase4_bisect_report.md
"""
import json
import os
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

# Sample the git history. We take:
#  · HEAD
#  · fff5897 (v1.5.6)
#  · every 40th commit between them (post-v1.5.6 = 82 commits → 3 anchors)
#  · every 40th commit before v1.5.6 back to the earliest visible commit
#    (Jul 13, 2026)
#
# Total anchors ≈ 15. Each run ≈ 30 s so total ≈ 8 min — acceptable.
STRIDE = 80


def _pick_anchors() -> list[dict]:
    # Get ALL commits reachable from HEAD (not just backend-touching), so we
    # never miss the actual v1.5.6 anchor SHA (which may itself not touch
    # backend/ but change surrounding config).
    cmd = ["git", "log", "--format=%H %ai"]
    r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=30)
    all_commits = []
    for ln in r.stdout.strip().splitlines():
        parts = ln.split(maxsplit=1)
        if len(parts) == 2:
            all_commits.append({"sha": parts[0], "date": parts[1]})
    # HEAD-first → oldest-first
    all_commits.reverse()

    v156_idx = next((i for i, c in enumerate(all_commits) if c["sha"].startswith("fff5897")), None)
    if v156_idx is None:
        raise RuntimeError("fff5897 not in history")

    picks = []
    # Oldest → v1.5.6 (every STRIDE)
    for i in range(0, v156_idx, STRIDE):
        picks.append({**all_commits[i], "note": "pre-v1.5.6"})
    picks.append({**all_commits[v156_idx], "note": "v1.5.6 anchor (Certified Baseline)"})
    # v1.5.6+1 → HEAD (every STRIDE)
    for i in range(v156_idx + 1, len(all_commits), STRIDE):
        picks.append({**all_commits[i], "note": "post-v1.5.6"})
    # Ensure HEAD is last
    head = all_commits[-1]
    if picks[-1]["sha"] != head["sha"]:
        picks.append({**head, "note": "HEAD"})
    return picks


def _checkout(sha: str) -> tuple[bool, str]:
    try:
        subprocess.run(
            ["git", "-C", str(BISECT_TREE), "checkout", "-f", sha],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except subprocess.CalledProcessError as e:
        return False, e.stderr[-500:]
    # Skip revisions where the backend/ tree doesn't exist yet (pre-restructure).
    be = BISECT_TREE / "backend"
    if not (be / "server.py").exists() or not (be / "routers" / "ops.py").exists():
        return False, "no backend/server.py or routers/ops.py in this revision"
    # Ensure .env is present (git worktree won't drag it).
    shutil.copy2("/app/backend/.env", be / ".env")
    return True, ""


def _run_worker(tree: Path) -> dict:
    env = {
        "PYTHONPATH": "/app/backend",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "workspace_recovery.tree_worker",
             str(tree / "backend"), str(CORPUS)],
            capture_output=True, text=True, timeout=180,
            cwd="/app/backend", env=env,
        )
    except subprocess.TimeoutExpired:
        return {"fatal": True, "reason": "timeout"}
    for line in reversed([ln for ln in proc.stdout.splitlines() if ln.strip()]):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"fatal": True, "returncode": proc.returncode,
            "stderr_tail": proc.stderr[-1000:]}


def _fingerprint_ops(resp: dict) -> list[str]:
    return [t.get("op") for t in (resp.get("trace") or []) if isinstance(t, dict)]


def _extract_final_text(resp: dict) -> str:
    return str(resp.get("output") or "")


def _s001_stage_breakdown(ops: list[str], final: str) -> dict:
    """Structured per-stage breakdown for S001 as the owner requested.

    Every field is derived from the runtime `ops` sequence and the final
    output — not from source-code inference.
    """
    ops_lower = [str(o or "").lower() for o in ops]
    def _any(pred): return any(pred(o) for o in ops_lower)
    interp = None
    if _any(lambda o: "powershell" in o or o.startswith("ps-")):
        interp = "powershell"
    elif _any(lambda o: o.startswith("cmd-") or "cmd-" in o):
        interp = "cmd"
    elif _any(lambda o: "bash" in o):
        interp = "bash"
    enc_recognized = _any(lambda o: "encodedcommand" in o or "ps-enc" in o or "-enc" in o)
    payload_extracted = _any(lambda o: o in ("extract-payload", "extract-b64") or "extract" in o)
    b64_done = _any(lambda o: "base64-decode" in o or "extract-b64" in o)
    utf16_done = _any(lambda o: "utf16" in o or "utf-16" in o)
    got_writehost = 'write-host' in final.lower() or 'tweet, tweet' in final.lower()
    # First divergent stage vs. expected pipeline order.
    expected_order = [
        ("interpreter", interp == "powershell"),
        ("encodedcommand_recognition", enc_recognized),
        ("payload_extraction", payload_extracted),
        ("base64_decode", b64_done),
        ("utf16le_decode", utf16_done),
        ("final_payload_writehost_tweet", got_writehost),
    ]
    first_missing = next((name for name, ok in expected_order if not ok), None)
    return {
        "interpreter_selected": interp,
        "encodedcommand_recognized": enc_recognized,
        "payload_extracted": payload_extracted,
        "base64_decoded": b64_done,
        "utf16le_decoded": utf16_done,
        "final_payload_correct": got_writehost,
        "first_missing_stage": first_missing,
        "final_snippet": final[:400],
    }


def _sample_status(sid: str, resp: dict, baseline_ops: list[str], baseline_final: str) -> dict:
    """Compare this run's response for `sid` against the baseline v1.5.6."""
    if not isinstance(resp, dict):
        return {"sample": sid, "status": "MISSING"}
    ops = _fingerprint_ops(resp)
    final = _extract_final_text(resp)
    # S001 special: fingerprint against owner expected, not baseline.
    if sid == "S001_ps_writehost_tweet":
        good = 'Write-Host "tweet, tweet!"' in final or "tweet, tweet" in final
        return {
            "sample": sid,
            "status": "PASS" if good else "FAIL",
            "against": "owner_expected",
            "ops": ops,
            "stages": _s001_stage_breakdown(ops, final),
        }
    same_ops = ops == baseline_ops
    same_final = final.strip() == baseline_final.strip()
    return {
        "sample": sid,
        "status": "PASS" if (same_ops and same_final) else "FAIL",
        "against": "v1.5.6_fingerprint",
        "same_ops": same_ops,
        "same_final": same_final,
        "ops": ops,
    }


def main() -> int:
    # Load baseline fingerprints (already recorded in Phase 3).
    baseline = json.loads((ART / "baseline_raw.json").read_text())
    baseline_by_id = {r["id"]: r for r in baseline.get("results", [])}
    baseline_fp = {
        sid: {
            "ops": _fingerprint_ops(entry.get("response") or {}),
            "final": _extract_final_text(entry.get("response") or {}),
        }
        for sid, entry in baseline_by_id.items()
    }

    anchors = _pick_anchors()
    print(f"[bisect] running {len(anchors)} anchors")

    results = []
    for i, a in enumerate(anchors, 1):
        print(f"[bisect] {i}/{len(anchors)} · {a['sha'][:10]} · {a['date']} · {a['note']}")
        ok, err = _checkout(a["sha"])
        if not ok:
            results.append({**a, "checkout_error": err, "samples": {}})
            continue
        run = _run_worker(BISECT_TREE)
        if run.get("fatal"):
            results.append({**a, "worker_fatal": run, "samples": {}})
            continue
        samples = {}
        for r in run.get("results", []):
            sid = r["id"]
            fp = baseline_fp.get(sid, {"ops": [], "final": ""})
            samples[sid] = _sample_status(
                sid, r.get("response") or {},
                fp["ops"], fp["final"],
            )
        results.append({**a, "samples": samples})

    (ART / "phase4_bisect_matrix.json").write_text(json.dumps(results, indent=2, default=str))
    _emit_report(results)
    return 0


def _emit_report(rows: list[dict]) -> None:
    # Determine sample id ordering from the first successful row.
    sample_ids = None
    for r in rows:
        if r.get("samples"):
            sample_ids = list(r["samples"].keys())
            break
    sample_ids = sample_ids or []

    lines = []
    lines.append("# Phase 4 · Historical Bisect (S001-anchored) — Runtime Evidence")
    lines.append("")
    lines.append("Every row below is the result of **checking out a real git SHA** and")
    lines.append("running the full corpus against it — no source-code inference. Baseline")
    lines.append("fingerprint = v1.5.6 (`fff5897`, Jul 28 16:10 UTC) as recorded in Phase 3.")
    lines.append("**Exception**: S001 is fingerprinted against the OWNER-SPECIFIED expected")
    lines.append('output `Write-Host "tweet, tweet!"`, not the v1.5.6 fingerprint — because')
    lines.append("v1.5.6 itself did NOT decode S001 correctly, and the bisect must therefore")
    lines.append("search the entire visible history for a revision that did.")
    lines.append("")
    lines.append("## Per-Revision PASS/FAIL Matrix")
    lines.append("")
    header = "| SHA | Date | Note | " + " | ".join(sid.replace("_", " ") for sid in sample_ids) + " |"
    sep = "|---|---|---|" + "|".join([":-:" for _ in sample_ids]) + "|"
    lines.append(header)
    lines.append(sep)
    for r in rows:
        sha = r["sha"][:10]
        date = r["date"]
        note = r.get("note", "")
        if r.get("checkout_error"):
            row = f"| `{sha}` | {date} | {note} | " + " | ".join(["ERR"] * len(sample_ids)) + " |"
            lines.append(row)
            continue
        if r.get("worker_fatal"):
            row = f"| `{sha}` | {date} | {note} | " + " | ".join(["BOOT-FAIL"] * len(sample_ids)) + " |"
            lines.append(row)
            continue
        cells = []
        for sid in sample_ids:
            s = r["samples"].get(sid, {})
            st = s.get("status", "-")
            mark = "✅" if st == "PASS" else ("❌" if st == "FAIL" else st)
            cells.append(mark)
        row = f"| `{sha}` | {date} | {note} | " + " | ".join(cells) + " |"
        lines.append(row)
    lines.append("")

    # S001-specific verdict
    lines.append("## S001 · Per-Anchor Stage Breakdown (runtime evidence)")
    lines.append("")
    lines.append("| SHA | Date | Note | Interp | -EncodedCmd | Extract | Base64 | UTF-16LE | Write-Host | 1st missing stage |")
    lines.append("|---|---|---|:-:|:-:|:-:|:-:|:-:|:-:|---|")
    for r in rows:
        if r.get("checkout_error") or r.get("worker_fatal"):
            lines.append(f"| `{r['sha'][:10]}` | {r['date']} | {r.get('note','')} | ERR | ERR | ERR | ERR | ERR | ERR | — |")
            continue
        s = r.get("samples", {}).get("S001_ps_writehost_tweet", {})
        st = s.get("stages", {}) or {}
        cell = lambda b: "✅" if b is True else ("❌" if b is False else "—")
        interp = st.get("interpreter_selected") or "—"
        lines.append(
            f"| `{r['sha'][:10]}` | {r['date']} | {r.get('note','')} | {interp} | "
            f"{cell(st.get('encodedcommand_recognized'))} | {cell(st.get('payload_extracted'))} | "
            f"{cell(st.get('base64_decoded'))} | {cell(st.get('utf16le_decoded'))} | "
            f"{cell(st.get('final_payload_correct'))} | {st.get('first_missing_stage') or '—'} |"
        )
    lines.append("")
    lines.append("## S001 Verdict")
    lines.append("")
    s001_passes = [r for r in rows
                   if r.get("samples", {}).get("S001_ps_writehost_tweet", {}).get("status") == "PASS"]
    if s001_passes:
        first = s001_passes[0]
        last = s001_passes[-1]
        lines.append("**S001 PASSES on at least one historical revision.** Restoration is a valid strategy.")
        lines.append(f"- Earliest known-good SHA: `{first['sha'][:10]}` ({first['date']}) — `{first.get('note')}`")
        lines.append(f"- Latest known-good SHA  : `{last['sha'][:10]}` ({last['date']}) — `{last.get('note')}`")
        lines.append("- Recommended action     : binary-search between the last-good and the first-bad neighbouring commit to pinpoint the regression, then Phase 4 disable/swap/restore on the responsible module.")
    else:
        lines.append("**S001 FAILS on every sampled historical revision, including the v1.5.6 baseline.**")
        lines.append("This is a **BUILD-NOT-RESTORE** case: no reachable revision produces")
        lines.append('`Write-Host "tweet, tweet!"` for the given `-encod` (5-char abbreviation)')
        lines.append("input. Per owner decision rule (b, Case 2), proceed to Phase 4 BUILD:")
        lines.append("extend the `-EncodedCommand` recognizer to accept all valid abbreviations")
        lines.append("(`-e` · `-en` · `-enc` · `-enco` · `-encod` · `-encoded` · `-encodedcommand`),")
        lines.append("add the UTF-16LE post-decode step, and certify against the full corpus")
        lines.append("BEFORE wiring into `routers/ops.py`. Do not touch the Intelligence Layer.")
    lines.append("")
    lines.append("## Per-Sample Regression Windows (excluding S001)")
    lines.append("")
    lines.append("For every corpus sample other than S001, the fingerprint is v1.5.6.")
    lines.append("A sample transitioning from ✅ at revision N to ❌ at revision N+1 pinpoints")
    lines.append("the regression window for that sample. This directly informs Phase 4.")
    lines.append("")
    for sid in sample_ids:
        if sid == "S001_ps_writehost_tweet":
            continue
        lines.append(f"### `{sid}`")
        prev = None
        transitions = []
        for r in rows:
            st = r.get("samples", {}).get(sid, {}).get("status")
            if prev is not None and st != prev and st in ("PASS", "FAIL"):
                transitions.append((prev, st, r["sha"][:10], r["date"]))
            if st in ("PASS", "FAIL"):
                prev = st
        if not transitions:
            lines.append("- No transitions observed across sampled anchors.")
        else:
            for a, b, sha, date in transitions:
                lines.append(f"- `{a}` → `{b}` at `{sha}` ({date})")
        lines.append("")

    (ROOT / "phase4_bisect_report.md").write_text("\n".join(lines))
    print(f"[bisect] wrote {ROOT / 'phase4_bisect_report.md'}")


if __name__ == "__main__":
    sys.exit(main())
