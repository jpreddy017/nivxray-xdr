"""
Phase 5 · Hunk Validator

For each proposed hunk we:
  1. Restore /tmp/wsp-bisect to HEAD (1a07de3).
  2. Apply that hunk in isolation.
  3. Run the 11-sample deterministic corpus.
  4. Score every sample as PASS / FAIL against its known-good fingerprint:
       S001 → owner expected  Write-Host "tweet, tweet!"
       S01..S10 → v1.5.6 baseline (ops == baseline_ops AND final == baseline_final)
  5. Restore HEAD and move to the next hunk.
  6. After the three individual runs, apply ALL three hunks together and
     confirm 11/11 PASS.

Writes:
    artifacts/phase5_hunk_validation.json
    phase5_hunk_validation_report.md

No files are ever modified inside /app/backend. All experiments happen in
/tmp/wsp-bisect. The running production backend is unaffected.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts"
ART.mkdir(exist_ok=True)
BISECT = Path("/tmp/wsp-bisect")
CORPUS = ROOT / "corpus.json"


def _reset_head():
    subprocess.run(["git", "-C", str(BISECT), "reset", "--hard", "HEAD"],
                   capture_output=True, timeout=30, check=True)
    subprocess.run(["git", "-C", str(BISECT), "clean", "-fdx"],
                   capture_output=True, timeout=30)
    subprocess.run(["git", "-C", str(BISECT), "checkout", "-f", "1a07de3"],
                   capture_output=True, text=True, timeout=30, check=True)
    shutil.copy2("/app/backend/.env", BISECT / "backend" / ".env")


def _apply_hunk_1() -> str:
    """Gate the rc22 preflight OFF in analysis_core.py."""
    path = BISECT / "backend" / "analysis_core.py"
    src = path.read_text()
    before = (
        "    # ── RC2.2 · Orchestrator preflight ────────────────────────────────────\n"
        "    try:\n"
        "        from rc22_adapter import try_orchestrator_first\n"
        "        adopted = try_orchestrator_first(payload, analysis_mode=analysis_mode)\n"
        "        if adopted:\n"
        "            return adopted\n"
        "    except Exception:\n"
        "        # Never let the adapter break the pipeline — legacy always available\n"
        "        pass\n"
    )
    after = (
        "    # ── RC2.2 · Orchestrator preflight ────────────────────────────────────\n"
        "    # DECODER-RECOVERY-LOCK · phase5_hunk_1 · owner-approved\n"
        "    # The rc22-orchestrator preflight was silently hijacking decoding through\n"
        "    # a Shared orchestrator that produces divergent chains for the certified\n"
        "    # corpus (see workspace_recovery/phase4_5_final_rca.md). Gated OFF until\n"
        "    # the orchestrator itself passes 11/11 in its own regression suite.\n"
        "    if False:  # PHASE-5 · HUNK-1\n"
        "        try:\n"
        "            from rc22_adapter import try_orchestrator_first\n"
        "            adopted = try_orchestrator_first(payload, analysis_mode=analysis_mode)\n"
        "            if adopted:\n"
        "                return adopted\n"
        "        except Exception:\n"
        "            pass\n"
    )
    if before not in src:
        raise RuntimeError("hunk1 anchor not found — file has drifted")
    path.write_text(src.replace(before, after, 1))
    return "hunk1 applied · rc22 preflight gated OFF"


def _apply_hunk_2() -> str:
    """Change insert(0) → append for the two PS normalizers only."""
    path = BISECT / "backend" / "magic_decoder.py"
    src = path.read_text()
    # Line 425 (backtick) and line 431 (alias). We match by unique context.
    before_bt = '    if _bt_pairs >= 1:\n        cands.insert(0, {"op": "powershell-backtick-normalize", "args": {}})\n'
    after_bt = ('    if _bt_pairs >= 1:\n'
                '        # DECODER-RECOVERY-LOCK · phase5_hunk_2 · append (not insert)\n'
                '        # so this analyst-facing normalizer runs AFTER the primary decode\n'
                '        # chain and cannot consume payloads intended for utf16le/hex/gzip.\n'
                '        cands.append({"op": "powershell-backtick-normalize", "args": {}})\n')
    before_al = (
        "    if re.search(r\"\\b(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b\", s, re.IGNORECASE):\n"
        "        cands.insert(0, {\"op\": \"powershell-alias-normalize\", \"args\": {}})\n"
    )
    after_al = (
        "    if re.search(r\"\\b(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b\", s, re.IGNORECASE):\n"
        "        # DECODER-RECOVERY-LOCK · phase5_hunk_2 · append (not insert)\n"
        "        cands.append({\"op\": \"powershell-alias-normalize\", \"args\": {}})\n"
    )
    if before_bt not in src or before_al not in src:
        raise RuntimeError("hunk2 anchor not found — file has drifted")
    src2 = src.replace(before_bt, after_bt, 1).replace(before_al, after_al, 1)
    path.write_text(src2)
    return "hunk2 applied · normalizers now append (not insert)"


def _apply_hunk_3() -> str:
    """Tighten the PS-detection regex in routers/ops.py:1866 from substring
    match to a positional match at the start of the input (with optional
    leading whitespace). Bash comments containing 'powershell' no longer
    trigger the PS post-decode alias-normalize."""
    path = BISECT / "backend" / "routers" / "ops.py"
    src = path.read_text()
    before = (
        "        # RC4.5 · PowerShell Alias → Canonical Cmdlet Normalizer — fires\n"
        "        # only when the input mentions powershell/pwsh (so we don't\n"
        "        # accidentally rewrite the word ``ls`` inside plain shell text).\n"
        "        if not _skip_ps_stages and _re.search(r\"\\b(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b\", src, _re.IGNORECASE):\n"
    )
    after = (
        "        # RC4.5 · PowerShell Alias → Canonical Cmdlet Normalizer — fires\n"
        "        # only when the input STARTS with powershell/pwsh (positional\n"
        "        # match, not substring). Prevents 'powershell' inside a Bash\n"
        "        # comment from triggering PS post-decode normalization.\n"
        "        # DECODER-RECOVERY-LOCK · phase5_hunk_3\n"
        "        if not _skip_ps_stages and _re.match(r\"^\\s*(?:powershell(?:\\.exe)?|pwsh(?:\\.exe)?)\\b\", src, _re.IGNORECASE):\n"
    )
    if before not in src:
        raise RuntimeError("hunk3 anchor not found — file has drifted")
    path.write_text(src.replace(before, after, 1))
    return "hunk3 applied · PS-detection regex tightened to positional match"


def _apply_hunk_4() -> str:
    """Widen the -EncodedCommand recognition in BOTH places in magic_decoder.py
    to accept every valid PowerShell abbreviation (-e -en -enc -enco -encod
    -encode -encoded -encodedcommand). Fixes S001 (owner anchor · powershell.exe
    -encod ...) which currently fails only because the 5-char abbreviation is
    not detected by either the ps-encodedcommand-multilayer gate (line 371)
    OR the looks_wrapped extract-payload gate (line 484).
    """
    path = BISECT / "backend" / "magic_decoder.py"
    src = path.read_text()

    # 4a · widen the multilayer gate regex
    before_a = 'if re.search(r"-e(?:c|nc|ncoded(?:command)?)?\\s+[A-Za-z0-9+/=\\s]{16,}", s, re.IGNORECASE):'
    after_a = (
        '# DECODER-RECOVERY-LOCK · phase5_hunk_4a · accept every unambiguous PS\n'
        '    # prefix of -EncodedCommand: -e -en -enc -enco -encod -encode\n'
        '    # -encoded -encodedcommand (see PS Help — prefix must be unambiguous).\n'
        '    if re.search(r"-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\\s+[A-Za-z0-9+/=\\s]{16,}", s, re.IGNORECASE):'
    )
    if before_a not in src:
        raise RuntimeError("hunk4a anchor not found — file has drifted")
    src = src.replace(before_a, after_a, 1)

    # 4b · widen the looks_wrapped substring check
    before_b = (
        '        looks_wrapped = any(m in _s_low for m in (\n'
        '            "frombase64string", "atob(", "base64_decode", "-encodedcommand", "$var_code",\n'
        '        ))'
    )
    after_b = (
        '        # DECODER-RECOVERY-LOCK · phase5_hunk_4b · match every PS\n'
        '        # abbreviation of -EncodedCommand for the extract-payload gate.\n'
        '        looks_wrapped = any(m in _s_low for m in (\n'
        '            "frombase64string", "atob(", "base64_decode", "$var_code",\n'
        '        )) or bool(re.search(\n'
        '            r"-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?\\s+[A-Za-z0-9+/=\\s]{16,}",\n'
        '            _s_low, re.IGNORECASE,\n'
        '        ))'
    )
    if before_b not in src:
        raise RuntimeError("hunk4b anchor not found — file has drifted")
    src = src.replace(before_b, after_b, 1)

    path.write_text(src)
    return "hunk4 applied · both -EncodedCommand gates widened (multilayer + extract-payload)"


def _apply_hunk_5() -> str:
    """Widen smart_decoder._PS_ENCODED_RE to accept every valid PowerShell
    abbreviation of -EncodedCommand. Currently `-encod` (5-char abbrev · S001
    owner anchor) is not matched, so smart_decode fails to peel it and
    magic_decode's aggressive normalizer wins the engine race with a
    "no known aliases found" output.
    """
    path = BISECT / "backend" / "smart_decoder.py"
    src = path.read_text()
    before = 'r"(?:-e(?:c|n|nc|ncoded(?:command)?)?)\\s+([A-Za-z0-9+/=\\s]{16,})",'
    after = (
        '# DECODER-RECOVERY-LOCK · phase5_hunk_5 · accept every unambiguous PS\n'
        '    # prefix of -EncodedCommand (see PS Help — prefix must be unambiguous).\n'
        '    r"(?:-e(?:n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)\\s+([A-Za-z0-9+/=\\s]{16,})",'
    )
    if before not in src:
        raise RuntimeError("hunk5 anchor not found — file has drifted")
    path.write_text(src.replace(before, after, 1))
    return "hunk5 applied · smart_decoder _PS_ENCODED_RE widened"


HUNKS = {
    "hunk_1_disable_rc22_preflight": _apply_hunk_1,
    "hunk_2_append_not_insert":       _apply_hunk_2,
    "hunk_3_positional_ps_regex":     _apply_hunk_3,
    "hunk_4_ps_encodedcommand_abbrev":_apply_hunk_4,
    "hunk_5_smart_ps_encoded_regex":  _apply_hunk_5,
}


def _run_corpus() -> dict:
    env = {"PYTHONPATH": "/app/backend",
           "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
    r = subprocess.run(
        [sys.executable, "-m", "workspace_recovery.tree_worker",
         str(BISECT / "backend"), str(CORPUS)],
        capture_output=True, text=True, timeout=180, cwd="/app/backend", env=env,
    )
    for line in reversed([ln for ln in r.stdout.splitlines() if ln.strip()]):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"fatal": True, "stderr_tail": r.stderr[-1000:]}


def _fingerprint(resp: dict) -> tuple[list, str]:
    ops = [t.get("op") for t in (resp.get("trace") or []) if isinstance(t, dict)]
    # Extract ONLY the decoded output block — everything between the first
    # "▼ DECODED OUTPUT" header and the next "━" section break. The
    # downstream summary (verdict, MITRE, IOCs, narrative) is Intelligence
    # Layer and must not gate the Decode Pipeline PASS/FAIL check per
    # the Decode Pipeline Contract.
    full = str(resp.get("output") or "")
    core = _extract_decoded_block(full)
    return ops, core.strip()


def _extract_decoded_block(full: str) -> str:
    marker = "▼ DECODED OUTPUT"
    if marker not in full:
        return full
    tail = full.split(marker, 1)[1]
    # Skip the leading horizontal-rule line then read up to the next
    # non-decoded section header.
    # Sections we consider Intelligence-Layer:
    for sep in ("NIVXRAY INVESTIGATION SUMMARY", "VERDICT CARD",
                "SEMANTIC ANALYSIS", "MITRE MAPPING", "IOC BUNDLE",
                "▼ ", "━━━"):
        # Only stop at "━━━" if it's the CLOSING horizontal rule after decoded
        # content — the OPENING rule sits immediately after the marker.
        pass
    # Trim the opening rule line.
    lines = tail.split("\n")
    started = False
    kept = []
    for ln in lines:
        if not started:
            if ln.strip().startswith("━"):
                continue  # opening rule
            if not ln.strip():
                continue  # blank right after marker
            started = True
        # Stop at the closing rule (a line of only "━") if we've seen content
        if started and ln.strip() and set(ln.strip()) == {"━"}:
            break
        # Stop at any Intelligence-Layer section header
        if started and any(h in ln for h in (
            "NIVXRAY INVESTIGATION SUMMARY", "VERDICT CARD",
            "SEMANTIC ANALYSIS", "MITRE MAPPING", "IOC BUNDLE")):
            break
        kept.append(ln)
    return "\n".join(kept).rstrip()


def _score(run: dict, baseline_fp: dict) -> dict:
    """Per-sample PASS/FAIL vs correct fingerprint."""
    out = {}
    for r in run.get("results", []):
        sid = r["id"]
        resp = r.get("response") or {}
        ops, final = _fingerprint(resp)
        if sid == "S001_ps_writehost_tweet":
            passed = ("tweet, tweet" in final.lower()
                      or 'write-host "tweet, tweet!"' in final.lower())
            out[sid] = {"pass": passed, "against": "owner_expected",
                        "ops": ops, "final_head": final[:180]}
        else:
            fp = baseline_fp.get(sid, {})
            passed = (ops == fp.get("ops") and final == fp.get("final"))
            out[sid] = {"pass": passed, "against": "v1.5.6_fingerprint",
                        "ops": ops, "final_head": final[:180]}
    return out


def main() -> int:
    baseline = json.loads((ART / "baseline_raw.json").read_text())
    baseline_fp = {}
    for r in baseline.get("results", []):
        resp = r.get("response") or {}
        ops, final = _fingerprint(resp)
        baseline_fp[r["id"]] = {"ops": ops, "final": final}

    experiments = []

    # ── Individual hunks ──
    for name, applier in HUNKS.items():
        print(f"[phase5] {name} · isolated apply")
        _reset_head()
        try:
            note = applier()
        except Exception as e:
            experiments.append({"experiment": name, "apply_error": str(e)})
            continue
        run = _run_corpus()
        if run.get("fatal"):
            experiments.append({"experiment": name, "worker_fatal": run})
            continue
        scored = _score(run, baseline_fp)
        experiments.append({
            "experiment": name,
            "note": note,
            "pass_count": sum(1 for v in scored.values() if v["pass"]),
            "total": len(scored),
            "per_sample": scored,
        })

    # ── Combined (all hunks) ──
    print("[phase5] COMBINED · all hunks together")
    _reset_head()
    try:
        _apply_hunk_1()
        _apply_hunk_2()
        _apply_hunk_3()
        _apply_hunk_4()
        _apply_hunk_5()
        run = _run_corpus()
        if run.get("fatal"):
            experiments.append({"experiment": "combined_all_hunks", "worker_fatal": run})
        else:
            scored = _score(run, baseline_fp)
            experiments.append({
                "experiment": "combined_all_hunks",
                "note": "hunk_1 + hunk_2 + hunk_3 + hunk_4 applied together",
                "pass_count": sum(1 for v in scored.values() if v["pass"]),
                "total": len(scored),
                "per_sample": scored,
            })
    except Exception as e:
        experiments.append({"experiment": "combined_all_hunks", "apply_error": str(e)})
    _reset_head()  # leave the worktree clean

    (ART / "phase5_hunk_validation.json").write_text(
        json.dumps(experiments, indent=2, default=str))
    _emit_report(experiments)
    return 0


def _emit_report(experiments: list) -> None:
    lines = []
    lines.append("# Phase 5 · Hunk Validation — Runtime Proof")
    lines.append("")
    lines.append("Each experiment ran the deterministic 11-sample corpus on `/tmp/wsp-bisect`")
    lines.append("at HEAD `1a07de3` with the named hunk applied in isolation, then all three")
    lines.append("together. Zero changes to `/app/backend`.")
    lines.append("")
    lines.append("## Aggregate results")
    lines.append("")
    lines.append("| Experiment | PASS |")
    lines.append("|------------|:----:|")
    for e in experiments:
        if e.get("worker_fatal") or e.get("apply_error"):
            lines.append(f"| `{e['experiment']}` | ERR ({e.get('apply_error') or 'worker_fatal'}) |")
            continue
        lines.append(f"| `{e['experiment']}` | **{e['pass_count']} / {e['total']}** |")
    lines.append("")
    lines.append("## Per-sample per-experiment")
    lines.append("")
    # Compact table
    sample_ids = []
    for e in experiments:
        if e.get("per_sample"):
            sample_ids = list(e["per_sample"].keys())
            break
    hdr = "| Experiment | " + " | ".join(sid[:14] for sid in sample_ids) + " |"
    sep = "|---" + "|:-:" * len(sample_ids) + "|"
    lines.append(hdr)
    lines.append(sep)
    for e in experiments:
        if not e.get("per_sample"):
            lines.append(f"| `{e['experiment']}` | " + " | ".join(["ERR"] * len(sample_ids)) + " |")
            continue
        cells = ["✅" if e["per_sample"][sid]["pass"] else "❌" for sid in sample_ids]
        lines.append(f"| `{e['experiment']}` | " + " | ".join(cells) + " |")
    lines.append("")
    # Per-experiment detail
    for e in experiments:
        if not e.get("per_sample"):
            continue
        lines.append(f"### `{e['experiment']}` — {e['pass_count']} / {e['total']}")
        lines.append("")
        lines.append(f"_{e.get('note','')}_")
        lines.append("")
        lines.append("| Sample | PASS | Ops |")
        lines.append("|---|:-:|-----|")
        for sid, r in e["per_sample"].items():
            mark = "✅" if r["pass"] else "❌"
            ops = str(r["ops"])[:80]
            lines.append(f"| `{sid}` | {mark} | `{ops}` |")
        lines.append("")
    # Verdict
    combined = next((e for e in experiments if e["experiment"] == "combined_all_hunks"), None)
    lines.append("## Approval verdict")
    lines.append("")
    if combined and combined.get("pass_count") == combined.get("total"):
        lines.append("**GO** — combined 3-hunk restore reaches **11 / 11**. Phase 5 approved to")
        lines.append("promote to `/app/backend`, then proceed to Phase 6 isolation.")
    elif combined and combined.get("pass_count"):
        lines.append(f"**PARTIAL** — combined reaches {combined['pass_count']}/{combined['total']}. Investigate the remaining ❌ rows before promoting.")
    else:
        lines.append("**NO-GO** — combined failed to boot or reach any PASS. Investigate before promoting.")
    (ROOT / "phase5_hunk_validation_report.md").write_text("\n".join(lines))
    print(f"[phase5] wrote {ROOT / 'phase5_hunk_validation_report.md'}")


if __name__ == "__main__":
    sys.exit(main())
