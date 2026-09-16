#!/usr/bin/env python3
"""NivXRay Open Benchmark runner — single-file portable.

Usage:
    python run_benchmark.py --engine nivxray --api https://your.nivxray
    python run_benchmark.py --engine cyberchef --api http://localhost:3000
    python run_benchmark.py --engine llm --model claude-sonnet-4-5

Emits results under `results/`.
"""
from __future__ import annotations
import argparse, importlib, json, sys, time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent


def _load_fixtures():
    fixtures = []
    for sub in ("rc40_obfuscation", "rc41_crypto"):
        for f in sorted((ROOT / "fixtures" / sub).glob("*.json")):
            fixtures.append(json.loads(f.read_text()))
    return fixtures


def _load_expected(fid):
    p = ROOT / "expected" / f"{fid}.json"
    return json.loads(p.read_text()) if p.exists() else {}


def _passed(fix, expected, resp) -> bool:
    text = json.dumps(resp, default=str).lower()
    # ANY-match keyword rule
    keywords = expected.get("expected_keywords") or fix.get("expected_iocs") or []
    if keywords:
        for k in keywords:
            if str(k).lower() in text:
                return True
    # Crypto-fixture path — algorithm identifier surfaces
    algo = fix.get("algorithm", "").lower()
    if algo:
        for probe in (algo, algo.split("-")[0], algo.split("+")[0]):
            if probe and probe in text:
                return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True,
                    choices=["nivxray", "cyberchef", "llm"])
    ap.add_argument("--api", default="")
    ap.add_argument("--model", default="claude-sonnet-4-5-20250929")
    ap.add_argument("--provider", default="anthropic")
    ap.add_argument("--email", default=""); ap.add_argument("--password", default="")
    args = ap.parse_args()

    sys.path.insert(0, str(ROOT / "engines"))
    adapter = importlib.import_module(f"{args.engine}_adapter")

    token = None
    if args.engine == "nivxray" and args.email:
        token = adapter.login(args.api, args.email, args.password)

    fixtures = _load_fixtures()
    print(f"loaded {len(fixtures)} fixtures")
    results = []
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    t_start = time.time()
    for i, fix in enumerate(fixtures, 1):
        exp = _load_expected(fix["id"])
        t0 = time.time()
        try:
            if args.engine == "nivxray":
                resp = adapter.decode(fix["command_line"], args.api, token)
            elif args.engine == "cyberchef":
                resp = adapter.decode(fix["command_line"], args.api)
            else:
                resp = adapter.decode(fix["command_line"], provider=args.provider,
                                       model=args.model)
            ok = _passed(fix, exp, resp)
            reason = "" if ok else "no-keyword-hit"
        except Exception as e:
            resp, ok, reason = {}, False, f"{type(e).__name__}: {e}"
        latency = int((time.time() - t0) * 1000)
        results.append({"id": fix["id"], "cat": fix.get("category") or "crypto",
                         "algo": fix.get("algorithm") or "-",
                         "passed": ok, "reason": reason, "latency_ms": latency})
        if i % 20 == 0:
            p = sum(1 for r in results if r["passed"])
            print(f"  {i}/{len(fixtures)} pass={p} ({p*100//i}%) elapsed={int(time.time()-t_start)}s")

    p = sum(1 for r in results if r["passed"])
    rate = p * 100 / len(results)
    (ROOT / "results" / f"{args.engine}_{ts}.json").write_text(
        json.dumps({"engine": args.engine, "total": len(results),
                     "passed": p, "rate": rate,
                     "duration_s": int(time.time() - t_start),
                     "results": results}, indent=2))

    # MD summary
    md = [f"# NivXRay Open Benchmark · {args.engine} · {ts}",
          f"- Total: {len(results)}",
          f"- Passed: {p} ({rate:.1f}%)",
          f"- Duration: {int(time.time()-t_start)}s",
          "", "## Failures (first 30)", ""]
    for r in [x for x in results if not x["passed"]][:30]:
        md.append(f"- `{r['id']}` [{r['algo']}] — {r['reason']} · {r['latency_ms']}ms")
    (ROOT / "results" / f"{args.engine}_{ts}.md").write_text("\n".join(md))
    print(f"\n{args.engine}: {p}/{len(results)} = {rate:.1f}%")


if __name__ == "__main__":
    main()
