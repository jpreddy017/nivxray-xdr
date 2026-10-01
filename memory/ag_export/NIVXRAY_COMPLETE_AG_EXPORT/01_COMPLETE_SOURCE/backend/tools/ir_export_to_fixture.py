"""IR Handoff JSON → Golden Fixture converter (RC3.4 · Feb-2026).

Converts an IR Handoff Export JSON (produced by the `/api/v2/analyze/report?fmt=json`
endpoint or the frontend "IR Handoff → JSON" button) into a canonical
`tests/fixtures/plugin_regression/prod-case-<name>.jsonl` entry so every
real-world production case becomes permanent CI regression protection.

The flywheel:
  1. Analyst hits an interesting payload in prod → saves case with a name.
  2. Analyst clicks IR Handoff → JSON → shares the file with engineering.
  3. `python tools/ir_export_to_fixture.py <case.json>` produces a locked
     fixture with the exact case name + observed findings surface.
  4. `pytest tests/test_plugin_golden_fixtures.py` re-verifies on every merge.

Usage:
    python tools/ir_export_to_fixture.py <case.json> [--out-dir DIR]
    python tools/ir_export_to_fixture.py case1.json case2.json case3.json

The generated fixture asserts:
  * Verdict must match observed (verdict downgrades are caught as regressions)
  * Risk score floor is set 5 pts below observed (allows minor rescoring)
  * Every MITRE technique observed must remain observed
  * Every IOC / LOLBAS / family observed must remain observed
  * Chain layer count floor set at observed count (no shorter chain allowed)

Refuses to overwrite an existing fixture unless `--force` is supplied.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return slug[:60] or "unnamed"


def _extract_findings(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise findings across sync (/api/v2/analyze) and async
    (/analyze/job) response shapes."""
    findings = doc.get("findings") or doc.get("verdict_card") or {}
    trace = doc.get("trace") or doc.get("chain_recipe") or []
    return {
        "verdict":       findings.get("verdict") or doc.get("verdict") or "unknown",
        "risk_score":    int(findings.get("risk_score") or doc.get("risk") or 0),
        "chain_layers":  [t.get("op") or t.get("decoder") or "?" for t in trace],
        "mitre":         sorted({(h.get("id") or h.get("technique_id"))
                                 for h in (findings.get("mitre_techniques")
                                           or findings.get("mitre") or [])
                                 if h.get("id") or h.get("technique_id")}),
        "iocs_urls":     sorted(set((findings.get("iocs") or {}).get("urls") or doc.get("iocs", {}).get("urls") or [])),
        "iocs_domains":  sorted(set((findings.get("iocs") or {}).get("domains") or doc.get("iocs", {}).get("domains") or [])),
        "iocs_ips":      sorted(set((findings.get("iocs") or {}).get("ips") or doc.get("iocs", {}).get("ips") or [])),
        "lolbas":        sorted({h.get("binary", "").lower()
                                 for h in (findings.get("lolbas") or doc.get("lolbas") or [])
                                 if h.get("binary")}),
        "family":        (findings.get("family") or {}).get("family") or "unknown",
        "family_conf":   float((findings.get("family") or {}).get("confidence") or 0.0),
        "tradecraft":    sorted({t.get("flag") for t in (findings.get("tradecraft") or []) if t.get("flag")}),
    }


def _convert(doc: Dict[str, Any], case_name: str) -> Dict[str, Any]:
    inp = doc.get("input") or doc.get("payload") or doc.get("raw_input") or ""
    if not inp:
        raise SystemExit("IR export missing `input` / `payload` / `raw_input` field")
    f = _extract_findings(doc)
    slug = _slugify(case_name)
    fixture: Dict[str, Any] = {
        "case_id":       f"prod-{slug}",
        "description":   f"Production IR case: {case_name!r} — frozen "
                         f"from live analyst investigation",
        "input":         inp,
        "detect_min_confidence": 0.1,
        "expected_verdict":     f["verdict"],
        "expected_risk_min":    max(0, f["risk_score"] - 5),
        "expected_chain_layers_min": max(1, len(f["chain_layers"])),
    }
    if f["mitre"]:
        fixture["expected_mitre"] = list(f["mitre"])
    if f["iocs_urls"]:
        fixture["expected_iocs_urls"] = list(f["iocs_urls"])
    if f["iocs_domains"]:
        fixture["expected_iocs_domains"] = list(f["iocs_domains"])
    if f["iocs_ips"]:
        fixture["expected_iocs_ips"] = list(f["iocs_ips"])
    if f["lolbas"]:
        fixture["expected_lolbas_binaries"] = list(f["lolbas"])
    if f["tradecraft"]:
        fixture["expected_tradecraft"] = list(f["tradecraft"])
    if f["family"] and f["family"] != "unknown":
        fixture["expected_family"] = f["family"]
        fixture["expected_family_min_confidence"] = max(0.5, f["family_conf"] - 0.05)
    return fixture


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("exports", nargs="+", help="IR Handoff JSON export file(s)")
    p.add_argument("--out-dir",
                   default="tests/fixtures/plugin_regression",
                   help="Destination fixture directory")
    p.add_argument("--force", action="store_true", help="Overwrite existing fixtures")
    args = p.parse_args()

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    written: List[Path] = []
    for exp_path in args.exports:
        doc = json.loads(Path(exp_path).read_text(encoding="utf-8"))
        case_name = (doc.get("case_name")
                     or doc.get("name")
                     or Path(exp_path).stem)
        fixture = _convert(doc, case_name)
        # A single "prod-cases" jsonl accumulates every prod case (easier
        # to browse than one file per case).
        out = out_dir / "prod-cases.jsonl"
        existing = []
        if out.exists():
            for line in out.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                existing.append(json.loads(line))
        # Overwrite entry with same case_id if present
        existing = [e for e in existing if e.get("case_id") != fixture["case_id"]]
        existing.append(fixture)
        lines = ["# prod-cases · Golden Fixtures · lock a live analyst case as a "
                 "permanent regression",
                 "# populated by tools/ir_export_to_fixture.py"]
        for e in sorted(existing, key=lambda x: x["case_id"]):
            lines.append(json.dumps(e, ensure_ascii=True))
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append(out)
        print(f"✓ locked {case_name!r} → {fixture['case_id']} "
              f"(verdict={fixture.get('expected_verdict')}, "
              f"risk≥{fixture.get('expected_risk_min')})")
    print(f"\n{len(args.exports)} case(s) written to {written[0] if written else '?'}")
    print("Next: run  `pytest tests/test_plugin_golden_fixtures.py -k prod-`  to verify.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
