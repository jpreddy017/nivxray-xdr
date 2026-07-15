"""NivXRay — Shellcode Analyzer.

Implements the "stop condition" for the recursive decode-and-route pipeline:
when text-decoding no longer yields printable output, hand the bytes off here
for shellcode-level analysis instead of hallucinating another decode layer.

Provides:
  * shannon_entropy(bytes) — the classic entropy check.
  * is_shellcode(bytes)    — heuristic bundling entropy + magic-byte prologues.
  * detect_arch(bytes)     — infer x86 / x86_64 / arm / arm64 / thumb from
                             instruction density (best-effort, capstone-backed).
  * disassemble(bytes, arch) — Capstone-driven listing (addr, hex, mnemonic, op).
  * extract_iocs(bytes)    — strings, hashes, IPs, domains, URLs, mutexes,
                             registry keys, imports lifted from binary payloads.
  * analyze(bytes, arch?)  — one-shot: entropy + arch + disassembly + IOCs.

Kept intentionally free of Pydantic / FastAPI imports so it can be unit-tested
in isolation.
"""
from __future__ import annotations
import math
import re
import string
from typing import Any, Dict, List, Optional

# Capstone is optional — degrade gracefully if it's missing (unit tests
# shouldn't blow up on a fresh container).
try:
    import capstone  # type: ignore
    _CS_OK = True
except Exception:                                          # pragma: no cover
    capstone = None                                        # type: ignore
    _CS_OK = False


# ---------------------------------------------------------------------------
# Entropy / stop condition
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Common shellcode / binary prologues per arch.
_SHELLCODE_PROLOGUES = [
    # x86_64 — classic Metasploit / MSFVenom / Cobalt-Strike stager entries
    (b"\xfc\xe8", "x86_64"),                              # cld; call
    (b"\xfc\xeb", "x86_64"),                              # cld; jmp
    (b"\xfc\x48\x83\xe4\xf0", "x86_64"),                  # cld; and rsp, -16
    (b"\xfc\x48\x81\xe4", "x86_64"),                      # cld; and rsp, imm
    (b"\x65\x48\x8b", "x86_64"),                          # mov rax, gs:[…]
    # x86 (32-bit)
    (b"\x31\xc0\x50", "x86"),
    (b"\x64\xa1", "x86"),                                 # mov eax, fs:[…]
    # PE / ELF / Mach-O — the LLM should route these to a binary loader
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho32"),
    (b"\xfe\xed\xfa\xcf", "macho64"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    # ARM32 / Thumb prologues (push {r0-r7,lr} = 0xff 0xb5)
    (b"\xff\xb5", "arm"),
    # ARM64 — stp x29, x30 ... (very common prologue)
    (b"\xfd\x7b", "arm64"),
]


def _is_valid_pe(data: bytes) -> bool:
    """Strict PE validator — requires MZ at 0 AND `PE\\0\\0` at e_lfanew.

    A raw XOR-brute output that happens to start with the bytes 0x4d 0x5a
    ("MZ") is NOT a PE — a real PE has the DOS header at offset 0 whose
    32-bit field at offset 0x3c points to the `PE\\0\\0` signature further
    into the file. Without this check we hallucinate "SHELLCODE DETECTED"
    on any random buffer whose first two bytes decode to `MZ`.
    """
    if len(data) < 0x40:
        return False
    if data[:2] != b"MZ":
        return False
    # e_lfanew is a signed 32-bit LE offset at 0x3c
    e_lfanew = int.from_bytes(data[0x3c:0x40], "little", signed=True)
    if e_lfanew < 0x40 or e_lfanew > len(data) - 4:
        return False
    return data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00"


def _is_repetitive(data: bytes, window: int = 512) -> bool:
    """True when the buffer has strong short-period byte repetition with a
    MULTI-BYTE motif — the classic signature of an incorrectly XOR-brute-
    forced blob (repeating ciphertext × repeating key = repeating output).

    Excludes single-byte fills (`\\x90` NOP sleds, `\\x00` padding,
    `\\x41` heap-spray fills) which ARE legitimate in real shellcode.

    Test: for period ∈ {2..16}, look for LONG spans of periodic repetition
    where the motif genuinely has ≥ 2 distinct byte values. Runs of a
    single-byte sled/fill are skipped because their appearance doesn't
    indicate periodic ciphertext noise.
    """
    buf = data[:window]
    if len(buf) < 32:
        return False
    # If a single byte value dominates >55 % of the window, this is a
    # NOP sled / heap-spray fill — not periodic ciphertext noise.
    from collections import Counter
    top_byte, top_count = Counter(buf).most_common(1)[0]
    if top_count / len(buf) > 0.55:
        return False
    for period in range(2, 17):
        if period >= len(buf):
            break
        # For each candidate period, look for CONTIGUOUS spans where the
        # motif genuinely repeats (period-shifted match) AND the local motif
        # is multi-byte. This catches `MZFT..DY..` repetition without
        # tripping on single-byte fill regions.
        max_run = 0
        current_run = 0
        for i in range(period, len(buf)):
            if buf[i] == buf[i - period]:
                current_run += 1
                if current_run > max_run:
                    max_run = current_run
            else:
                current_run = 0
        # A "long" periodic run = at least half the window
        if max_run < len(buf) // 2:
            continue
        # Verify the motif inside the run has ≥ 2 distinct byte values
        # (skip if it's a mono-byte fill at that period).
        # Take the middle of the buffer to sample the motif away from
        # start/end fill regions.
        mid = len(buf) // 2
        motif = buf[mid:mid + period]
        if len(set(motif)) < 2:
            continue
        return True
    return False


def is_shellcode(data: bytes, entropy_threshold: float = 6.0) -> bool:
    """True iff the buffer looks like an executable payload rather than text."""
    if not data or len(data) < 16:
        return False
    # Repetitive periodic buffers are XOR-brute noise, never real code
    if _is_repetitive(data):
        return False
    for prologue, arch in _SHELLCODE_PROLOGUES:
        if data.startswith(prologue):
            # PE / ELF / Mach-O — validate the full header signature
            if arch == "pe":
                return _is_valid_pe(data)
            return True
    if shannon_entropy(data) >= entropy_threshold:
        # rule out pure-ASCII high-entropy blobs (base64 leftovers)
        printable_ratio = sum(1 for b in data if 0x20 <= b < 0x7f) / len(data)
        if printable_ratio < 0.85:
            return True
    return False


def starts_with_known_prologue(data: bytes) -> bool:
    """Strict: only True when the buffer starts with a KNOWN shellcode/binary
    prologue. Used by the magic decoder to award a terminal-state boost without
    getting fooled by high-entropy over-decoded random bytes."""
    if not data or len(data) < 4:
        return False
    # Repetitive buffers are XOR-brute noise, never real shellcode
    if _is_repetitive(data):
        return False
    for prologue, arch in _SHELLCODE_PROLOGUES:
        if data.startswith(prologue):
            # PE / ELF headers must pass strict signature validation.
            # This is the ANTI-HALLUCINATION guard: XOR-brute occasionally
            # produces `MZ` at offset 0 by chance; without validating the
            # rest of the PE header the tool would falsely claim
            # "SHELLCODE DETECTED · PE executable" on random noise.
            if arch == "pe":
                return _is_valid_pe(data)
            return True
    return False


# ---------------------------------------------------------------------------
# Arch auto-detection
# ---------------------------------------------------------------------------

ARCH_ALIASES = {
    "x86": "x86", "i386": "x86", "ia32": "x86",
    "x64": "x86_64", "x86_64": "x86_64", "amd64": "x86_64",
    "arm": "arm", "arm32": "arm", "thumb": "thumb",
    "arm64": "arm64", "aarch64": "arm64",
    "pe": "pe", "elf": "elf", "macho": "macho",
}


def _cs_mode(arch: str):
    """Map an arch label to a capstone (arch, mode) tuple."""
    if not _CS_OK:
        return None
    a = ARCH_ALIASES.get(arch.lower(), arch.lower())
    if a == "x86":
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    if a == "x86_64":
        return (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    if a == "arm":
        return (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    if a == "thumb":
        return (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
    if a == "arm64":
        return (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    return None


def detect_arch(data: bytes, hint: Optional[str] = None) -> str:
    """Best-effort arch detector — tries every supported architecture with
    Capstone and picks the one that produces the highest ratio of valid
    instructions covering the buffer. Falls back to `x86_64` on ties.
    """
    if hint:
        h = ARCH_ALIASES.get(hint.lower())
        if h:
            return h

    # Fast-path: obvious magic bytes
    for prologue, arch in _SHELLCODE_PROLOGUES:
        if data.startswith(prologue) and arch not in ("pe", "elf", "macho32", "macho64", "macho-fat"):
            return arch

    if not _CS_OK:
        return "x86_64"

    candidates = ["x86_64", "x86", "arm64", "arm", "thumb"]
    best = ("x86_64", 0.0)
    sample = data[:256]
    for arch in candidates:
        mode = _cs_mode(arch)
        if not mode:
            continue
        try:
            md = capstone.Cs(*mode)
            md.skipdata = False
            covered = 0
            for insn in md.disasm(sample, 0):
                covered += insn.size
                if covered >= len(sample):
                    break
            score = covered / max(1, len(sample))
        except Exception:
            score = 0.0
        if score > best[1]:
            best = (arch, score)
    return best[0]


# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------

def disassemble(data: bytes, arch: str = "x86_64", base_addr: int = 0,
                max_insns: int = 400) -> List[Dict[str, Any]]:
    """Return a Capstone listing as a list of instruction dicts."""
    if not _CS_OK or not data:
        return []
    mode = _cs_mode(arch)
    if not mode:
        return []
    md = capstone.Cs(*mode)
    md.skipdata = True
    out: List[Dict[str, Any]] = []
    for i, insn in enumerate(md.disasm(data, base_addr)):
        if i >= max_insns:
            break
        out.append({
            "addr": f"0x{insn.address:08x}",
            "hex":  insn.bytes.hex(" "),
            "op":   insn.mnemonic,
            "args": insn.op_str,
        })
    return out


# ---------------------------------------------------------------------------
# IOC extraction on binary buffers
# ---------------------------------------------------------------------------

_PRINTABLE = set(bytes(string.printable, "ascii")) - {ord(c) for c in "\r\n\t\x0b\x0c"}


def _ascii_strings(data: bytes, min_len: int = 4) -> List[str]:
    out, cur = [], []
    for b in data:
        if b in _PRINTABLE:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def _utf16le_strings(data: bytes, min_len: int = 4) -> List[str]:
    out, cur = [], []
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and lo in _PRINTABLE:
            cur.append(chr(lo))
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


# lightweight IOC regex bank
_IP_RE      = re.compile(r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b")
_URL_RE     = re.compile(r"\bhttps?://[^\s\"'<>]{4,}", re.I)
_DOMAIN_RE  = re.compile(r"\b(?!\d+$)[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9][a-z0-9-]{0,62})+\.(?:com|net|org|io|ai|gov|edu|co|ru|cn|us|uk|de|xyz|top|info|biz|club|shop|online|site|app|dev|pw|cc|to|ly|me)\b", re.I)
_MD5_RE     = re.compile(r"\b[a-f0-9]{32}\b", re.I)
_SHA1_RE    = re.compile(r"\b[a-f0-9]{40}\b", re.I)
_SHA256_RE  = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_REGKEY_RE  = re.compile(r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+)\\[A-Za-z0-9\\\\_\-\.\s]{4,}", re.I)
_MUTEX_RE   = re.compile(r"(?:Global|Local)\\[A-Za-z0-9_\-\.]{4,}")
_API_HINT   = re.compile(r"\b(?:GetProcAddress|LoadLibrary[AW]?|VirtualAlloc(?:Ex)?|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|WinExec|ShellExecute[AW]?|InternetOpen[AW]?|InternetConnect[AW]?|HttpSendRequest[AW]?|URLDownloadToFile[AW]?|WSAStartup|socket|connect|send|recv|bind|listen|CreateProcess[AW]?|OpenProcess|Nt(?:AllocateVirtualMemory|ProtectVirtualMemory|WriteVirtualMemory|CreateSection))\b")


def extract_iocs(data: bytes) -> Dict[str, List[str]]:
    """Extract IOCs from a binary buffer (ASCII + UTF-16LE strings)."""
    strings = _ascii_strings(data) + _utf16le_strings(data)
    text = "\n".join(strings)

    def uniq(seq):
        seen, out = set(), []
        for s in seq:
            if s not in seen:
                seen.add(s); out.append(s)
        return out

    urls    = uniq(_URL_RE.findall(text))
    ips     = uniq(_IP_RE.findall(text))
    # exclude URL-embedded domains from the domain set to reduce dupes
    url_dom = set()
    for u in urls:
        try:
            host = u.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
            url_dom.add(host.lower())
        except Exception:
            pass
    domains = uniq(d for d in _DOMAIN_RE.findall(text) if d.lower() not in url_dom)
    hashes  = {
        "md5":    uniq(_MD5_RE.findall(text)),
        "sha1":   uniq(_SHA1_RE.findall(text)),
        "sha256": uniq(_SHA256_RE.findall(text)),
    }
    regkeys = uniq(_REGKEY_RE.findall(text))
    mutexes = uniq(_MUTEX_RE.findall(text))
    apis    = uniq(_API_HINT.findall(text))
    return {
        "strings_top": strings[:80],
        "urls":     urls,
        "ips":      ips,
        "domains":  domains,
        "hashes":   hashes,
        "regkeys":  regkeys,
        "mutexes":  mutexes,
        "imports":  apis,
    }


# ---------------------------------------------------------------------------
# One-shot analyzer
# ---------------------------------------------------------------------------

def analyze(data: bytes, arch: Optional[str] = None, max_insns: int = 300) -> Dict[str, Any]:
    """Bundle entropy + arch + disassembly + IOCs into a single dict."""
    if not data:
        return {
            "size": 0, "entropy": 0.0, "is_shellcode": False,
            "arch": None, "disassembly": [], "iocs": {}, "hex_preview": "",
        }
    detected_arch = detect_arch(data, hint=arch)
    return {
        "size":         len(data),
        "entropy":      round(shannon_entropy(data), 3),
        "is_shellcode": is_shellcode(data),
        "arch":         detected_arch,
        "arch_hint":    arch or None,
        "disassembly":  disassemble(data, detected_arch, max_insns=max_insns),
        "iocs":         extract_iocs(data),
        "hex_preview":  data[:64].hex(" "),
        "capstone_available": _CS_OK,
    }
