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
    # Mask URL substrings so hash regexes don't match URL path segments
    # (GitHub Gist IDs, S3 keys, blob paths, etc.) as MD5 / SHA1 IOCs.
    _hash_txt = _URL_RE.sub(lambda m: " " * (m.end() - m.start()), text)
    hashes  = {
        "md5":    uniq(_MD5_RE.findall(_hash_txt)),
        "sha1":   uniq(_SHA1_RE.findall(_hash_txt)),
        "sha256": uniq(_SHA256_RE.findall(_hash_txt)),
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
# API Hashing Dictionary & Recognition
# ---------------------------------------------------------------------------

_API_HASH_TABLE_ROR13 = {
    0xec0e4e8e: "LoadLibraryA",
    0x7c0dfcaa: "GetProcAddress",
    0x0e8afe98: "VirtualAlloc",
    0x91afca54: "VirtualAllocEx",
    0x160d6838: "CreateProcessA",
    0xe73a0336: "WinExec",
    0x76da08d2: "URLDownloadToFileA",
    0xa779563a: "InternetOpenA",
    0xc69f8957: "InternetConnectA",
    0x3b2e55eb: "HttpOpenRequestA",
    0x7b18062d: "HttpSendRequestA",
    0x384a4e20: "WSAStartup",
    0xadf509d9: "WSASocketA",
    0x5b38e10a: "connect",
    0x6b80297f: "closesocket",
    0x348019b8: "ExitProcess",
    0x7946c61b: "NtAllocateVirtualMemory",
    0x50e182e7: "NtProtectVirtualMemory",
    0x3711d9f4: "NtWriteVirtualMemory",
}

_API_HASH_TABLE_DJB2 = {
    0x5e376042: "LoadLibraryA",
    0x241d7d0a: "GetProcAddress",
    0x1bb89063: "VirtualAlloc",
}


def detect_api_hashing(data: bytes, arch: str = "x86_64") -> Dict[str, Any]:
    """Scan for common Windows API export hashes (ROR13 / DJB2)."""
    if not data or len(data) < 4:
        return {"detected": False, "has_hash_loop": False, "resolved_apis": [], "api_count": 0}

    resolved: List[Dict[str, Any]] = []
    seen = set()

    for i in range(0, min(len(data) - 3, 4096)):
        val = int.from_bytes(data[i:i + 4], "little")
        if val in _API_HASH_TABLE_ROR13 and val not in seen:
            seen.add(val)
            resolved.append({
                "hash": f"0x{val:08x}",
                "algorithm": "ROR13",
                "api": _API_HASH_TABLE_ROR13[val],
                "status": "API_NAME_RESOLVED",
                "offset": i,
            })
        elif val in _API_HASH_TABLE_DJB2 and val not in seen:
            seen.add(val)
            resolved.append({
                "hash": f"0x{val:08x}",
                "algorithm": "DJB2",
                "api": _API_HASH_TABLE_DJB2[val],
                "status": "API_NAME_RESOLVED",
                "offset": i,
            })

    has_hash_loop = False
    try:
        if _CS_OK:
            for insn in disassemble(data[:512], arch, max_insns=60):
                op = insn.get("op", "")
                args = insn.get("args", "")
                if op == "ror" and ("13" in args or "0xd" in args):
                    has_hash_loop = True
                    break
    except Exception:
        pass

    return {
        "detected": bool(resolved or has_hash_loop),
        "has_hash_loop": has_hash_loop,
        "resolved_apis": resolved,
        "api_count": len(resolved),
    }


# ---------------------------------------------------------------------------
# PEB / TEB Access Detection
# ---------------------------------------------------------------------------

def detect_peb_teb_access(data: bytes, arch: str = "x86_64") -> bool:
    """Detect in-memory PEB/TEB lookups used for stealth API resolution."""
    if not data or len(data) < 4:
        return False
    if b"\x64\xa1\x30\x00\x00\x00" in data or b"\x64\x8b" in data or b"\x65\x48\x8b" in data:
        return True
    if _CS_OK:
        try:
            for insn in disassemble(data[:256], arch, max_insns=40):
                op_str = insn.get("args", "").lower()
                if "fs:" in op_str or "gs:" in op_str:
                    return True
        except Exception:
            pass
    return False


# ---------------------------------------------------------------------------
# Static Shellcode Deobfuscation (Zero-Execution)
# ---------------------------------------------------------------------------

def deobfuscate_shellcode(data: bytes, max_layers: int = 3) -> Dict[str, Any]:
    """Static-first shellcode deobfuscator (zero code execution).

    Identifies and peels single-byte XOR, rolling-key XOR, and bitwise NOT transforms.
    Each transformation produces SHA-256 in/out hashes, execution metrics, and bounded previews.
    """
    import hashlib
    if not data or len(data) < 16:
        return {
            "success": False,
            "stages": [],
            "final_bytes": data,
            "stop_reason": "payload_too_short",
        }

    current = bytearray(data)
    stages: List[Dict[str, Any]] = []
    stop_reason = "no_transformation_identified"

    for depth in range(max_layers):
        in_hash = hashlib.sha256(current).hexdigest()
        stage_applied = False

        # If current buffer is already clean shellcode or PE, halt honestly
        if starts_with_known_prologue(current) or _is_valid_pe(current):
            stop_reason = "terminal_payload_reached"
            break

        # Single-Byte XOR brute force
        best_xor_key = None
        best_buf = None
        for key in range(1, 256):
            xored = bytes(b ^ key for b in current)
            if starts_with_known_prologue(xored) or _is_valid_pe(xored):
                best_xor_key = key
                best_buf = xored
                break

        if best_xor_key is not None and best_buf is not None:
            out_hash = hashlib.sha256(best_buf).hexdigest()
            stages.append({
                "stage_index": depth,
                "decoder": "shellcode-xor-single",
                "op": "shellcode-xor-single",
                "input_hash": in_hash,
                "output_hash": out_hash,
                "input_length": len(current),
                "output_length": len(best_buf),
                "why_selected": f"Single-byte XOR with key 0x{best_xor_key:02x} revealed valid executable prologue",
                "confidence": 0.95,
                "status": "success",
                "preview": best_buf[:64].hex(" "),
                "output_payload": best_buf[:65536].hex(" "),
                "key": f"0x{best_xor_key:02x}",
            })
            current = bytearray(best_buf)
            stage_applied = True
            stop_reason = "terminal_payload_reached"

        # Rolling XOR with seed incrementing per byte
        if not stage_applied:
            for seed in range(1, 256):
                rolling_buf = bytes(current[i] ^ ((seed + i) & 0xFF) for i in range(len(current)))
                if starts_with_known_prologue(rolling_buf) or _is_valid_pe(rolling_buf):
                    out_hash = hashlib.sha256(rolling_buf).hexdigest()
                    stages.append({
                        "stage_index": depth,
                        "decoder": "shellcode-rolling-xor",
                        "op": "shellcode-rolling-xor",
                        "input_hash": in_hash,
                        "output_hash": out_hash,
                        "input_length": len(current),
                        "output_length": len(rolling_buf),
                        "why_selected": f"Rolling XOR with seed 0x{seed:02x} revealed valid executable prologue",
                        "confidence": 0.90,
                        "status": "success",
                        "preview": rolling_buf[:64].hex(" "),
                        "output_payload": rolling_buf[:65536].hex(" "),
                        "seed": f"0x{seed:02x}",
                    })
                    current = bytearray(rolling_buf)
                    stage_applied = True
                    stop_reason = "terminal_payload_reached"
                    break

        # Bitwise NOT inversion
        if not stage_applied:
            not_buf = bytes(b ^ 0xFF for b in current)
            if starts_with_known_prologue(not_buf) or _is_valid_pe(not_buf):
                out_hash = hashlib.sha256(not_buf).hexdigest()
                stages.append({
                    "stage_index": depth,
                    "decoder": "shellcode-bitwise-not",
                    "op": "shellcode-bitwise-not",
                    "input_hash": in_hash,
                    "output_hash": out_hash,
                    "input_length": len(current),
                    "output_length": len(not_buf),
                    "why_selected": "Bitwise NOT inversion revealed valid executable prologue",
                    "confidence": 0.90,
                    "status": "success",
                    "preview": not_buf[:64].hex(" "),
                    "output_payload": not_buf[:65536].hex(" "),
                })
                current = bytearray(not_buf)
                stage_applied = True
                stop_reason = "terminal_payload_reached"

        if not stage_applied:
            break

    return {
        "success": bool(stages),
        "stages": stages,
        "final_bytes": bytes(current),
        "stop_reason": stop_reason,
    }


# ---------------------------------------------------------------------------
# Embedded Artifact Carving & Recursion
# ---------------------------------------------------------------------------

def carve_embedded_artifacts(data: bytes) -> List[Dict[str, Any]]:
    """Scan raw/deobfuscated buffer for embedded executables and archives."""
    import hashlib
    if not data or len(data) < 64:
        return []
    carved: List[Dict[str, Any]] = []

    # 1. Carve embedded Windows PE (Reflective Loader payload)
    idx = 0
    while idx < len(data) - 64 and len(carved) < 5:
        pos = data.find(b"MZ", idx)
        if pos == -1:
            break
        candidate = data[pos:]
        if _is_valid_pe(candidate):
            sha = hashlib.sha256(candidate).hexdigest()
            pe_analysis = None
            try:
                from services.analyzers.pe import analyze as analyze_pe
                pe_analysis = analyze_pe(candidate)
            except Exception:
                try:
                    from services.pe_analyzer import analyze_pe
                    pe_analysis = analyze_pe(candidate)
                except Exception:
                    pass

            carved.append({
                "child_id": f"pe:{sha[:16]}",
                "artifact_type": "pe",
                "offset": pos,
                "size": len(candidate),
                "sha256": sha,
                "relationship": "carved_from_shellcode",
                "pe_analysis": pe_analysis,
            })
            idx = pos + 64
        else:
            idx = pos + 1

    # 2. Carve embedded ZIP archives
    zpos = data.find(b"PK\x03\x04")
    if zpos != -1 and len(carved) < 5:
        zip_candidate = data[zpos:]
        zsha = hashlib.sha256(zip_candidate).hexdigest()
        carved.append({
            "child_id": f"zip:{zsha[:16]}",
            "artifact_type": "archive",
            "offset": zpos,
            "size": len(zip_candidate),
            "sha256": zsha,
            "relationship": "carved_from_shellcode",
        })

    return carved


# ---------------------------------------------------------------------------
# One-shot analyzer (Enriched with Deobfuscation, Carving & API Hashing)
# ---------------------------------------------------------------------------

def analyze(data: bytes, arch: Optional[str] = None, max_insns: int = 300) -> Dict[str, Any]:
    """Bundle entropy + arch + disassembly + IOCs + deobfuscation + carving."""
    if not data:
        return {
            "size": 0, "entropy": 0.0, "is_shellcode": False,
            "arch": None, "disassembly": [], "iocs": {}, "hex_preview": "",
            "deobfuscation": {"success": False, "stages": []},
            "api_hashes": {"detected": False, "resolved_apis": []},
            "peb_teb_access": False,
            "carved_artifacts": [],
            "has_embedded_pe": False,
        }

    # Static deobfuscation pass
    deob = deobfuscate_shellcode(data)
    effective_data = deob["final_bytes"] if deob["success"] else data

    detected_arch = detect_arch(effective_data, hint=arch)
    disasm = disassemble(effective_data, detected_arch, max_insns=max_insns)
    iocs = extract_iocs(effective_data)
    api_hashes = detect_api_hashing(effective_data, detected_arch)
    peb_access = detect_peb_teb_access(effective_data, detected_arch)
    carved = carve_embedded_artifacts(effective_data)

    return {
        "size": len(data),
        "entropy": round(shannon_entropy(data), 3),
        "is_shellcode": is_shellcode(data),
        "arch": detected_arch,
        "arch_hint": arch or None,
        "disassembly": disasm,
        "iocs": iocs,
        "hex_preview": data[:64].hex(" "),
        "capstone_available": _CS_OK,
        "deobfuscation": deob,
        "api_hashes": api_hashes,
        "peb_teb_access": peb_access,
        "carved_artifacts": carved,
        "has_embedded_pe": any(c["artifact_type"] == "pe" for c in carved),
    }



# ---------------------------------------------------------------------------
# v1.3.5 · Shellcode family annotator (analyst-friendly output card)
# ---------------------------------------------------------------------------

# Family fingerprints — checked in order. Each entry: (name, matcher, mitre)
_SHELLCODE_FAMILIES: List[tuple] = [
    ("Metasploit Meterpreter (reverse_tcp/https · x86 stager)",
     lambda d: d.startswith(b"\xfc\xe8") and (b"ws2_32" in d.lower() or b"wininet" in d.lower() or b"MSIE" in d),
     "T1071.001"),
    ("Metasploit Meterpreter (reverse_tcp/https · x64 stager)",
     lambda d: d.startswith(b"\xfc\x48\x83\xe4\xf0") and (b"ws2_32" in d.lower() or b"wininet" in d.lower()),
     "T1071.001"),
    ("Cobalt Strike Beacon (staged · x86)",
     lambda d: d.startswith(b"\xfc\xe8") and b"beacon" in d.lower(),
     "T1071.001"),
    ("Generic MSFVenom shellcode (x86 · reverse-shell)",
     lambda d: d.startswith(b"\xfc\xe8") and (b"\x0f\xb7\x4a\x26" in d[:64] or b"\x31\xff" in d[:64]),
     "T1059"),
    ("Generic MSFVenom shellcode (x64)",
     lambda d: d.startswith(b"\xfc\x48"),
     "T1059"),
    ("Windows PE Executable dropped inline",
     lambda d: d.startswith(b"MZ") and b"PE\x00\x00" in d[:512],
     "T1027.002"),
    ("Linux ELF binary dropped inline",
     lambda d: d.startswith(b"\x7fELF"),
     "T1027.002"),
]


def _hex_dump(data: bytes, offset: int = 0, count: int = 128, width: int = 16) -> str:
    """Classic hex+ASCII side-by-side dump for the first `count` bytes."""
    end = min(len(data), offset + count)
    lines = []
    for i in range(offset, end, width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part}  |{ascii_part}|")
    if end < len(data):
        lines.append(f"  … ({len(data) - end} more bytes truncated)")
    return "\n".join(lines)


def _extract_user_agents(data: bytes) -> List[str]:
    """Pull User-Agent strings from shellcode HTTP staging."""
    uas: List[str] = []
    for s in _ascii_strings(data, min_len=20):
        if s.startswith("Mozilla/") or "compatible;" in s or "MSIE " in s:
            uas.append(s)
    return uas[:5]


def _family_recognise(data: bytes) -> tuple:
    """Return (family_name, mitre_id) or (None, None)."""
    for name, match, mitre in _SHELLCODE_FAMILIES:
        try:
            if match(data):
                return name, mitre
        except Exception:
            continue
    return None, None


def annotate_shellcode(data: bytes, max_bytes: int = 4096) -> Optional[str]:
    """Produce an analyst-friendly shellcode investigation card.

    Returns None if `data` doesn't match any known shellcode family or magic.
    Otherwise returns a multi-line annotation string:

        # --- Shellcode Detected: <family> ---
        # Arch:   x86_64 · Size: 512B · Entropy: 6.94
        # MITRE:  T1071.001
        # UA:     Mozilla/5.0 (compatible; MSIE 9.0; ...)
        # IOCs:   http://…, 10.1.2.3:4444
        # Hex dump (first 128 bytes):
        #   00000000  fc e8 82 00 …  |…|
        # Disassembly (first 24 instructions):
        #   00000000  cld
        #   00000001  call 0x87
        # Recommendation: dump to /tmp/x.bin and feed to `speakeasy` or `scdbg`
    """
    if not data or len(data) < 8:
        return None
    if not (starts_with_known_prologue(data) or is_shellcode(data)):
        return None

    family, mitre = _family_recognise(data)
    arch = detect_arch(data)
    ents = round(shannon_entropy(data), 3)
    uas = _extract_user_agents(data)
    iocs = extract_iocs(data)
    urls = iocs.get("urls") or []
    ips = iocs.get("ipv4") or iocs.get("ips") or []
    apis = [s for s in _ascii_strings(data, 6)
            if s.lower() in ("kernel32.dll", "ws2_32.dll", "wininet.dll", "advapi32.dll",
                             "loadlibrarya", "getprocaddress", "wsastartup", "wsasocket",
                             "connect", "recv", "send", "createprocessa",
                             "virtualalloc", "internetopena", "internetconnecta",
                             "httpopenrequesta", "httpsendrequesta")][:10]

    # Optional disassembly (short — capstone may not be installed)
    disasm_lines: List[str] = []
    try:
        for insn in disassemble(data[:min(len(data), max_bytes)], arch, max_insns=24):
            disasm_lines.append(f"  {insn.get('addr', 0):08x}  {insn.get('mnemonic','?'):8s} {insn.get('op_str','')}")
    except Exception:
        pass

    lines = []
    lines.append(f"# ─── Shellcode Detected: {family or 'Unknown shellcode / binary'} ───")
    lines.append(f"# Arch    : {arch} · Size: {len(data)}B · Entropy: {ents}")
    if mitre:
        lines.append(f"# MITRE   : {mitre}")
    if uas:
        for ua in uas:
            lines.append(f"# UA      : {ua}")
    if urls:
        lines.append(f"# URLs    : {', '.join(urls[:5])}")
    if ips:
        lines.append(f"# IPs     : {', '.join(ips[:5])}")
    if apis:
        lines.append(f"# APIs    : {', '.join(apis)}")
    lines.append("#")
    lines.append("# Hex dump (first 128 bytes):")
    lines.append(_hex_dump(data, 0, 128))
    if disasm_lines:
        lines.append("#")
        lines.append("# Disassembly (first 24 instructions):")
        lines.extend(disasm_lines)
    lines.append("#")
    lines.append("# Recommendation: extract raw bytes → run through `speakeasy` "
                 "or `scdbg` for full behavioural analysis. If Meterpreter/Cobalt "
                 "Strike, extract the C2 config with `1768` or `dissect.cobaltstrike`.")
    return "\n".join(lines)
