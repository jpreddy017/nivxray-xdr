"""PE (Portable Executable) Analyzer — deterministic static analysis.

Priority 1 · Phase 1 (2026-02 · owner-approved bundle).

This module is the natural continuation of the IEDDE pipeline: when the
recipe planner reaches `binary_artifact_recovered` on a PE payload, the
Workspace no longer stops at "here's the executable, go open PEStudio".
Instead, the recovered bytes are handed to `analyze_pe` and the analyst
gets a structured static-analysis report inside the Workspace itself:

    ▸ Overview          — arch, subsystem, compile timestamp, imphash
    ▸ Hashes            — md5, sha1, sha256, imphash
    ▸ Sections          — name, sizes, entropy, R/W/X characteristics
    ▸ Imports           — DLL → [functions]
    ▸ Exports           — name → ordinal
    ▸ Resources         — type, id, lang, size, sha256
    ▸ Strings           — ASCII + UTF-16LE, min-length 6, capped at 500
    ▸ Packer Hints      — UPX / MPRESS / ASPack / high-entropy heuristics
    ▸ Findings          — analyst-oriented signals (RWX sections, empty
                          imports, invalid timestamp, TLS callbacks,
                          executable overlay, atypical entrypoint)

Design constraints (owner directive · 2026-02):
    1. `pefile` is treated as an OPTIONAL capability. If unavailable,
       `is_available()` returns False and the caller degrades gracefully —
       the PE Analysis panel just does not render (never crashes).
    2. No runtime installations. If `pefile` isn't already in the pod,
       the feature is disabled — the deployment is deterministic.
    3. Pure function. Never raises. Every error path returns a diagnostic
       dict instead of propagating an exception.
    4. Rule 21 (Determinism). Identical input → byte-identical output.
       Findings are sorted by severity+key so ordering is stable.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ─── Optional-capability import ────────────────────────────────────────────
try:
    import pefile  # type: ignore
    _HAS_PEFILE = True
except Exception:
    pefile = None  # type: ignore
    _HAS_PEFILE = False


def is_available() -> bool:
    """True iff the deterministic PE analyser can run in this pod."""
    return _HAS_PEFILE


# ─── Helpers ───────────────────────────────────────────────────────────────
_UPX_SIGNATURES = ("UPX0", "UPX1", "UPX2", "UPX3", "UPX!")
_MPRESS_SIGNATURES = (".MPRESS1", ".MPRESS2", "MPRESS")
_ASPACK_SIGNATURES = (".aspack", ".adata", "ASPack")
_PETITE_SIGNATURES = (".petite", "petite")

_MIN_STRING_LEN = 6
_MAX_STRINGS = 500
_HIGH_ENTROPY = 7.4  # Shannon entropy threshold flagged as suspicious


def _shannon_entropy(data: bytes) -> float:
    """Deterministic Shannon entropy (bits/byte), 0-8."""
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _characteristics(section) -> Dict[str, bool]:
    """Decode PE section IMAGE_SCN_* flags into a readable dict."""
    chars = int(section.Characteristics)
    return {
        "read":  bool(chars & 0x40000000),
        "write": bool(chars & 0x80000000),
        "exec":  bool(chars & 0x20000000),
        "code":  bool(chars & 0x00000020),
        "initialized_data":   bool(chars & 0x00000040),
        "uninitialized_data": bool(chars & 0x00000080),
    }


def _clean_ascii(raw: bytes) -> str:
    try:
        s = raw.decode("ascii", errors="replace").rstrip("\x00")
    except Exception:
        return ""
    # Strip control chars (except common whitespace) for readability.
    return "".join(c for c in s if 32 <= ord(c) < 127)


def _extract_strings(data: bytes) -> List[Dict[str, Any]]:
    """Deterministic ASCII + UTF-16LE string extraction.

    Returns a list of `{value, encoding, offset}` capped at `_MAX_STRINGS`.
    """
    strings: List[Tuple[int, str, str]] = []
    # ASCII strings (printable, len >= _MIN_STRING_LEN)
    for m in re.finditer(rb"[\x20-\x7e]{" + str(_MIN_STRING_LEN).encode() + rb",}", data):
        strings.append((m.start(), m.group().decode("ascii", errors="replace"), "ascii"))
        if len(strings) >= _MAX_STRINGS * 2:
            break
    # UTF-16LE strings
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){" + str(_MIN_STRING_LEN).encode() + rb",}", data):
        v = m.group().decode("utf-16-le", errors="replace")
        strings.append((m.start(), v, "utf-16-le"))
        if len(strings) >= _MAX_STRINGS * 4:
            break
    # De-dup by value+encoding, sort by offset (deterministic).
    seen: set = set()
    unique: List[Dict[str, Any]] = []
    for off, val, enc in strings:
        key = (val, enc)
        if key in seen:
            continue
        seen.add(key)
        unique.append({"value": val, "encoding": enc, "offset": off})
        if len(unique) >= _MAX_STRINGS:
            break
    unique.sort(key=lambda s: s["offset"])
    return unique


def _dos_timestamp(pe) -> Optional[str]:
    ts = int(pe.FILE_HEADER.TimeDateStamp)
    if ts <= 0 or ts > 4102444800:  # >= 2100-01-01
        return None
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
    except Exception:
        return None


def _is_invalid_timestamp(pe) -> bool:
    ts = int(pe.FILE_HEADER.TimeDateStamp)
    if ts <= 0:
        return True
    # Anything before Windows NT 3.1 (1993) or after 2100 is suspect.
    return ts < 725846400 or ts > 4102444800


# ─── Public analysis entry point ───────────────────────────────────────────
def analyze_pe(data: bytes) -> Dict[str, Any]:
    """Deterministic PE static-analysis report.

    Returns a dict with `available: bool` at minimum. When `available` is
    True and no parse error occurred, the dict carries `overview`,
    `hashes`, `sections`, `imports`, `exports`, `resources`, `strings`,
    `packer_hints`, and `findings`.

    Never raises. Every failure surfaces as `error` in the returned dict.
    """
    if not _HAS_PEFILE:
        return {
            "available": False,
            "reason": "pefile_not_installed",
            "message": "PE analysis capability unavailable in this deployment.",
        }
    if not isinstance(data, (bytes, bytearray)) or len(data) < 64 or data[:2] != b"MZ":
        return {
            "available": True,
            "error": "not_a_pe",
            "message": "Payload does not carry an MZ header.",
        }

    try:
        pe = pefile.PE(data=bytes(data), fast_load=False)
    except Exception as e:
        return {
            "available": True,
            "error": "pe_parse_failed",
            "message": f"pefile could not parse the payload: {type(e).__name__}: {e}",
        }

    try:
        return _build_report(pe, bytes(data))
    except Exception as e:
        return {
            "available": True,
            "error": "pe_report_build_failed",
            "message": f"{type(e).__name__}: {e}",
        }


def _build_report(pe, data: bytes) -> Dict[str, Any]:
    # ── Hashes ────────────────────────────────────────────────────────
    hashes = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "imphash": pe.get_imphash() or None,
    }

    # ── Overview ──────────────────────────────────────────────────────
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    machine = int(pe.FILE_HEADER.Machine)
    _MACHINES = {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0xaa64: "ARM64", 0x200: "IA64"}
    arch = _MACHINES.get(machine, f"unknown_0x{machine:04x}")
    subsystem = int(pe.OPTIONAL_HEADER.Subsystem)
    _SUBSYS = {
        1: "Native", 2: "Windows GUI", 3: "Windows CUI (Console)",
        5: "OS/2 CUI", 7: "POSIX CUI", 9: "Windows CE GUI",
        10: "EFI Application", 11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver", 13: "EFI ROM", 14: "Xbox",
    }
    overview = {
        "arch":                arch,
        "kind":                "dll" if is_dll else "exe",
        "subsystem":           _SUBSYS.get(subsystem, f"unknown_{subsystem}"),
        "entry_point":         f"0x{int(pe.OPTIONAL_HEADER.AddressOfEntryPoint):08x}",
        "image_base":          f"0x{int(pe.OPTIONAL_HEADER.ImageBase):016x}",
        "size_of_image":       int(pe.OPTIONAL_HEADER.SizeOfImage),
        "size_of_headers":     int(pe.OPTIONAL_HEADER.SizeOfHeaders),
        "file_size":           len(data),
        "timestamp_raw":       int(pe.FILE_HEADER.TimeDateStamp),
        "timestamp":           _dos_timestamp(pe),
        "characteristics":     int(pe.FILE_HEADER.Characteristics),
        "dll_characteristics": int(pe.OPTIONAL_HEADER.DllCharacteristics),
        "number_of_sections":  int(pe.FILE_HEADER.NumberOfSections),
        "linker_version":      f"{int(pe.OPTIONAL_HEADER.MajorLinkerVersion)}.{int(pe.OPTIONAL_HEADER.MinorLinkerVersion)}",
        "os_version":          f"{int(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)}.{int(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)}",
        "subsystem_version":   f"{int(pe.OPTIONAL_HEADER.MajorSubsystemVersion)}.{int(pe.OPTIONAL_HEADER.MinorSubsystemVersion)}",
    }

    # ── Sections ──────────────────────────────────────────────────────
    sections: List[Dict[str, Any]] = []
    for s in pe.sections:
        raw_data = s.get_data() or b""
        name = s.Name.rstrip(b"\x00").decode("latin-1", errors="replace") or "?"
        sections.append({
            "name":            name,
            "virtual_size":    int(s.Misc_VirtualSize),
            "virtual_address": f"0x{int(s.VirtualAddress):08x}",
            "raw_size":        int(s.SizeOfRawData),
            "raw_offset":      f"0x{int(s.PointerToRawData):08x}",
            "entropy":         _shannon_entropy(raw_data),
            "characteristics": _characteristics(s),
            "md5":             hashlib.md5(raw_data).hexdigest() if raw_data else None,
        })

    # ── Imports ───────────────────────────────────────────────────────
    imports: List[Dict[str, Any]] = []
    try:
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
        ])
    except Exception:
        pass
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode("latin-1", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("latin-1", errors="replace"))
                elif imp.ordinal is not None:
                    funcs.append(f"ord_{imp.ordinal}")
            imports.append({"dll": dll, "functions": sorted(funcs)})
    imports.sort(key=lambda x: x["dll"].lower())

    # ── Exports ───────────────────────────────────────────────────────
    exports: List[Dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append({
                "name":    (exp.name or b"").decode("latin-1", errors="replace") or None,
                "ordinal": int(exp.ordinal) if exp.ordinal is not None else None,
                "address": f"0x{int(exp.address):08x}" if exp.address else None,
            })
    exports.sort(key=lambda x: (x["name"] or "", x["ordinal"] or 0))

    # ── Resources ─────────────────────────────────────────────────────
    resources: List[Dict[str, Any]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rtype_name = (
                rtype.name.decode(errors="replace") if rtype.name is not None
                else pefile.RESOURCE_TYPE.get(int(rtype.struct.Id), f"type_{int(rtype.struct.Id)}")
            )
            for rid in rtype.directory.entries:
                for rlang in rid.directory.entries:
                    dr = rlang.data.struct
                    off, size = int(dr.OffsetToData), int(dr.Size)
                    blob = pe.get_data(off, size) if size else b""
                    resources.append({
                        "type":     str(rtype_name),
                        "id":       int(rid.struct.Id) if rid.name is None else str(rid.name),
                        "language": int(rlang.struct.Id),
                        "size":     size,
                        "sha256":   hashlib.sha256(blob).hexdigest() if blob else None,
                    })
    resources.sort(key=lambda r: (str(r["type"]), str(r["id"]), r["language"]))

    # ── Packer hints ──────────────────────────────────────────────────
    section_names = [s["name"] for s in sections]
    packer_hints: List[Dict[str, str]] = []
    if any(n in _UPX_SIGNATURES for n in section_names):
        packer_hints.append({"family": "UPX", "confidence": "high",
                              "evidence": "UPX0/UPX1 section names"})
    if any(n in _MPRESS_SIGNATURES for n in section_names):
        packer_hints.append({"family": "MPRESS", "confidence": "high",
                              "evidence": ".MPRESS1/.MPRESS2 section names"})
    if any(n in _ASPACK_SIGNATURES for n in section_names):
        packer_hints.append({"family": "ASPack", "confidence": "high",
                              "evidence": ".aspack section name"})
    if any(n in _PETITE_SIGNATURES for n in section_names):
        packer_hints.append({"family": "Petite", "confidence": "medium",
                              "evidence": ".petite section name"})
    # Heuristic: single high-entropy executable section + no readable strings
    high_entropy_exec = [
        s for s in sections
        if s["entropy"] >= _HIGH_ENTROPY and s["characteristics"]["exec"]
    ]
    if not packer_hints and high_entropy_exec:
        packer_hints.append({
            "family": "unknown_packer",
            "confidence": "low",
            "evidence": (
                f"{len(high_entropy_exec)} executable section(s) with "
                f"entropy >= {_HIGH_ENTROPY} — likely packed/encrypted"
            ),
        })

    # ── Strings ───────────────────────────────────────────────────────
    strings = _extract_strings(data)

    # ── Analyst-oriented findings ────────────────────────────────────
    findings = _compute_findings(pe, overview, sections, imports, hashes, len(data))

    return {
        "available":     True,
        "overview":      overview,
        "hashes":        hashes,
        "sections":      sections,
        "imports":       imports,
        "exports":       exports,
        "resources":     resources,
        "packer_hints":  packer_hints,
        "strings":       strings,
        "findings":      findings,
    }


# ─── Analyst-oriented findings engine ──────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _compute_findings(pe, overview, sections, imports, hashes, filesize) -> List[Dict[str, Any]]:
    """Produce a list of `{severity, code, title, detail}` sorted by severity.

    These are deterministic analyst signals — no heuristic magic beyond
    threshold comparisons. Every rule cites its evidence.
    """
    f: List[Dict[str, Any]] = []

    # RWX sections — a section that is simultaneously writable AND executable
    # is unusual in benign PE files (compilers emit either RX or RW). This is
    # a classic packer / self-modifying-code indicator.
    for s in sections:
        c = s["characteristics"]
        if c["write"] and c["exec"]:
            f.append({
                "severity": "high", "code": "rwx_section",
                "title":  f"Writable + executable section '{s['name']}'",
                "detail": (
                    f"Section '{s['name']}' is both writable and executable "
                    f"(virtual_size={s['virtual_size']}, entropy={s['entropy']}). "
                    "This is highly unusual in benign PE files and is common "
                    "in packers and self-modifying-code malware."
                ),
            })

    # High-entropy sections
    for s in sections:
        if s["entropy"] >= _HIGH_ENTROPY:
            f.append({
                "severity": "medium", "code": "high_entropy_section",
                "title":  f"High-entropy section '{s['name']}' (entropy={s['entropy']})",
                "detail": (
                    f"Entropy {s['entropy']} exceeds the {_HIGH_ENTROPY} threshold — "
                    "the section content is very close to uniformly random, "
                    "typical of compressed or encrypted payloads."
                ),
            })

    # Empty imports table — almost always a packer or manual-mapped PE
    if not imports:
        f.append({
            "severity": "high", "code": "no_imports",
            "title":  "Import table is empty",
            "detail": (
                "The PE has zero DLL imports. Normal binaries import at least "
                "kernel32.dll or ntdll.dll. This strongly indicates the imports "
                "will be resolved at runtime (packer / manual-map / API-hashing)."
            ),
        })

    # Invalid / suspicious compile timestamp
    if _is_invalid_timestamp(pe):
        f.append({
            "severity": "medium", "code": "invalid_timestamp",
            "title":  "Invalid or improbable compile timestamp",
            "detail": (
                f"TimeDateStamp={int(pe.FILE_HEADER.TimeDateStamp)} is either zero, "
                "before Windows NT 3.1 (1993), or after 2100. Common in packed / "
                "tampered / stripped binaries."
            ),
        })

    # Executable overlay
    try:
        overlay_off = pe.get_overlay_data_start_offset()
    except Exception:
        overlay_off = None
    if overlay_off is not None and overlay_off < filesize:
        overlay_size = filesize - overlay_off
        f.append({
            "severity": "medium", "code": "overlay_present",
            "title":  f"Executable carries an overlay ({overlay_size} bytes)",
            "detail": (
                f"Data at file offset 0x{overlay_off:08x} lives outside any PE "
                "section. Overlays are used by installers, packers, and appended "
                "payloads (encrypted second stages, quiet droppers)."
            ),
        })

    # TLS callbacks — code that runs before the main entry point
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        try:
            callback_addr = int(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
        except Exception:
            callback_addr = 0
        if callback_addr:
            f.append({
                "severity": "high", "code": "tls_callback",
                "title":  "TLS callback present",
                "detail": (
                    f"AddressOfCallBacks=0x{callback_addr:x}. TLS callbacks run "
                    "BEFORE the main entry point and are frequently abused for "
                    "early anti-analysis logic."
                ),
            })

    # Atypical section count
    if overview["number_of_sections"] > 12:
        f.append({
            "severity": "low", "code": "many_sections",
            "title":  f"Unusually many sections ({overview['number_of_sections']})",
            "detail": "Most benign PEs have 3-8 sections. High counts are common in packers.",
        })

    # Entry point outside all sections — packer stub or manually crafted PE
    ep = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    ep_in_section = False
    for s in pe.sections:
        va = int(s.VirtualAddress)
        vs = int(s.Misc_VirtualSize) or int(s.SizeOfRawData)
        if va <= ep < (va + vs):
            ep_in_section = True
            break
    if not ep_in_section and ep != 0:
        f.append({
            "severity": "high", "code": "ep_outside_sections",
            "title":  "Entry point lies outside any section",
            "detail": (
                f"AddressOfEntryPoint=0x{ep:08x} is not inside any declared "
                "section. Common in manual-mapped payloads and some packers."
            ),
        })

    # Purely informational — an imphash lets analysts pivot in threat intel.
    if hashes.get("imphash"):
        f.append({
            "severity": "info", "code": "imphash_available",
            "title":  f"imphash {hashes['imphash']} — pivot in threat intel",
            "detail": "Use this imphash to search VirusTotal / Malpedia for family clustering.",
        })

    f.sort(key=lambda x: (_SEV_ORDER.get(x["severity"], 99), x["code"]))
    return f


__all__ = ["analyze_pe", "is_available"]
