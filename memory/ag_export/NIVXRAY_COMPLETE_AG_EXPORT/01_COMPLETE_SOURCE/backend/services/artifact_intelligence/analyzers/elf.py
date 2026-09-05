"""ELF analyzer plugin — deterministic static analysis for Linux/BSD
Executable and Linkable Format binaries.

Phase 3 · Cycle C · owner-approved 2026-02.

Extracts analyst-facing signals for cloud-workload, container, IoT, and
Linux-server investigations:

    ▸ Overview:         class · endianness · machine · type · entry
                         point · ABI · # sections · # segments
    ▸ Sections:         name · addr · size · entropy · flags (R/W/X)
    ▸ Program headers:  segments (PT_LOAD / PT_DYNAMIC / PT_GNU_STACK /
                         PT_TLS / PT_INTERP) with permissions
    ▸ Dynamic entries:  DT_NEEDED · DT_RUNPATH · DT_RPATH · DT_SONAME ·
                         DT_INIT · DT_FINI
    ▸ Symbols:          .dynsym (imports / exports) — first 250
    ▸ Notes:            build-id · GNU-property
    ▸ Findings:         RWX segment · executable stack (GNU_STACK+X) ·
                         suspicious DT_RUNPATH/DT_RPATH · high-entropy
                         section · statically linked · stripped · UPX
                         signatures

Uses only `elftools` (pyelftools). Never raises — every failure surfaces
as a diagnostic dict. Deterministic (Rule 21) — identical bytes → byte-
identical report.
"""
from __future__ import annotations

import hashlib
import io
import math
from typing import Any, Dict, List, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.sections import SymbolTableSection, NoteSection
    from elftools.elf.constants import P_FLAGS
    _HAS_ELFTOOLS = True
except Exception:
    ELFFile = None  # type: ignore
    _HAS_ELFTOOLS = False


_HIGH_ENTROPY = 7.4
_UPX_SECTION_NAMES = ("UPX0", "UPX1", "UPX2", ".UPX0", ".UPX1")


class ELFAnalyzer:
    artifact_type = "elf"
    display_name  = "Linux ELF (Executable and Linkable Format)"

    def magic_matcher(self, data: bytes) -> Optional[int]:
        # ELF magic is exactly 4 bytes: 0x7f 'E' 'L' 'F'.
        if not data.startswith(b"\x7fELF"):
            return None
        # High confidence — ELF magic is extremely specific.
        return 99

    def is_available(self) -> bool:
        return _HAS_ELFTOOLS

    def analyze(self, data: bytes) -> Dict[str, Any]:
        if not _HAS_ELFTOOLS:
            return {
                "available": False,
                "reason":   "elftools_not_installed",
                "message":  "ELF analysis capability unavailable — pyelftools is not installed.",
            }
        try:
            return _build_report(data)
        except Exception as e:
            return {
                "available": True,
                "error":   "elf_parse_failed",
                "message": f"{type(e).__name__}: {e}",
            }


# ─── Helpers ───────────────────────────────────────────────────────────
def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts: Dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    e = 0.0
    for c in counts.values():
        p = c / n
        e -= p * math.log2(p)
    return round(e, 3)


def _p_flags(flags: int) -> Dict[str, bool]:
    return {
        "read":  bool(flags & P_FLAGS.PF_R),
        "write": bool(flags & P_FLAGS.PF_W),
        "exec":  bool(flags & P_FLAGS.PF_X),
    }


# ─── Report builder ───────────────────────────────────────────────────
def _build_report(data: bytes) -> Dict[str, Any]:
    stream = io.BytesIO(data)
    elf = ELFFile(stream)

    header = elf.header
    e_type = str(header["e_type"])
    e_machine = str(header["e_machine"])
    is_dyn = e_type == "ET_DYN"

    # ── Overview ─────────────────────────────────────────────────
    overview = {
        "elf_class":         elf.elfclass,
        "endianness":        "little" if elf.little_endian else "big",
        "machine":           e_machine,
        "type":              e_type,
        "entry_point":       f"0x{int(header['e_entry']):x}",
        "abi":               str(header["e_ident"]["EI_OSABI"]),
        "num_sections":      elf.num_sections(),
        "num_segments":      elf.num_segments(),
        "file_size":         len(data),
        "is_dyn":            is_dyn,
    }

    # ── Program headers / segments ───────────────────────────────
    segments: List[Dict[str, Any]] = []
    exec_stack = False
    rwx_present = False
    for seg in elf.iter_segments():
        p_type = str(seg["p_type"])
        p_flags = int(seg["p_flags"])
        perms = _p_flags(p_flags)
        segments.append({
            "type":        p_type,
            "vaddr":       f"0x{int(seg['p_vaddr']):x}",
            "filesz":      int(seg["p_filesz"]),
            "memsz":       int(seg["p_memsz"]),
            "align":       int(seg["p_align"]),
            "permissions": perms,
        })
        if p_type == "PT_GNU_STACK" and perms["exec"]:
            exec_stack = True
        if perms["write"] and perms["exec"]:
            rwx_present = True

    # ── Sections ─────────────────────────────────────────────────
    sections: List[Dict[str, Any]] = []
    for s in elf.iter_sections():
        try:
            raw = s.data()
        except Exception:
            raw = b""
        flags = int(s["sh_flags"])
        sections.append({
            "name":    s.name or "<no-name>",
            "type":    str(s["sh_type"]),
            "addr":    f"0x{int(s['sh_addr']):x}",
            "size":    int(s["sh_size"]),
            "offset":  f"0x{int(s['sh_offset']):x}",
            "entropy": _shannon_entropy(raw),
            "flags":   {
                "write":     bool(flags & 0x1),
                "alloc":     bool(flags & 0x2),
                "exec":      bool(flags & 0x4),
                "tls":       bool(flags & 0x400),
            },
        })
    section_names = [s["name"] for s in sections]

    # ── Dynamic entries ─────────────────────────────────────────
    needed: List[str] = []
    runpath: List[str] = []
    rpath:   List[str] = []
    soname:  Optional[str] = None
    dyn = elf.get_section_by_name(".dynamic")
    if isinstance(dyn, DynamicSection):
        for tag in dyn.iter_tags():
            t = str(tag.entry.d_tag)
            if t == "DT_NEEDED":
                needed.append(str(tag.needed))
            elif t == "DT_RUNPATH":
                runpath.append(str(tag.runpath))
            elif t == "DT_RPATH":
                rpath.append(str(tag.rpath))
            elif t == "DT_SONAME":
                soname = str(tag.soname)
    needed.sort()
    runpath.sort()
    rpath.sort()

    # ── Dynamic symbols ─────────────────────────────────────────
    dynsym: List[Dict[str, Any]] = []
    dsym_section = elf.get_section_by_name(".dynsym")
    if isinstance(dsym_section, SymbolTableSection):
        for i, sym in enumerate(dsym_section.iter_symbols()):
            if i >= 250:
                break
            if not sym.name:
                continue
            dynsym.append({
                "name":    sym.name,
                "type":    str(sym["st_info"]["type"]),
                "bind":    str(sym["st_info"]["bind"]),
                "shndx":   str(sym["st_shndx"]),
                "size":    int(sym["st_size"]),
            })
    dynsym.sort(key=lambda x: x["name"])

    # ── Notes (build-id + GNU property) ─────────────────────────
    notes: List[Dict[str, Any]] = []
    for s in elf.iter_sections():
        if not isinstance(s, NoteSection):
            continue
        try:
            for note in s.iter_notes():
                notes.append({
                    "section": s.name,
                    "name":    str(note.get("n_name") or ""),
                    "type":    str(note.get("n_type") or ""),
                    "desc":    (note.get("n_desc") or "")[:200] if isinstance(note.get("n_desc"), str) else None,
                })
        except Exception:
            continue

    # ── Hashes ──────────────────────────────────────────────────
    hashes = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    # ── Analyst-oriented findings ───────────────────────────────
    findings = _compute_findings(
        overview=overview, segments=segments, sections=sections,
        needed=needed, rpath=rpath, runpath=runpath,
        exec_stack=exec_stack, rwx_present=rwx_present,
        section_names=section_names, dsym_present=dsym_section is not None,
    )

    return {
        "available": True,
        "overview": overview,
        "hashes":   hashes,
        "sections": sections,
        "segments": segments,
        "dynamic": {
            "needed":  needed,
            "runpath": runpath,
            "rpath":   rpath,
            "soname":  soname,
        },
        "symbols":  dynsym,
        "notes":    notes,
        "findings": findings,
    }


# ─── Findings engine ─────────────────────────────────────────────────
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _compute_findings(*, overview, segments, sections, needed, rpath, runpath,
                     exec_stack, rwx_present, section_names, dsym_present) -> List[Dict[str, Any]]:
    f: List[Dict[str, Any]] = []

    # RWX segment (rare in benign ELFs)
    if rwx_present:
        f.append({
            "severity": "high", "code": "rwx_segment",
            "title":  "PT_LOAD segment is simultaneously writable and executable",
            "detail": "RWX segments are extremely unusual in normal executables. Common in packed or self-modifying code.",
        })
    # Executable stack
    if exec_stack:
        f.append({
            "severity": "high", "code": "exec_stack",
            "title":  "Executable stack (PT_GNU_STACK carries PF_X)",
            "detail": "Modern toolchains emit non-executable stacks. An executable stack indicates old code or attacker-crafted linker options.",
        })
    # DT_RPATH / DT_RUNPATH abuse
    if rpath:
        f.append({
            "severity": "high", "code": "dt_rpath",
            "title":  f"DT_RPATH set ({', '.join(rpath)})",
            "detail": "DT_RPATH forces the loader to search these paths first — classic library-hijacking primitive.",
        })
    if runpath:
        f.append({
            "severity": "medium", "code": "dt_runpath",
            "title":  f"DT_RUNPATH set ({', '.join(runpath)})",
            "detail": "DT_RUNPATH is less dangerous than DT_RPATH but can still enable library hijacking.",
        })
    # High-entropy executable sections
    for s in sections:
        if s["entropy"] >= _HIGH_ENTROPY and s["flags"]["exec"]:
            f.append({
                "severity": "medium", "code": "high_entropy_exec",
                "title":  f"High-entropy executable section '{s['name']}' (entropy={s['entropy']})",
                "detail": "Section content is close to uniformly random — typical of packed/encrypted payloads.",
            })
    # UPX
    if any(n in _UPX_SECTION_NAMES for n in section_names):
        f.append({
            "severity": "high", "code": "packer_upx",
            "title":  "UPX section names present",
            "detail": "The ELF appears packed with UPX. Unpack before deeper analysis.",
        })
    # Statically linked (no DT_NEEDED)
    if overview.get("is_dyn") is False and not needed:
        f.append({
            "severity": "medium", "code": "statically_linked",
            "title":  "Statically linked (no DT_NEEDED entries)",
            "detail": "Static binaries are harder to fingerprint and are sometimes used by malware to avoid missing-library errors.",
        })
    # Stripped (no dynsym / no .symtab)
    if not dsym_present:
        f.append({
            "severity": "low", "code": "stripped",
            "title":  "Binary carries no .dynsym section",
            "detail": "Symbols were stripped — reduces analysis surface. Common but occasionally suspicious.",
        })
    # Info: architecture
    f.append({
        "severity": "info", "code": "elf_summary",
        "title":  f"ELF {overview['elf_class']}-bit · {overview['machine']} · {overview['type']}",
        "detail": f"Endianness: {overview['endianness']} · ABI: {overview['abi']} · sections: {overview['num_sections']} · segments: {overview['num_segments']}",
    })

    f.sort(key=lambda x: (_SEV_ORDER.get(x["severity"], 99), x["code"]))
    return f


__all__ = ["ELFAnalyzer"]
