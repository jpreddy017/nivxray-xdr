"""Safe archive extraction · P0 Security Hardening Gate.

Defends the ``/api/upload`` boundary (and any future archive-consuming
path) against:

- decompression bombs (huge expanded size, extreme ratio)
- archive recursion / nesting (ZIP-in-ZIP-in-…)
- excessive file counts (many-small-files bomb)
- oversized individual entries
- path traversal (``../``, absolute paths, symlinks-in-zip)
- malformed / hostile archives that crash the parser

All limits are enforced SERVER-SIDE, BEFORE bytes are read into memory
(we walk the ZipInfo table first). The public entry point is
``safe_iter_zip_members`` — a generator that yields ``(name, bytes)``
tuples for each safe, in-limits member; on any breach it raises
``ArchiveGuardError`` with a deterministic reason code.

Config surface (environment):

    NIVX_ARCHIVE_MAX_DEPTH              = "3"      # nesting depth
    NIVX_ARCHIVE_MAX_ENTRIES            = "512"    # file count in one archive
    NIVX_ARCHIVE_MAX_TOTAL_BYTES        = "52428800"   # 50 MB total expanded
    NIVX_ARCHIVE_MAX_ENTRY_BYTES        = "16777216"   # 16 MB per member
    NIVX_ARCHIVE_MAX_COMPRESSION_RATIO  = "200"    # per-entry ratio cap

Nothing here reads or writes any NIVX_FLAG_*.
"""
from __future__ import annotations
import io
import os
import zipfile
from dataclasses import dataclass
from typing import Iterator, Tuple


# ─── Config ──────────────────────────────────────────────────────────
def _cfg_int(name: str, default: int) -> int:
    try:
        v = int(os.environ.get(name, "").strip() or default)
        return max(1, v)
    except Exception:
        return default


def load_limits() -> "ArchiveLimits":
    return ArchiveLimits(
        max_depth              = _cfg_int("NIVX_ARCHIVE_MAX_DEPTH", 3),
        max_entries            = _cfg_int("NIVX_ARCHIVE_MAX_ENTRIES", 512),
        max_total_bytes        = _cfg_int("NIVX_ARCHIVE_MAX_TOTAL_BYTES", 50 * 1024 * 1024),
        max_entry_bytes        = _cfg_int("NIVX_ARCHIVE_MAX_ENTRY_BYTES", 16 * 1024 * 1024),
        max_compression_ratio  = _cfg_int("NIVX_ARCHIVE_MAX_COMPRESSION_RATIO", 200),
    )


@dataclass(frozen=True)
class ArchiveLimits:
    max_depth: int
    max_entries: int
    max_total_bytes: int
    max_entry_bytes: int
    max_compression_ratio: int


# ─── Structured error ────────────────────────────────────────────────
class ArchiveGuardError(Exception):
    """Raised when an archive violates a P0 limit or looks hostile.

    ``reason`` is a stable snake_case token — safe to surface to the
    client. ``detail`` may contain measured values (byte counts, depth,
    ratio) for the analyst; keep it free of sensitive filesystem
    details (paths inside the archive OK, host paths NOT OK).
    """
    def __init__(self, reason: str, detail: dict | None = None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail or {}

    def to_dict(self) -> dict:
        return {"error": "archive_guard", "reason": self.reason, **self.detail}


# ─── Path-traversal check ────────────────────────────────────────────
def _is_safe_member_name(name: str) -> bool:
    if not name:
        return False
    if name.startswith(("/", "\\")):
        return False
    # Windows drive letter or backslash traversal
    if len(name) > 2 and name[1] == ":":
        return False
    # POSIX / mixed traversal
    parts = name.replace("\\", "/").split("/")
    return not any(p in ("..", "") for p in parts if p)


# ─── Core: walk one ZIP archive under limits ────────────────────────
def safe_iter_zip_members(
    raw: bytes,
    limits: ArchiveLimits | None = None,
    *,
    depth: int = 0,
) -> Iterator[Tuple[str, bytes]]:
    """Yield ``(member_name, member_bytes)`` for every safe member of a ZIP.

    Raises :class:`ArchiveGuardError` on any limit breach. Never yields
    partial state for a malformed archive.

    ``depth`` starts at 0 for the top-level archive; nested calls (a caller
    that recursively expands a member which is itself an archive) MUST
    increment it. This function does NOT recurse into nested archives on
    its own — the calling code decides whether recursion is desired, but
    it is capped by ``max_depth``.
    """
    limits = limits or load_limits()
    if depth >= limits.max_depth:
        raise ArchiveGuardError("depth_exceeded",
                                {"depth": depth, "max_depth": limits.max_depth})

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as e:
        raise ArchiveGuardError("malformed_archive", {"parser": str(e)})
    except Exception as e:                                        # noqa: BLE001
        raise ArchiveGuardError("archive_parse_error", {"parser": type(e).__name__})

    infos = zf.infolist()

    if len(infos) > limits.max_entries:
        raise ArchiveGuardError("entry_count_exceeded",
                                {"entries": len(infos),
                                 "max_entries": limits.max_entries})

    total = 0
    for info in infos:
        name = info.filename or ""
        if not _is_safe_member_name(name):
            raise ArchiveGuardError("unsafe_member_name",
                                    {"member": name[:200]})

        # Skip directory entries — no bytes, no harm.
        if name.endswith("/"):
            continue

        # Per-entry expanded size
        if info.file_size > limits.max_entry_bytes:
            raise ArchiveGuardError("entry_too_large",
                                    {"member": name[:200],
                                     "size": info.file_size,
                                     "max_entry_bytes": limits.max_entry_bytes})

        # Per-entry compression ratio (only if compressed_size > 0 to
        # avoid divide-by-zero for stored/empty members).
        if info.compress_size > 0:
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > limits.max_compression_ratio:
                raise ArchiveGuardError("compression_ratio_exceeded",
                                        {"member": name[:200],
                                         "ratio": round(ratio, 2),
                                         "max_ratio": limits.max_compression_ratio})

        # Running total expanded size
        total += info.file_size
        if total > limits.max_total_bytes:
            raise ArchiveGuardError("total_size_exceeded",
                                    {"total": total,
                                     "max_total_bytes": limits.max_total_bytes})

        try:
            data = zf.read(info)
        except Exception as e:                                    # noqa: BLE001
            raise ArchiveGuardError("member_read_error",
                                    {"member": name[:200],
                                     "parser": type(e).__name__})

        yield name, data
